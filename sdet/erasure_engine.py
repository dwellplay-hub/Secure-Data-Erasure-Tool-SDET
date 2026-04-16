"""
SDET Erasure Engine
Core secure deletion logic implementing NIST SP 800-88 Rev. 2 CLEAR and
legacy educational methods (Gutmann, DoD).
"""

import os
import sys
import struct
import random
import string
import hashlib
import datetime
import threading
import logging
from pathlib import Path
from typing import Callable, Optional, List


AUDIT_LOG_FILE = ".sdet_audit.log"

GUTMANN_PATTERNS = [
    b'\x55',
    b'\xaa',
    bytes([0x92, 0x49, 0x24]),
    bytes([0x49, 0x24, 0x92]),
    bytes([0x24, 0x92, 0x49]),
    b'\x00',
    b'\x11',
    b'\x22',
    b'\x33',
    b'\x44',
    b'\x55',
    b'\x66',
    b'\x77',
    b'\x88',
    b'\x99',
    b'\xaa',
    b'\xbb',
    b'\xcc',
    b'\xdd',
    b'\xee',
    b'\xff',
    bytes([0x92, 0x49, 0x24]),
    bytes([0x49, 0x24, 0x92]),
    bytes([0x24, 0x92, 0x49]),
    bytes([0x6d, 0xb6, 0xdb]),
    bytes([0xb6, 0xdb, 0x6d]),
    bytes([0xdb, 0x6d, 0xb6]),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
]

DOD_3PASS = [b'\x00', b'\xff', None]
DOD_7PASS = [b'\x00', b'\xff', None, b'\x00', b'\xff', None, None]


SYSTEM_BLACKLIST = [
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run",
    "/sbin", "/sys", "/usr", "/var",
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    "C:\\System Volume Information", "C:\\ProgramData",
]


def _sha256_path(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()


def _mask_filename(name: str) -> str:
    if len(name) <= 3:
        return name[0] + "***"
    visible = max(3, len(name) // 3)
    ext_parts = name.rsplit(".", 1)
    if len(ext_parts) == 2:
        base, ext = ext_parts
        masked_base = base[:max(1, len(base) // 3)] + "*" * max(3, len(base) - len(base) // 3)
        return f"{masked_base}.{ext}"
    return name[:visible] + "*" * (len(name) - visible)


def _write_audit(entry: dict) -> None:
    try:
        log_dir = Path.home()
        log_path = log_dir / AUDIT_LOG_FILE
        with open(log_path, "a", encoding="utf-8") as f:
            timestamp = entry.get("timestamp", datetime.datetime.utcnow().isoformat())
            sha = entry.get("sha256_path", "N/A")
            method = entry.get("method", "N/A")
            passes = entry.get("passes", "N/A")
            status = entry.get("status", "N/A")
            f.write(f"[{timestamp}] SHA256={sha} METHOD={method} PASSES={passes} STATUS={status}\n")
    except Exception:
        pass


def _is_blacklisted(path: str) -> bool:
    abs_path = os.path.abspath(path)
    for bl in SYSTEM_BLACKLIST:
        if abs_path.lower().startswith(bl.lower()):
            return True
    return False


def _overwrite_pass(filepath: str, pattern: Optional[bytes], file_size: int) -> None:
    with open(filepath, "r+b") as f:
        f.seek(0)
        written = 0
        chunk_size = 65536
        while written < file_size:
            to_write = min(chunk_size, file_size - written)
            if pattern is None:
                data = os.urandom(to_write)
            else:
                full_reps = (to_write // len(pattern)) + 1
                data = (pattern * full_reps)[:to_write]
            f.write(data)
            written += len(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass


def _randomize_name(filepath: str) -> str:
    parent = os.path.dirname(filepath)
    rand_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    new_path = os.path.join(parent, rand_name)
    os.rename(filepath, new_path)
    return new_path


def nist_clear(
    filepath: str,
    randomize_name: bool = False,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    stop_event: Optional[threading.Event] = None
) -> dict:
    """
    NIST SP 800-88 Rev. 2 CLEAR sanitization.
    - 1-pass random overwrite (user-addressable sectors)
    - fsync/flush for write-through confirmation
    - File truncation to zero
    - Directory entry removal (unlink)
    - Optional filename randomization
    """
    result = {
        "method": "NIST_CLEAR",
        "passes": 1,
        "status": "FAILED",
        "sha256_path": _sha256_path(filepath),
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "masked_name": _mask_filename(os.path.basename(filepath)),
    }

    try:
        if _is_blacklisted(filepath):
            result["status"] = "BLOCKED_BLACKLIST"
            _write_audit(result)
            return result

        if not os.path.isfile(filepath):
            result["status"] = "FILE_NOT_FOUND"
            _write_audit(result)
            return result

        file_size = os.path.getsize(filepath)

        if progress_callback:
            progress_callback(0.1, "Starting NIST Clear overwrite...")

        if stop_event and stop_event.is_set():
            result["status"] = "ABORTED"
            return result

        _overwrite_pass(filepath, None, file_size)

        if progress_callback:
            progress_callback(0.7, "Overwrite complete. Truncating file...")

        if stop_event and stop_event.is_set():
            result["status"] = "ABORTED"
            return result

        with open(filepath, "r+b") as f:
            f.truncate(0)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

        if progress_callback:
            progress_callback(0.85, "Truncated. Removing directory entry...")

        current_path = filepath
        if randomize_name:
            current_path = _randomize_name(filepath)
            if progress_callback:
                progress_callback(0.92, "Filename randomized.")

        os.unlink(current_path)

        if progress_callback:
            progress_callback(1.0, "File securely erased.")

        result["status"] = "SUCCESS"
        _write_audit(result)
        return result

    except PermissionError as e:
        result["status"] = f"PERMISSION_ERROR"
        _write_audit(result)
        return result
    except Exception as e:
        result["status"] = f"ERROR"
        _write_audit(result)
        return result


def gutmann_35pass(
    filepath: str,
    randomize_name: bool = False,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    stop_event: Optional[threading.Event] = None
) -> dict:
    """
    Gutmann 35-pass overwrite — LEGACY EDUCATIONAL ONLY.
    Not recommended for SSDs. Obsolete per NIST SP 800-88.
    """
    result = {
        "method": "GUTMANN_35PASS",
        "passes": 35,
        "status": "FAILED",
        "sha256_path": _sha256_path(filepath),
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "masked_name": _mask_filename(os.path.basename(filepath)),
    }

    try:
        if _is_blacklisted(filepath):
            result["status"] = "BLOCKED_BLACKLIST"
            _write_audit(result)
            return result

        if not os.path.isfile(filepath):
            result["status"] = "FILE_NOT_FOUND"
            _write_audit(result)
            return result

        file_size = os.path.getsize(filepath)
        total_passes = len(GUTMANN_PATTERNS)

        shuffled_middle = list(GUTMANN_PATTERNS[7:21])
        random.shuffle(shuffled_middle)
        patterns = list(GUTMANN_PATTERNS[:7]) + shuffled_middle + list(GUTMANN_PATTERNS[21:])

        for i, pattern in enumerate(patterns):
            if stop_event and stop_event.is_set():
                result["status"] = "ABORTED"
                return result

            _overwrite_pass(filepath, pattern, file_size)

            if progress_callback:
                pct = (i + 1) / total_passes * 0.9
                progress_callback(pct, f"Gutmann pass {i+1}/{total_passes}...")

        with open(filepath, "r+b") as f:
            f.truncate(0)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

        current_path = filepath
        if randomize_name:
            current_path = _randomize_name(filepath)

        os.unlink(current_path)

        if progress_callback:
            progress_callback(1.0, "Gutmann 35-pass complete.")

        result["status"] = "SUCCESS"
        _write_audit(result)
        return result

    except PermissionError:
        result["status"] = "PERMISSION_ERROR"
        _write_audit(result)
        return result
    except Exception:
        result["status"] = "ERROR"
        _write_audit(result)
        return result


def dod_overwrite(
    filepath: str,
    passes: int = 3,
    randomize_name: bool = False,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    stop_event: Optional[threading.Event] = None
) -> dict:
    """
    DoD 3-pass or 7-pass overwrite — DEPRECATED / EDUCATIONAL ONLY.
    Obsolete per NIST SP 800-88 Rev. 2.
    """
    patterns = DOD_3PASS if passes == 3 else DOD_7PASS
    method_name = f"DOD_{passes}PASS"

    result = {
        "method": method_name,
        "passes": passes,
        "status": "FAILED",
        "sha256_path": _sha256_path(filepath),
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "masked_name": _mask_filename(os.path.basename(filepath)),
    }

    try:
        if _is_blacklisted(filepath):
            result["status"] = "BLOCKED_BLACKLIST"
            _write_audit(result)
            return result

        if not os.path.isfile(filepath):
            result["status"] = "FILE_NOT_FOUND"
            _write_audit(result)
            return result

        file_size = os.path.getsize(filepath)
        total = len(patterns)

        for i, pattern in enumerate(patterns):
            if stop_event and stop_event.is_set():
                result["status"] = "ABORTED"
                return result

            _overwrite_pass(filepath, pattern, file_size)

            if progress_callback:
                pct = (i + 1) / total * 0.9
                progress_callback(pct, f"DoD pass {i+1}/{total}...")

        with open(filepath, "r+b") as f:
            f.truncate(0)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

        current_path = filepath
        if randomize_name:
            current_path = _randomize_name(filepath)

        os.unlink(current_path)

        if progress_callback:
            progress_callback(1.0, f"DoD {passes}-pass complete.")

        result["status"] = "SUCCESS"
        _write_audit(result)
        return result

    except PermissionError:
        result["status"] = "PERMISSION_ERROR"
        _write_audit(result)
        return result
    except Exception:
        result["status"] = "ERROR"
        _write_audit(result)
        return result


def erase_directory(
    dirpath: str,
    method: str = "nist_clear",
    passes: int = 3,
    randomize_name: bool = False,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    stop_event: Optional[threading.Event] = None
) -> List[dict]:
    """Recursively erase all files in a directory."""
    results = []

    if _is_blacklisted(dirpath):
        return [{"status": "BLOCKED_BLACKLIST", "method": method}]

    all_files = []
    for root, dirs, files in os.walk(dirpath):
        for fname in files:
            all_files.append(os.path.join(root, fname))

    total = len(all_files)
    if total == 0:
        return results

    for idx, fpath in enumerate(all_files):
        if stop_event and stop_event.is_set():
            break

        file_progress = None
        if progress_callback:
            base_pct = idx / total
            end_pct = (idx + 1) / total

            def file_progress(pct, msg, base=base_pct, end=end_pct):
                overall = base + pct * (end - base)
                progress_callback(overall, msg)

        if method == "gutmann":
            r = gutmann_35pass(fpath, randomize_name, file_progress, stop_event)
        elif method == "dod":
            r = dod_overwrite(fpath, passes, randomize_name, file_progress, stop_event)
        else:
            r = nist_clear(fpath, randomize_name, file_progress, stop_event)

        results.append(r)

    try:
        import shutil
        shutil.rmtree(dirpath, ignore_errors=True)
    except Exception:
        pass

    return results


def delete_audit_log() -> bool:
    """Securely delete the audit log file."""
    try:
        log_path = Path.home() / AUDIT_LOG_FILE
        if log_path.exists():
            r = nist_clear(str(log_path))
            return r["status"] == "SUCCESS"
        return True
    except Exception:
        return False
