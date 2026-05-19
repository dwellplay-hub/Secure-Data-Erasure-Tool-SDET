"""
SDET Erasure Engine
Core secure deletion logic implementing NIST SP 800-88 Rev. 2 CLEAR and
legacy educational methods (Gutmann, DoD).
"""

import os
import sys
import struct
import random
import secrets
import string
import hashlib
import datetime
import threading
import logging
from pathlib import Path
from typing import Callable, Optional, List

# <-- TAMBAHAN KUNCI KESELAMATAN (RACE CONDITION PATCH)
if os.name == 'nt':
    import msvcrt
# ---------------------------------------------------------

AUDIT_LOG_FILE = ".sdet_audit.log"
RANDOMIZE_FAILED_MSG = "Filename randomization failed, proceeding with original name"
PERMISSION_DENIED_MSG = "Permission denied"
FILE_SIZE_CHANGED_MSG = "File size changed during operation"
FILE_DELETED_DURING_OP = "FILE_DELETED_DURING_OPERATION"

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

# <-- TAMBAHAN KUNCI KESELAMATAN (RACE CONDITION PATCH)
def _lock_file(f):
    """
    Memaksa kunci eksklusif pada fail di Windows untuk mengelakkan Race Condition.
    Akan melontarkan PermissionError jika fail sedang digunakan oleh proses lain.
    """
    if os.name == 'nt':
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise PermissionError("File is locked by another process (Race Condition Prevented).")
# ---------------------------------------------------------

def _sha256_path(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()


def _mask_filename(name: str) -> str:
    if not name:
        return "***"
    if len(name) <= 3:
        return name[0] + "***"
    visible = max(3, len(name) // 3)
    ext_parts = name.rsplit(".", 1)
    if len(ext_parts) == 2:
        base, ext = ext_parts
        masked_base = base[:max(1, len(base) // 3)] + "*" * max(3, len(base) - len(base) // 3)
        return f"{masked_base}.{ext}"
    return name[:visible] + "*" * (len(name) - visible)


def _audit_log_path() -> Path:
    return Path(__file__).resolve().parent / AUDIT_LOG_FILE


def _write_audit(entry: dict) -> None:
    try:
        log_path = _audit_log_path()
        with open(log_path, "a", encoding="utf-8") as f:
            timestamp = entry.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
            sha = entry.get("sha256_path", "N/A")
            method = entry.get("method", "N/A")
            passes = entry.get("passes", "N/A")
            status = entry.get("status", "N/A")
            f.write(f"[{timestamp}] SHA256={sha} METHOD={method} PASSES={passes} STATUS={status}\n")
    except Exception:
        pass


def _is_blacklisted(path: str) -> bool:
    abs_path = os.path.normcase(os.path.abspath(path))
    for bl in SYSTEM_BLACKLIST:
        normalized_blacklist = os.path.normcase(os.path.abspath(bl))
        if abs_path.startswith(normalized_blacklist):
            return True
    return False


def _overwrite_pass(filepath: str, pattern: Optional[bytes], file_size: int) -> None:
    try:
        with open(filepath, "r+b") as f:
            _lock_file(f)  # <-- TAMBAHAN KUNCI KESELAMATAN (RACE CONDITION PATCH)
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
    except IOError as e:
        logging.warning(f"IO error during overwrite pass: {str(e)}")
        raise


def _randomize_name(filepath: str) -> Optional[str]:
    """Randomize filename. Returns new path on success, None on failure."""
    try:
        parent = os.path.dirname(filepath)
        # Gunakan secrets (CSPRNG) menggantikan random untuk keselamatan gred industri
        rand_name = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(16))
        new_path = os.path.join(parent, rand_name)
        os.rename(filepath, new_path)
        return new_path
    except OSError as e:
        logging.warning(f"Failed to randomize filename: {str(e)}")
        return None


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
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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

        if not _perform_nist_clear_overwrite(filepath, randomize_name, result, progress_callback, stop_event):
            return result

        result["status"] = "SUCCESS"
        _write_audit(result)
        return result

    except PermissionError as e:
        result["status"] = f"PERMISSION_ERROR: {str(e)}"
        logging.exception(PERMISSION_DENIED_MSG)
        _write_audit(result)
        return result
    except FileNotFoundError as e:
        result["status"] = f"FILE_NOT_FOUND: {str(e)}"
        _write_audit(result)
        return result
    except Exception as e:
        result["status"] = f"ERROR: {type(e).__name__}: {str(e)}"
        logging.exception("Unexpected error during NIST Clear")
        _write_audit(result)
        return result


def _perform_nist_clear_overwrite(
    filepath: str,
    randomize_name: bool,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]],
    stop_event: Optional[threading.Event]
) -> bool:
    """Helper function to perform NIST Clear overwrite. Returns True on success."""
    file_size = os.path.getsize(filepath)

    if progress_callback:
        progress_callback(0.1, "Starting NIST Clear overwrite...")

    if stop_event and stop_event.is_set():
        result["status"] = "ABORTED"
        return False

    # Recheck file size to prevent race condition
    actual_size = os.path.getsize(filepath)
    if actual_size != file_size:
        logging.warning(f"{FILE_SIZE_CHANGED_MSG}: {file_size} -> {actual_size}")
        file_size = actual_size

    _overwrite_pass(filepath, None, file_size)

    if progress_callback:
        progress_callback(0.7, "Overwrite complete. Truncating file...")

    if stop_event and stop_event.is_set():
        result["status"] = "ABORTED"
        return False

    return _truncate_and_remove_file(filepath, randomize_name, result, progress_callback)


def _truncate_and_remove_file(
    filepath: str,
    randomize_name: bool,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]]
) -> bool:
    """Truncate file and remove it. Returns True on success."""
    with open(filepath, "r+b") as f:
        _lock_file(f)  # <-- TAMBAHAN KUNCI KESELAMATAN (RACE CONDITION PATCH)
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
        randomized = _randomize_name(filepath)
        if randomized:
            current_path = randomized
            if progress_callback:
                progress_callback(0.92, "Filename randomized.")
        else:
            logging.warning(RANDOMIZE_FAILED_MSG)

    try:
        os.unlink(current_path)
    except OSError as e:
        result["status"] = f"UNLINK_FAILED: {str(e)}"
        _write_audit(result)
        return False

    if progress_callback:
        progress_callback(1.0, "File securely erased.")

    return True


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
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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

        if not _perform_gutmann_overwrite(filepath, randomize_name, result, progress_callback, stop_event):
            return result

        result["status"] = "SUCCESS"
        _write_audit(result)
        return result

    except PermissionError as e:
        result["status"] = f"PERMISSION_ERROR: {str(e)}"
        logging.exception(PERMISSION_DENIED_MSG)
        _write_audit(result)
        return result
    except FileNotFoundError as e:
        result["status"] = f"FILE_NOT_FOUND: {str(e)}"
        _write_audit(result)
        return result
    except Exception as e:
        result["status"] = f"ERROR: {type(e).__name__}: {str(e)}"
        logging.exception("Unexpected error during Gutmann 35-pass")
        _write_audit(result)
        return result


def _perform_gutmann_overwrite(
    filepath: str,
    randomize_name: bool,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]],
    stop_event: Optional[threading.Event]
) -> bool:
    """Helper function to perform Gutmann overwrite. Returns True on success."""
    total_passes = len(GUTMANN_PATTERNS)

    shuffled_middle = list(GUTMANN_PATTERNS[7:21])
    random.shuffle(shuffled_middle)
    patterns = list(GUTMANN_PATTERNS[:7]) + shuffled_middle + list(GUTMANN_PATTERNS[21:])

    if not _perform_overwrite_passes(filepath, patterns, total_passes, result, progress_callback, stop_event):
        return False

    return _truncate_and_remove_file_gutmann(filepath, randomize_name, result, progress_callback)


def _perform_overwrite_passes(
    filepath: str,
    patterns: list,
    total_passes: int,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]],
    stop_event: Optional[threading.Event]
) -> bool:
    """Perform overwrite passes. Returns True on success."""
    for i, pattern in enumerate(patterns):
        if stop_event and stop_event.is_set():
            result["status"] = "ABORTED"
            return False

        # Recheck file size to prevent race condition
        try:
            actual_size = os.path.getsize(filepath)
            logging.debug(f"File size at pass {i+1}: {actual_size}")
        except FileNotFoundError:
            result["status"] = FILE_DELETED_DURING_OP
            _write_audit(result)
            return False

        _overwrite_pass(filepath, pattern, actual_size)

        if progress_callback:
            pct = (i + 1) / total_passes * 0.9
            progress_callback(pct, f"Gutmann pass {i+1}/{total_passes}...")

    return True


def _truncate_and_remove_file_gutmann(
    filepath: str,
    randomize_name: bool,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]]
) -> bool:
    """Truncate file and remove for Gutmann. Returns True on success."""
    with open(filepath, "r+b") as f:
        _lock_file(f)  # <-- TAMBAHAN KUNCI KESELAMATAN (RACE CONDITION PATCH)
        f.truncate(0)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass

    current_path = filepath
    if randomize_name:
        randomized = _randomize_name(filepath)
        if randomized:
            current_path = randomized
        else:
            logging.warning(RANDOMIZE_FAILED_MSG)

    try:
        os.unlink(current_path)
    except OSError as e:
        result["status"] = f"UNLINK_FAILED: {str(e)}"
        _write_audit(result)
        return False

    if progress_callback:
        progress_callback(1.0, "Gutmann 35-pass complete.")

    return True


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
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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

        if not _perform_dod_overwrite(filepath, patterns, passes, randomize_name, result, progress_callback, stop_event):
            return result

        result["status"] = "SUCCESS"
        _write_audit(result)
        return result

    except PermissionError as e:
        result["status"] = f"PERMISSION_ERROR: {str(e)}"
        logging.exception(PERMISSION_DENIED_MSG)
        _write_audit(result)
        return result
    except FileNotFoundError as e:
        result["status"] = f"FILE_NOT_FOUND: {str(e)}"
        _write_audit(result)
        return result
    except Exception as e:
        result["status"] = f"ERROR: {type(e).__name__}: {str(e)}"
        logging.exception(f"Unexpected error during DoD {passes}-pass")
        _write_audit(result)
        return result


def _perform_dod_overwrite(
    filepath: str,
    patterns: list,
    passes: int,
    randomize_name: bool,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]],
    stop_event: Optional[threading.Event]
) -> bool:
    """Helper function to perform DoD overwrite. Returns True on success."""
    total = len(patterns)

    if not _perform_dod_passes(filepath, patterns, total, result, progress_callback, stop_event):
        return False

    return _truncate_and_remove_file_dod(filepath, randomize_name, passes, result, progress_callback)


def _perform_dod_passes(
    filepath: str,
    patterns: list,
    total: int,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]],
    stop_event: Optional[threading.Event]
) -> bool:
    """Perform DoD overwrite passes. Returns True on success."""
    for i, pattern in enumerate(patterns):
        if stop_event and stop_event.is_set():
            result["status"] = "ABORTED"
            return False

        # Recheck file size to prevent race condition
        try:
            actual_size = os.path.getsize(filepath)
            logging.debug(f"File size at pass {i+1}: {actual_size}")
        except FileNotFoundError:
            result["status"] = FILE_DELETED_DURING_OP
            _write_audit(result)
            return False

        _overwrite_pass(filepath, pattern, actual_size)

        if progress_callback:
            pct = (i + 1) / total * 0.9
            progress_callback(pct, f"DoD pass {i+1}/{total}...")

    return True


def _truncate_and_remove_file_dod(
    filepath: str,
    randomize_name: bool,
    passes: int,
    result: dict,
    progress_callback: Optional[Callable[[float, str], None]]
) -> bool:
    """Truncate file and remove for DoD. Returns True on success."""
    with open(filepath, "r+b") as f:
        _lock_file(f)  # <-- TAMBAHAN KUNCI KESELAMATAN (RACE CONDITION PATCH)
        f.truncate(0)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass

    current_path = filepath
    if randomize_name:
        randomized = _randomize_name(filepath)
        if randomized:
            current_path = randomized
        else:
            logging.warning(RANDOMIZE_FAILED_MSG)

    try:
        os.unlink(current_path)
    except OSError as e:
        result["status"] = f"UNLINK_FAILED: {str(e)}"
        _write_audit(result)
        return False

    if progress_callback:
        progress_callback(1.0, f"DoD {passes}-pass complete.")

    return True


def erase_directory(
    dirpath: str,
    method: str = "nist_clear",
    passes: int = 3,
    randomize_name: bool = False,
    progress_callback: Optional[Callable[[float, str], None]] = None,
    stop_event: Optional[threading.Event] = None
) -> List[dict]:
    """Recursively erase all files in a directory using streaming to avoid memory issues."""
    results = []

    if _is_blacklisted(dirpath):
        return [{"status": "BLOCKED_BLACKLIST", "method": method}]

    # Count total files first (required for progress tracking)
    total = _count_directory_files(dirpath)
    if total == 0:
        return results

    # Stream files instead of loading all into memory
    _erase_files_in_directory(dirpath, method, passes, randomize_name, progress_callback, stop_event, results, total)

    # Remove empty directory tree
    _remove_directory_tree(dirpath)

    return results


def _count_directory_files(dirpath: str) -> int:
    """Count total files in directory. Returns 0 on error."""
    try:
        total = 0
        for root, dirs, files in os.walk(dirpath):
            total += len(files)
        return total
    except Exception:
        logging.exception("Error counting files in directory")
        return 0


def _erase_files_in_directory(
    dirpath: str,
    method: str,
    passes: int,
    randomize_name: bool,
    progress_callback: Optional[Callable[[float, str], None]],
    stop_event: Optional[threading.Event],
    results: List[dict],
    total: int
) -> None:
    """Erase files in directory with streaming approach."""
    try:
        idx = 0
        for root, dirs, files in os.walk(dirpath):
            for fname in files:
                if stop_event and stop_event.is_set():
                    break

                fpath = os.path.join(root, fname)
                idx += 1

                file_progress = _create_progress_callback(progress_callback, idx, total)
                _erase_single_file(method, passes, randomize_name, file_progress, stop_event, results, fpath)

            if stop_event and stop_event.is_set():
                break
    except Exception:
        logging.exception("Error during directory traversal")


def _create_progress_callback(
    progress_callback: Optional[Callable[[float, str], None]],
    idx: int,
    total: int
) -> Optional[Callable[[float, str], None]]:
    """Create a nested progress callback for file-level progress."""
    if not progress_callback:
        return None
    
    base_pct = (idx - 1) / total
    end_pct = idx / total

    def file_progress(pct: float, msg: str) -> None:
        overall = base_pct + pct * (end_pct - base_pct)
        progress_callback(overall, msg)
    
    return file_progress


def _erase_single_file(
    method: str,
    passes: int,
    randomize_name: bool,
    file_progress: Optional[Callable[[float, str], None]],
    stop_event: Optional[threading.Event],
    results: List[dict],
    fpath: str
) -> None:
    """Erase a single file and append result."""
    try:
        if method == "gutmann":
            r = gutmann_35pass(fpath, randomize_name, file_progress, stop_event)
        elif method == "dod":
            r = dod_overwrite(fpath, passes, randomize_name, file_progress, stop_event)
        else:
            r = nist_clear(fpath, randomize_name, file_progress, stop_event)
        results.append(r)
    except Exception:
        logging.exception(f"Error erasing file {fpath}")
        results.append({"status": "ERROR", "filepath": fpath})


def _remove_directory_tree(dirpath: str) -> None:
    """Remove empty directory tree."""
    try:
        import shutil
        shutil.rmtree(dirpath, ignore_errors=True)
    except Exception:
        logging.warning("Failed to remove directory tree")


def delete_audit_log() -> bool:
    """Securely delete the audit log file."""
    try:
        log_path = _audit_log_path()
        if log_path.exists():
            r = nist_clear(str(log_path))
            return r["status"] == "SUCCESS"
        return True
    except Exception:
        return False