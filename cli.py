#!/usr/bin/env python3
"""
SDET CLI — Secure Data Erasure Tool Command-Line Interface
NIST SP 800-88 Rev. 2 Aligned

Usage:
    python cli.py --file <path> [options]
"""

import sys
import os
import time
import shutil
import argparse
import textwrap

# Memastikan modul sdet boleh diimport dari mana-mana lokasi terminal dijalankan
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sdet.erasure_engine import (
    nist_clear,
    gutmann_35pass,
    dod_overwrite,
    erase_directory,
    delete_audit_log,
    AUDIT_LOG_FILE,
    _mask_filename  # <--- PATCH S05: Ditambah untuk menopeng nama fail
)

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║           SDET — Secure Data Erasure Tool v1.0               ║
║      NIST SP 800-88 Rev. 2 Aligned File-Level Sanitization   ║
╚══════════════════════════════════════════════════════════════╝
"""

NIST_PURGE_INFO = """
╔══════════════════════════════════════════════════════════════╗
║                ℹ  NIST PURGE — Information Only              ║
╚══════════════════════════════════════════════════════════════╝

NIST SP 800-88 Rev. 2 defines PURGE as cryptographic erase or
firmware-level commands (e.g., Secure Erase, NVMe Format NVM).

WHY software-only overwrite is INSUFFICIENT for PURGE:
  • Modern SSDs use Flash Translation Layer (FTL) and wear leveling,
    which means write commands may not reach the same physical cells
    previously written. Data may survive in unmapped sectors.
  • NVMe and ATA Secure Erase commands bypass the FTL and instruct
    the controller to erase all NAND flash cells, including reserves.
  • SDET cannot issue firmware-level commands. It operates strictly
    at the OS file-system layer.

RECOMMENDED TOOLS FOR NIST PURGE:
  • Linux/NVMe:   nvme format /dev/nvme0 --ses=1
  • Linux/SATA:   hdparm --security-erase <device>
  • Windows:      Manufacturer-provided secure erase utilities
  • macOS:        Disk Utility "Erase" with security options

⚠ SDET does NOT perform NIST PURGE. Use firmware tools for PURGE.
"""

def _print_colored(text: str, color: str = "") -> None:
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    if color and sys.stdout.isatty():
        print(f"{colors.get(color, '')}{text}{colors['reset']}")
    else:
        print(text)

def _print_result(result: dict) -> None:
    status = result.get("status", "UNKNOWN")
    method = result.get("method", "UNKNOWN")
    masked = result.get("masked_name", "???")

    if status == "SUCCESS":
        _print_colored(f"  ✔ {masked} — {method} — {status}", "green")
    elif status == "BLOCKED_BLACKLIST":
        _print_colored(f"  ✖ {masked} — BLOCKED: Critical system path protected", "red")
    elif status == "FILE_NOT_FOUND":
        _print_colored(f"  ✖ {masked} — FILE NOT FOUND", "red")
    elif status == "ABORTED":
        _print_colored(f"  ⚠ {masked} — ABORTED by user", "yellow")
    elif "PERMISSION_ERROR" in status:
        _print_colored(f"  ✖ {masked} — PERMISSION_ERROR: File locked or Admin required", "red")
    else:
        _print_colored(f"  ✖ {masked} — {status}", "red")

def _confirm(prompt: str) -> bool:
    try:
        response = input(f"{prompt} [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False

# Pembolehubah global untuk menjejak masa kemas kini terminal yang terakhir
_last_update_time = 0.0

def _cli_progress(pct: float, msg: str) -> None:
    global _last_update_time
    current_time = time.time()
    
    # --- UI THROTTLING PATCH ---
    # Jika belum 100%, halang terminal dari dikemas kini lebih kerap daripada 0.05 saat (50ms).
    # Ini menghilangkan kelipan (flickering) dan melajukan proses pemadaman fail!
    if pct < 1.0 and (current_time - _last_update_time) < 0.05:
        return
        
    _last_update_time = current_time

    bar_len = 40
    filled = int(bar_len * pct)
    bar = "█" * filled + "░" * (bar_len - filled)
    
    term_width = shutil.get_terminal_size((80, 20)).columns
    max_msg_len = max(10, term_width - 52)
    safe_msg = msg[:max_msg_len]
    
    sys.stdout.write(f"\r  [{bar}] {int(pct * 100):3d}%  {safe_msg}\033[K")
    sys.stdout.flush()
    
    if pct >= 1.0:
        print()

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sdet",
        description="SDET — Secure Data Erasure Tool (NIST SP 800-88 Rev. 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        DISCLAIMER:
          SDET implements NIST SP 800-88 Rev. 2 CLEAR — logical sanitization only.
          It does NOT perform firmware-level PURGE or physical DESTROY operations.
          Legacy methods (Gutmann, DoD) are included for educational comparison only.
        """)
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--file", "-f", metavar="PATH", help="File to securely erase")
    target_group.add_argument("--dir", "-d", metavar="PATH", help="Directory to recursively erase (use with --recursive)")

    method_group = parser.add_mutually_exclusive_group()
    method_group.add_argument("--nist-clear", action="store_true", default=False,
                               help="NIST SP 800-88 CLEAR 1-pass random (DEFAULT, recommended)")
    method_group.add_argument("--legacy", metavar="METHOD", choices=["gutmann", "dod3", "dod7"],
                               help="Legacy method: gutmann|dod3|dod7 (educational only, not recommended)")
    method_group.add_argument("--purge-info", action="store_true", default=False,
                               help="Display NIST PURGE information (no file operation)")

    parser.add_argument("--recursive", "-r", action="store_true", help="Recursively erase directory")
    parser.add_argument("--randomize-name", action="store_true", help="Randomize filename before deletion")
    parser.add_argument("--cleanup-logs", action="store_true", help="Securely delete the audit log")
    parser.add_argument("--no-confirm", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--version", action="version", version="SDET 1.0.0")

    return parser

def _resolve_method(args) -> tuple[str, str, int]:
    if args.legacy == "gutmann":
        return (
            "gutmann",
            "⚠ LEGACY — Gutmann 35-pass (EDUCATIONAL ONLY)\n"
            "  NOT recommended for SSDs. Ineffective due to wear leveling.",
            35,
        )
    if args.legacy == "dod3":
        return (
            "dod",
            "⚠ DEPRECATED — DoD 3-pass (NOT RECOMMENDED)\n"
            "  Obsolete per NIST SP 800-88 Rev. 2.",
            3,
        )
    if args.legacy == "dod7":
        return (
            "dod",
            "⚠ DEPRECATED — DoD 7-pass (NOT RECOMMENDED)\n"
            "  Obsolete per NIST SP 800-88 Rev. 2.",
            7,
        )

    return (
        "nist_clear",
        "✅ NIST SP 800-88 Rev. 2 CLEAR (Recommended)\n"
        "  1-pass random overwrite + fsync + truncate + unlink",
        1,
    )

def _run_directory(target_path: str, args) -> int:
    results = erase_directory(
        target_path,
        method=args.method_key,
        passes=args.dod_passes,
        randomize_name=args.randomize_name,
        progress_callback=_cli_progress,
    )
    print()
    success = sum(1 for r in results if r.get("status") == "SUCCESS")
    failed = len(results) - success
    _print_colored(
        f"  Results: {success} succeeded, {failed} failed",
        "green" if failed == 0 else "yellow",
    )
    for r in results:
        _print_result(r)
    return 0

def _run_file(target_path: str, args) -> int:
    if args.method_key == "gutmann":
        _print_colored("  Starting Gutmann 35-pass (this may take a while)...", "yellow")
        result = gutmann_35pass(target_path, args.randomize_name, _cli_progress)
    elif args.method_key == "dod":
        _print_colored(f"  Starting DoD {args.dod_passes}-pass...", "yellow")
        result = dod_overwrite(target_path, args.dod_passes, args.randomize_name, _cli_progress)
    else:
        result = nist_clear(target_path, args.randomize_name, _cli_progress)

    print()
    _print_result(result)
    return 0

def _print_target_summary(target_path: str, method_label: str, randomize_name: bool) -> None:
    # <--- PATCH S05: Topeng (Mask) laluan fail di antaramuka CLI
    masked_target = _mask_filename(os.path.basename(target_path))
    
    _print_colored("  Target:  " + masked_target + " (Masked for Visual Privacy)", "white")
    _print_colored("  Method:  " + method_label, "cyan")
    if randomize_name:
        _print_colored("  Option:  Randomize filename enabled", "white")
    _print_colored("\n  ⚠ WARNING: This operation is IRREVERSIBLE.\n", "yellow")

def _handle_purge_info(args):
    if not args.purge_info:
        return None
    print(NIST_PURGE_INFO)
    return 0

def _handle_cleanup_logs(args):
    if not args.cleanup_logs:
        return None
    _print_colored("  Securely deleting audit log...", "cyan")
    ok = delete_audit_log()
    _print_colored(
        "  ✔ Audit log securely deleted." if ok else "  ✖ Failed to delete audit log (may not exist).",
        "green" if ok else "yellow",
    )
    return 0 if ok else 1

def _resolve_target(args, parser):
    if not args.file and not args.dir:
        _print_colored("  ✖ ERROR: Specify --file or --dir.\n", "red")
        parser.print_help()
        raise ValueError("missing target")

    target_path = args.file or args.dir
    is_dir = bool(args.dir) or os.path.isdir(target_path)

    if is_dir and not args.recursive:
        _print_colored(
            "  ✖ ERROR: Target is a directory. Use --recursive to erase all files inside.",
            "red",
        )
        raise ValueError("directory requires recursive")

    return target_path, is_dir

def main() -> int:
    parser = _build_arg_parser()
    
    # --- BLOK PERLINDUNGAN DOUBLE-CLICK (IDIOT-PROOF) ---
    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        print("\n  [!] WARNING: You tried to open this application using the GUI (Double-Click).")
        print("      This is a Command-Line (CLI) tool. Please open a Terminal/PowerShell")
        print("      and run this file with parameters. Example:")
        print("      .\\SDET-CLI-Windows.exe --help")
        print("      .\\SDET-CLI-Windows.exe --file sensitive_document.txt\n")
        input("  Press ENTER to exit...")
        return 1
    # ----------------------------------------------------

    args = parser.parse_args()

    # <--- PATCH S05: Padam sejarah terminal dengan pantas untuk elak intipan arahan
    if not args.purge_info and not args.cleanup_logs:
        os.system('cls' if os.name == 'nt' else 'clear')

    print(BANNER)

    for handler in (_handle_purge_info, _handle_cleanup_logs):
        result = handler(args)
        if result is not None:
            return result

    try:
        target_path, is_dir = _resolve_target(args, parser)
    except ValueError:
        return 1

    args.method_key, method_label, args.dod_passes = _resolve_method(args)

    _print_target_summary(target_path, method_label, args.randomize_name)

    if not args.no_confirm and not _confirm("  Are you sure you want to securely erase this target?"):
        _print_colored("  Aborted by user.", "yellow")
        return 0

    print()
    return _run_directory(target_path, args) if is_dir else _run_file(target_path, args)

# --- KRITIKAL: BAHAGIAN PEMANGGILAN UTAMA ---
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n  [!] Dibatalkan oleh pengguna (Ctrl+C).")
        sys.exit(130)
    except Exception as e:
        print(f"\n  [!] Ralat Kritikal: {e}")
        sys.exit(1)