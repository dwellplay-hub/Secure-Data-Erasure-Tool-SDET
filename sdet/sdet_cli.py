#!/usr/bin/env python3
"""
SDET CLI — Secure Data Erasure Tool Command-Line Interface
NIST SP 800-88 Rev. 2 Aligned

Usage:
    python sdet_cli.py --file <path> [options]

Options:
    --nist-clear          NIST SP 800-88 CLEAR (default, recommended)
    --legacy gutmann      Gutmann 35-pass (LEGACY - educational only)
    --legacy dod3         DoD 3-pass (DEPRECATED - educational only)
    --legacy dod7         DoD 7-pass (DEPRECATED - educational only)
    --purge-info          Display NIST PURGE information only (no erasure)
    --recursive           Recursively erase all files in a directory
    --randomize-name      Randomize filename before deletion (metadata obfuscation)
    --cleanup-logs        Securely delete the audit log file
    --no-confirm          Skip confirmation prompt (use with care)
"""

import sys
import os
import argparse
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sdet.erasure_engine import (
    nist_clear,
    gutmann_35pass,
    dod_overwrite,
    erase_directory,
    delete_audit_log,
    AUDIT_LOG_FILE,
)


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║          SDET — Secure Data Erasure Tool v1.0               ║
║     NIST SP 800-88 Rev. 2 Aligned File-Level Sanitization   ║
╚══════════════════════════════════════════════════════════════╝
"""

NIST_PURGE_INFO = """
╔══════════════════════════════════════════════════════════════╗
║                 ℹ  NIST PURGE — Information Only             ║
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
    else:
        _print_colored(f"  ✖ {masked} — {status}", "red")


def _confirm(prompt: str) -> bool:
    try:
        response = input(f"{prompt} [y/N]: ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _cli_progress(pct: float, msg: str) -> None:
    bar_len = 40
    filled = int(bar_len * pct)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r  [{bar}] {int(pct * 100):3d}%  {msg[:40]:<40}")
    sys.stdout.flush()
    if pct >= 1.0:
        print()


def main() -> int:
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

    args = parser.parse_args()

    print(BANNER)

    if args.purge_info:
        print(NIST_PURGE_INFO)
        return 0

    if args.cleanup_logs:
        _print_colored("  Securely deleting audit log...", "cyan")
        ok = delete_audit_log()
        if ok:
            _print_colored("  ✔ Audit log securely deleted.", "green")
        else:
            _print_colored("  ✖ Failed to delete audit log (may not exist).", "yellow")
        return 0 if ok else 1

    if not args.file and not args.dir:
        _print_colored("  ✖ ERROR: Specify --file or --dir.\n", "red")
        parser.print_help()
        return 1

    target_path = args.file or args.dir
    is_dir = bool(args.dir) or os.path.isdir(target_path)

    if is_dir and not args.recursive:
        _print_colored("  ✖ ERROR: Target is a directory. Use --recursive to erase all files inside.", "red")
        return 1

    if args.legacy == "gutmann":
        method_label = "⚠ LEGACY — Gutmann 35-pass (EDUCATIONAL ONLY)"
        method_label += "\n  NOT recommended for SSDs. Ineffective due to wear leveling."
        method_key = "gutmann"
        dod_passes = 3
    elif args.legacy == "dod3":
        method_label = "⚠ DEPRECATED — DoD 3-pass (NOT RECOMMENDED)"
        method_label += "\n  Obsolete per NIST SP 800-88 Rev. 2."
        method_key = "dod"
        dod_passes = 3
    elif args.legacy == "dod7":
        method_label = "⚠ DEPRECATED — DoD 7-pass (NOT RECOMMENDED)"
        method_label += "\n  Obsolete per NIST SP 800-88 Rev. 2."
        method_key = "dod"
        dod_passes = 7
    else:
        method_label = "✅ NIST SP 800-88 Rev. 2 CLEAR (Recommended)"
        method_label += "\n  1-pass random overwrite + fsync + truncate + unlink"
        method_key = "nist_clear"
        dod_passes = 3

    _print_colored("  Target:  " + target_path, "white")
    _print_colored("  Method:  " + method_label, "cyan")
    if args.randomize_name:
        _print_colored("  Option:  Randomize filename enabled", "white")

    _print_colored("\n  ⚠ WARNING: This operation is IRREVERSIBLE.\n", "yellow")

    if not args.no_confirm:
        if not _confirm("  Are you sure you want to securely erase this target?"):
            _print_colored("  Aborted by user.", "yellow")
            return 0

    print()

    if is_dir:
        results = erase_directory(
            target_path,
            method=method_key,
            passes=dod_passes,
            randomize_name=args.randomize_name,
            progress_callback=_cli_progress,
        )
        print()
        success = sum(1 for r in results if r.get("status") == "SUCCESS")
        failed = len(results) - success
        _print_colored(f"  Results: {success} succeeded, {failed} failed", "green" if failed == 0 else "yellow")
        for r in results:
            _print_result(r)
    else:
        if method_key == "gutmann":
            _print_colored("  Starting Gutmann 35-pass (this may take a while)...", "yellow")
            result = gutmann_35pass(target_path, args.randomize_name, _cli_progress)
        elif method_key == "dod":
            _print_colored(f"  Starting DoD {dod_passes}-pass...", "yellow")
            result = dod_overwrite(target_path, dod_passes, args.randomize_name, _cli_progress)
        else:
            result = nist_clear(target_path, args.randomize_name, _cli_progress)

        print()
        _print_result(result)

    print()
    _print_colored(f"  Audit log: ~/{AUDIT_LOG_FILE} (SHA-256 anonymized, no raw paths stored)", "cyan")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
