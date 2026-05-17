import argparse
import sys
import os
import threading

# Pastikan import dari sdet.erasure_engine berjaya
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sdet.erasure_engine import (
    nist_clear,
    gutmann_35pass,
    dod_overwrite,
    _is_blacklisted,
    _mask_filename
)

def create_parser():
    parser = argparse.ArgumentParser(description="SDET - Secure Data Erasure Tool (CLI)")
    parser.add_argument("-f", "--file", help="Target file to securely delete", required=True)
    parser.add_argument("--nist-clear", action="store_true", help="Use NIST SP 800-88 CLEAR method (Default)")
    parser.add_argument("--legacy", choices=["gutmann", "dod3", "dod7"], help="Use legacy erasure methods")
    parser.add_argument("--randomize-name", action="store_true", help="Obfuscate filename before deletion")
    return parser


def validate_target(target_path):
    if _is_blacklisted(target_path):
        print("\n[BLOCKED_BLACKLIST] Critical system path protected.")
        print(f"Path: {os.path.abspath(target_path)}")
        print("Operation cancelled to prevent OS damage.")
        sys.exit(1)

    if not os.path.exists(target_path):
        print(f"\n[ERROR] Target file does not exist:\n{os.path.abspath(target_path)}")
        sys.exit(1)


def get_method_display(args):
    if args.legacy == "gutmann":
        return "Gutmann 35-pass (LEGACY)"
    if args.legacy == "dod3":
        return "DoD 3-pass (DEPRECATED)"
    if args.legacy == "dod7":
        return "DoD 7-pass (DEPRECATED)"
    return "✅ NIST SP 800-88 Rev. 2 CLEAR (Recommended)\n  1-pass random overwrite + fsync + truncate + unlink"


def prompt_confirmation():
    try:
        confirm = input("  Are you sure you want to securely erase this target? [y/N]: ")
    except EOFError:
        sys.exit(1)

    if confirm.lower() != 'y':
        print("\n  [ABORTED] Operation cancelled by user.")
        sys.exit(0)


def select_erase_method(args, target_path, progress_callback, stop_event):
    if args.legacy == "gutmann":
        return gutmann_35pass(target_path, args.randomize_name, progress_callback, stop_event)
    if args.legacy == "dod3":
        return dod_overwrite(target_path, 3, args.randomize_name, progress_callback, stop_event)
    if args.legacy == "dod7":
        return dod_overwrite(target_path, 7, args.randomize_name, progress_callback, stop_event)
    return nist_clear(target_path, args.randomize_name, progress_callback, stop_event)


def print_banner(masked, method_disp):
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║            SDET — Secure Data Erasure Tool v1.0              ║")
    print("║      NIST SP 800-88 Rev. 2 Aligned File-Level Sanitization   ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")
    print(f"  Target:  {masked} (Masked for Visual Privacy)")
    print(f"  Method:  {method_disp}")
    print("\n  ⚠ WARNING: This operation is IRREVERSIBLE.\n")


def main():
    parser = create_parser()
    args = parser.parse_args()
    target_path = args.file

    validate_target(target_path)
    os.system('cls' if os.name == 'nt' else 'clear')

    masked = _mask_filename(os.path.basename(target_path))
    method_disp = get_method_display(args)
    print_banner(masked, method_disp)
    prompt_confirmation()

    print("")  # Baris kosong untuk kekemasan UI

    stop_event = threading.Event()

    def progress_callback(pct, msg):
        # Cetak peratusan di terminal pada baris yang sama (\r)
        print(f"\r  [{'█' * int(pct * 40):<40}] {pct * 100:.0f}%  {msg}", end="", flush=True)

    try:
        res = select_erase_method(args, target_path, progress_callback, stop_event)
        print("\n\n")  # Baris baharu selepas progress bar tamat

        if res["status"] == "SUCCESS":
            print(f"  ✔ {res.get('masked_name', masked)} — {res.get('method', 'ERASED')} — SUCCESS")
        else:
            print(f"  ✖ Failed: {res['status']}")

    except PermissionError:
        print("\n\n  PERMISSION_ERROR: Permission denied.")
        print("  The file may be in use by another process (File Lock) or requires Administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n  UNEXPECTED ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Penangkap Ralat "Ctrl + C" untuk keluar dengan kemas
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [ABORTED] Operation forcibly cancelled by user (Ctrl+C).")
        sys.exit(0)