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

def main():
    parser = argparse.ArgumentParser(description="SDET - Secure Data Erasure Tool (CLI)")
    parser.add_argument("-f", "--file", help="Target file to securely delete", required=True)
    parser.add_argument("--nist-clear", action="store_true", help="Use NIST SP 800-88 CLEAR method (Default)")
    parser.add_argument("--legacy", choices=["gutmann", "dod3", "dod7"], help="Use legacy erasure methods")
    parser.add_argument("--randomize-name", action="store_true", help="Obfuscate filename before deletion")

    args = parser.parse_args()
    target_path = args.file

    # ---------------------------------------------------------
    # TEST-S01: Directory Traversal & Blacklist Defense
    # ---------------------------------------------------------
    if _is_blacklisted(target_path):
        print(f"\n[BLOCKED_BLACKLIST] Critical system path protected.")
        print(f"Path: {os.path.abspath(target_path)}")
        print("Operation cancelled to prevent OS damage.")
        sys.exit(1)

    if not os.path.exists(target_path):
        print(f"\n[ERROR] Target file does not exist:\n{os.path.abspath(target_path)}")
        sys.exit(1)

    # ---------------------------------------------------------
    # TEST-S05: GUI / CLI Shoulder Surfing Defense
    # ---------------------------------------------------------
    masked = _mask_filename(os.path.basename(target_path))
    print(f"\nTarget: {masked} (Filename Masked for Privacy)")

    stop_event = threading.Event()

    def progress_callback(pct, msg):
        # Cetak peratusan di terminal pada baris yang sama (\r)
        print(f"\rProgress: [{pct:.1f}%] {msg}", end="", flush=True)

    try:
        if args.legacy == "gutmann":
            print("Method: Gutmann 35-pass (LEGACY)\n")
            res = gutmann_35pass(target_path, args.randomize_name, progress_callback, stop_event)
        elif args.legacy == "dod3":
            print("Method: DoD 3-pass (DEPRECATED)\n")
            res = dod_overwrite(target_path, 3, args.randomize_name, progress_callback, stop_event)
        elif args.legacy == "dod7":
            print("Method: DoD 7-pass (DEPRECATED)\n")
            res = dod_overwrite(target_path, 7, args.randomize_name, progress_callback, stop_event)
        else:
            print("Method: NIST SP 800-88 Rev. 2 CLEAR\n")
            res = nist_clear(target_path, args.randomize_name, progress_callback, stop_event)

        print("\n") # Baris baharu selepas progress bar tamat
        
        if res["status"] == "SUCCESS":
            print(f"✔ {res.get('masked_name', masked)} — {res.get('method', 'ERASED')} — SUCCESS")
        else:
            print(f"✖ Failed: {res['status']}")

    # ---------------------------------------------------------
    # TEST-S03 & S04: Privilege Escalation & Race Condition
    # ---------------------------------------------------------
    except PermissionError:
        print("\nPERMISSION_ERROR: Permission denied.")
        print("The file may be in use by another process (File Lock) or requires Administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\nUNEXPECTED ERROR: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()