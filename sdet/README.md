# SDET — Secure Data Erasure Tool

**NIST SP 800-88 Rev. 2 Aligned | File-Level Sanitization**

---

## Overview

SDET is a cross-platform secure file deletion tool that implements NIST SP 800-88 Rev. 2 CLEAR sanitization at the file-system level. It provides both a command-line interface (CLI) and a modern graphical user interface (GUI) built with CustomTkinter.

### NIST SP 800-88 Compliance Model

| Method | Status | Notes |
|--------|--------|-------|
| NIST CLEAR | ✅ Implemented (Default) | 1-pass random overwrite + fsync + truncate + unlink |
| NIST PURGE | ℹ Info Only | Requires firmware tools (nvme-cli, hdparm) |
| NIST DESTROY | ❌ Out of Scope | Physical destruction only |
| Gutmann 35-pass | ⚠ Legacy/Educational | Not recommended for SSDs |
| DoD 3/7-pass | ⚠ Deprecated | Obsolete per NIST SP 800-88 |

---

## Installation

```bash
pip install customtkinter
```

---

## Usage

### GUI

```bash
python sdet/sdet_gui.py
```

### CLI

```bash
# Default: NIST Clear (recommended)
python sdet/sdet_cli.py --file secret.txt

# Gutmann 35-pass (legacy, educational only)
python sdet/sdet_cli.py --file secret.txt --legacy gutmann

# DoD 3-pass (deprecated)
python sdet/sdet_cli.py --file secret.txt --legacy dod3

# DoD 7-pass (deprecated)
python sdet/sdet_cli.py --file secret.txt --legacy dod7

# NIST PURGE information only (no file operation)
python sdet/sdet_cli.py --purge-info

# Recursive directory erasure
python sdet/sdet_cli.py --dir /path/to/folder --recursive

# With filename randomization
python sdet/sdet_cli.py --file secret.txt --randomize-name

# Delete audit log
python sdet/sdet_cli.py --cleanup-logs

# Skip confirmation
python sdet/sdet_cli.py --file secret.txt --no-confirm
```

---

## NIST CLEAR Implementation Details

The NIST Clear method performs:

1. **1-pass random overwrite** — Fills all user-addressable bytes with cryptographically random data via `os.urandom()`
2. **fsync / FlushFileBuffers** — Forces write completion to physical media
3. **File truncation** — Reduces file size to zero
4. **Directory entry removal** — `os.unlink()` removes the file system entry
5. **Optional filename randomization** — Renames file to a random string before deletion to prevent metadata leakage

**Note:** NIST CLEAR is logical file-system sanitization. It does NOT guarantee hardware-level erasure on SSDs due to Flash Translation Layer (FTL) and wear leveling. For firmware-level PURGE, use: `nvme format`, `hdparm --security-erase`, or vendor utilities.

---

## Ethical Logging

- **Audit log** (`~/.sdet_audit.log`): SHA-256 hashed file paths only — no raw paths stored
- **UI activity log**: Filenames displayed as masked (e.g., `sec***.txt`) for shoulder-surf protection
- **In-memory only**: The GUI log exists only in RAM and clears on exit

---

## Safe Mode — System Blacklist

The following critical paths are protected and cannot be erased:

- Unix: `/bin`, `/boot`, `/dev`, `/etc`, `/lib`, `/proc`, `/sbin`, `/sys`, `/usr`, `/var`
- Windows: `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`

Any attempt to erase a protected path is **blocked** with an "Accidental Deletion Prevented" error.

---

## Disclaimer

SDET implements NIST SP 800-88 Rev. 2 CLEAR — logical sanitization only. It does NOT perform firmware-level PURGE or physical DESTROY operations. Legacy overwrite methods (Gutmann, DoD) are included strictly for educational comparison and are not recommended for production use.
