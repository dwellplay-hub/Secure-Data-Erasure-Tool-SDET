# Secure Data Erasure Tool (SDET)

A production-grade, secure data destruction utility featuring both a Modern Desktop Graphical User Interface (GUI) and a robust Command Line Interface (CLI). 

## 🛠️ System Architecture & Frameworks
- **Core Engine:** Pure Python 3 with low-level OS file descriptor locking and streaming I/O buffers.
- **GUI Controller (`main.py`):** Driven by `CustomTkinter` implementing responsive design and stateful thread handling.
- **CLI Controller (`cli.py`):** Driven by Python's native `argparse` with strict validation schemes.

## 🔒 Sanitization Standards Implemented
1. **NIST SP 800-88 Rev. 1 CLEAR:** Single-pass cryptographic pseudo-random overwrite with hardware-level flush validation (`os.fsync`).
2. **DoD 5220.22-M (3-Pass & 7-Pass):** Legacy defense compliance penimpaan multi-pass.
3. **Gutmann Algorithm (35-Pass):** Complete academic magnetic-domain erasure sequence.

## 🛡️ Security Hardening Features
- **CWE-23 Path Traversal Shield:** Resolves absolute canonical paths via `pathlib.Path.resolve()` to prevent arbitrary file deletions.
- **Race Condition Lock Guard:** Leverages exclusive OS file-locking (`msvcrt` / `fcntl`) during active deletion streams.
- **Pseudonymized Logging:** Compiles audit logs with SHA-256 hash matching paths and filename masking to enforce data privacy (PDPA compliance).

## 🚀 Installation & Setup
Ensure you have Python 3.10+ installed. Clone the repository and install dependencies:
```bash
pip install -r requirements.txt

GUI mode
python main.py

CLI mode
python cli.py --file "sensitive_document.txt" --legacy gutmann