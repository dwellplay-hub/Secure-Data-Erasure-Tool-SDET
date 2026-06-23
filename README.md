# Secure Data Erasure Tool (SDET)

A production-grade, secure data deletion utility featuring both a Modern Desktop Graphical User Interface (GUI) and a Command Line Interface (CLI). 

## 🛠️ System Architecture & Frameworks
- **Core Engine:** Pure Python 3 
- **GUI Controller (`main.py`):** Driven by `CustomTkinter` 
- **CLI Controller (`cli.py`):** Driven by Python's native `argparse` with strict validation schemes.

## 🔒 Sanitization Standards Implemented
1. **NIST SP 800-88 Rev. (1-Pass CLEAR)
2. **DoD 5220.22-M (3-Pass & 7-Pass)
3. **Gutmann Algorithm (35-Pass)

