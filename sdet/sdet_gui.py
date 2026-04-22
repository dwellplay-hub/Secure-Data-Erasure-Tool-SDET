#!/usr/bin/env python3
"""
SDET GUI — Secure Data Erasure Tool Graphical User Interface
Built with CustomTkinter for a modern, dark-mode experience.
NIST SP 800-88 Rev. 2 Aligned
"""

import sys
import os
import threading
import datetime
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import customtkinter as ctk
except ImportError:
    print("ERROR: customtkinter is not installed.")
    print("Install it with:  pip install customtkinter")
    sys.exit(1)

from tkinter import filedialog, messagebox
import tkinter as tk

from sdet.erasure_engine import (
    nist_clear,
    gutmann_35pass,
    dod_overwrite,
    erase_directory,
    delete_audit_log,
    _mask_filename,
    AUDIT_LOG_FILE,
)


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

APP_TITLE = "SDET — Secure Data Erasure Tool"
APP_VERSION = "v1.0"

COLOR_SAFE = "#2fa36b"
COLOR_WARNING = "#e8a020"
COLOR_DANGER = "#d94040"
COLOR_INFO = "#4f9bdb"
COLOR_BG = "#1a1a2e"
COLOR_CARD = "#16213e"
COLOR_CARD2 = "#0f3460"
COLOR_TEXT = "#e0e0e0"
COLOR_DIM = "#888888"

NIST_PURGE_TEXT = (
    "NIST PURGE requires firmware-level commands — not achievable via software.\n\n"
    "WHY software overwrite is insufficient for PURGE:\n"
    "  • SSDs use Flash Translation Layer (FTL) and wear leveling\n"
    "  • Write commands may not reach the same physical cells\n"
    "  • Data may survive in unmapped/reserved sectors\n\n"
    "RECOMMENDED TOOLS FOR NIST PURGE:\n"
    "  • Linux/NVMe:  nvme format /dev/nvme0 --ses=1\n"
    "  • Linux/SATA:  hdparm --security-erase <device>\n"
    "  • Windows:     Manufacturer secure erase utilities\n"
    "  • macOS:       Disk Utility with security options"
)


class SDETApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"{APP_TITLE}  {APP_VERSION}")
        self.geometry("920x720")
        self.minsize(800, 640)
        self.configure(fg_color=COLOR_BG)

        self._erase_thread: threading.Thread = None
        self._stop_event = threading.Event()
        self._is_erasing = False
        self._selected_path = tk.StringVar(value="")
        self._is_directory = False
        self._ui_log_lines = []

        self._mode = tk.StringVar(value="normal")
        self._method = tk.StringVar(value="nist_clear")
        self._randomize = tk.BooleanVar(value=False)
        self._recursive = tk.BooleanVar(value=False)

        self.protocol("WM_DELETE_WINDOW", self._safe_exit)
        self._build_ui()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_header()
        self._build_main_content()
        self._build_footer()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=COLOR_CARD2, corner_radius=0, height=70)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        icon_label = ctk.CTkLabel(
            header, text="🔒", font=ctk.CTkFont(size=28), text_color=COLOR_INFO
        )
        icon_label.grid(row=0, column=0, padx=(20, 10), pady=12)

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.grid(row=0, column=1, sticky="w", pady=12)

        ctk.CTkLabel(
            title_frame,
            text="Secure Data Erasure Tool",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=COLOR_TEXT,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame,
            text="NIST SP 800-88 Rev. 2 Aligned  |  File-Level Sanitization",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_DIM,
        ).pack(anchor="w")

        mode_frame = ctk.CTkFrame(header, fg_color="transparent")
        mode_frame.grid(row=0, column=2, padx=20, pady=12)

        ctk.CTkLabel(
            mode_frame, text="Mode:", font=ctk.CTkFont(size=12), text_color=COLOR_DIM
        ).pack(side="left", padx=(0, 8))

        self._mode_switch = ctk.CTkSegmentedButton(
            mode_frame,
            values=["Normal", "Advanced"],
            command=self._on_mode_change,
            font=ctk.CTkFont(size=12),
            width=160,
        )
        self._mode_switch.set("Normal")
        self._mode_switch.pack(side="left")

    def _build_main_content(self):
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew", padx=16, pady=8)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        self._build_left_panel(content)
        self._build_right_panel(content)

    def _build_left_panel(self, parent):
        left = ctk.CTkFrame(parent, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)

        self._build_file_card(left)
        self._build_method_card(left)
        self._build_options_card(left)
        self._build_action_card(left)

    def _build_file_card(self, parent):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12)
        card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text="TARGET",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=COLOR_DIM,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        path_frame = ctk.CTkFrame(card, fg_color="transparent")
        path_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        path_frame.columnconfigure(0, weight=1)

        self._path_entry = ctk.CTkEntry(
            path_frame,
            textvariable=self._selected_path,
            placeholder_text="No file or folder selected...",
            font=ctk.CTkFont(size=12),
            height=36,
            state="readonly",
        )
        self._path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        btn_frame = ctk.CTkFrame(path_frame, fg_color="transparent")
        btn_frame.grid(row=0, column=1)

        ctk.CTkButton(
            btn_frame,
            text="📄 File",
            width=80,
            height=36,
            command=self._browse_file,
            font=ctk.CTkFont(size=12),
            fg_color=COLOR_INFO,
            hover_color="#3a7bc8",
        ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            btn_frame,
            text="📁 Folder",
            width=80,
            height=36,
            command=self._browse_dir,
            font=ctk.CTkFont(size=12),
            fg_color="#555577",
            hover_color="#444466",
        ).pack(side="left")

    def _build_method_card(self, parent):
        self._method_card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12)
        self._method_card.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self._method_card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._method_card,
            text="ERASURE METHOD",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=COLOR_DIM,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self._normal_method_frame = ctk.CTkFrame(self._method_card, fg_color="transparent")
        self._normal_method_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))

        ctk.CTkLabel(
            self._normal_method_frame,
            text="✅  NIST SP 800-88 Rev. 2 CLEAR",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLOR_SAFE,
        ).pack(anchor="w")

        ctk.CTkLabel(
            self._normal_method_frame,
            text="  1-pass random overwrite + fsync + truncate + unlink\n  Recommended for all modern storage media.",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_DIM,
            justify="left",
        ).pack(anchor="w")

        self._advanced_method_frame = ctk.CTkFrame(self._method_card, fg_color="transparent")

        methods = [
            ("nist_clear",   "✅  NIST SP 800-88 CLEAR",        "Recommended — 1-pass random + fsync + unlink",  COLOR_SAFE),
            ("gutmann",      "⚠  Gutmann 35-pass",              "LEGACY — Not for SSDs. Educational only.",       COLOR_WARNING),
            ("dod3",         "⚠  DoD 3-pass",                   "DEPRECATED per NIST SP 800-88. Educational.",    COLOR_WARNING),
            ("dod7",         "⚠  DoD 7-pass",                   "DEPRECATED per NIST SP 800-88. Educational.",    COLOR_WARNING),
            ("purge_info",   "ℹ  NIST PURGE (Info Only)",        "Software cannot perform PURGE. Info only.",      COLOR_INFO),
        ]

        for method_id, label, desc, color in methods:
            row = ctk.CTkFrame(self._advanced_method_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)

            rb = ctk.CTkRadioButton(
                row,
                text=label,
                variable=self._method,
                value=method_id,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=color,
                command=self._on_method_change,
            )
            rb.pack(anchor="w")

            ctk.CTkLabel(
                row,
                text=f"     {desc}",
                font=ctk.CTkFont(size=10),
                text_color=COLOR_DIM,
                justify="left",
            ).pack(anchor="w")

    def _build_options_card(self, parent):
        self._options_card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12)
        self._options_card.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self._options_card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._options_card,
            text="OPTIONS",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=COLOR_DIM,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        opt_frame = ctk.CTkFrame(self._options_card, fg_color="transparent")
        opt_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))

        self._randomize_switch = ctk.CTkSwitch(
            opt_frame,
            text="Randomize Filename  (metadata obfuscation)",
            variable=self._randomize,
            onvalue=True,
            offvalue=False,
            font=ctk.CTkFont(size=12),
            progress_color=COLOR_INFO,
        )
        self._randomize_switch.pack(anchor="w", pady=3)

        self._recursive_switch = ctk.CTkSwitch(
            opt_frame,
            text="Recursive Deletion  (erase entire folder)",
            variable=self._recursive,
            onvalue=True,
            offvalue=False,
            font=ctk.CTkFont(size=12),
            progress_color=COLOR_WARNING,
            command=self._on_recursive_change,
        )
        self._recursive_switch.pack(anchor="w", pady=3)

        sep = ctk.CTkFrame(opt_frame, fg_color=COLOR_DIM, height=1)
        sep.pack(fill="x", pady=8)

        ctk.CTkButton(
            opt_frame,
            text="🗑  Delete Audit Log",
            width=200,
            height=30,
            command=self._delete_audit_log,
            font=ctk.CTkFont(size=11),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            text_color=COLOR_DIM,
        ).pack(anchor="w")

    def _build_action_card(self, parent):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12)
        card.grid(row=3, column=0, sticky="ew", pady=(0, 0))
        card.columnconfigure(0, weight=1)

        self._progress_bar = ctk.CTkProgressBar(
            card, mode="determinate", height=8, progress_color=COLOR_SAFE
        )
        self._progress_bar.set(0)
        self._progress_bar.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))

        self._progress_label = ctk.CTkLabel(
            card, text="Ready", font=ctk.CTkFont(size=11), text_color=COLOR_DIM
        )
        self._progress_label.grid(row=1, column=0, sticky="w", padx=16)

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(8, 14))
        btn_row.columnconfigure(0, weight=1)

        self._erase_btn = ctk.CTkButton(
            btn_row,
            text="🔒  Secure Delete",
            height=46,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color=COLOR_DANGER,
            hover_color="#b03030",
            command=self._start_erase,
        )
        self._erase_btn.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self._abort_btn = ctk.CTkButton(
            btn_row,
            text="⏹  Abort",
            height=46,
            width=100,
            font=ctk.CTkFont(size=13),
            fg_color="#444444",
            hover_color="#555555",
            command=self._abort_erase,
            state="disabled",
        )
        self._abort_btn.grid(row=0, column=1)

        self._exit_btn = ctk.CTkButton(
            btn_row,
            text="Exit",
            height=46,
            width=80,
            font=ctk.CTkFont(size=13),
            fg_color="#333333",
            hover_color="#444444",
            command=self._safe_exit,
        )
        self._exit_btn.grid(row=0, column=2, padx=(8, 0))

    def _build_right_panel(self, parent):
        right = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=12)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        header = ctk.CTkFrame(right, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))
        header.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="ACTIVITY LOG",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=COLOR_DIM,
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="🔒 Visual Privacy: Filenames masked",
            font=ctk.CTkFont(size=9),
            text_color=COLOR_INFO,
        ).grid(row=0, column=1, sticky="e")

        self._log_textbox = ctk.CTkTextbox(
            right,
            font=ctk.CTkFont(family="Courier", size=11),
            fg_color="#0d0d1a",
            text_color=COLOR_TEXT,
            state="disabled",
            corner_radius=8,
            wrap="word",
        )
        self._log_textbox.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

        ctk.CTkButton(
            right,
            text="Clear Log",
            height=28,
            width=100,
            font=ctk.CTkFont(size=11),
            fg_color="#333333",
            hover_color="#444444",
            command=self._clear_log,
        ).grid(row=2, column=0, sticky="e", padx=12, pady=(0, 12))

        nist_info_card = ctk.CTkFrame(right, fg_color="#0a1628", corner_radius=8)
        nist_info_card.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 12))

        ctk.CTkLabel(
            nist_info_card,
            text="⚠ NIST CLEAR is LOGICAL sanitization only.\nIt does NOT perform firmware-level PURGE.\nFor SSDs, firmware tools may be required.",
            font=ctk.CTkFont(size=10),
            text_color=COLOR_WARNING,
            justify="left",
        ).pack(padx=12, pady=10, anchor="w")

    def _build_footer(self):
        footer = ctk.CTkFrame(self, fg_color=COLOR_CARD, corner_radius=0, height=30)
        footer.grid(row=2, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            footer,
            text=(
                "SDET v1.0  |  NIST SP 800-88 Rev. 2 CLEAR  |  "
                "Audit log uses SHA-256 anonymization  |  No raw paths stored"
            ),
            font=ctk.CTkFont(size=10),
            text_color=COLOR_DIM,
        ).grid(row=0, column=0, pady=6)

    def _on_mode_change(self, value):
        if value == "Advanced":
            self._normal_method_frame.grid_remove()
            self._advanced_method_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        else:
            self._advanced_method_frame.grid_remove()
            self._normal_method_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
            self._method.set("nist_clear")

    def _on_method_change(self):
        if self._method.get() == "purge_info":
            self._show_purge_info()
            self._method.set("nist_clear")
            return

        method = self._method.get()
        if method in ("gutmann", "dod3", "dod7"):
            self._progress_bar.configure(progress_color=COLOR_WARNING)
        else:
            self._progress_bar.configure(progress_color=COLOR_SAFE)

    def _on_recursive_change(self):
        # The recursive switch is user-facing, so log the change
        # rather than leaving the callback empty.
        if self._recursive.get():
            self._log("Recursive deletion enabled.", COLOR_INFO)
        else:
            self._log("Recursive deletion disabled.", COLOR_DIM)

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select file to erase")
        if path:
            self._selected_path.set(path)
            self._is_directory = False
            self._recursive.set(False)
            self._log(f"Selected file: {_mask_filename(os.path.basename(path))}", COLOR_INFO)

    def _browse_dir(self):
        path = filedialog.askdirectory(title="Select folder to erase")
        if path:
            self._selected_path.set(path)
            self._is_directory = True
            self._recursive.set(True)
            self._log(f"Selected folder: {_mask_filename(os.path.basename(path))}", COLOR_WARNING)

    def _log(self, message: str, color: str = None):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_textbox.configure(state="normal")
        self._log_textbox.insert("end", f"[{timestamp}] {message}\n")
        self._log_textbox.configure(state="disabled")
        self._log_textbox.see("end")

    def _clear_log(self):
        self._log_textbox.configure(state="normal")
        self._log_textbox.delete("1.0", "end")
        self._log_textbox.configure(state="disabled")

    def _show_purge_info(self):
        win = ctk.CTkToplevel(self)
        win.title("NIST PURGE — Information Only")
        win.geometry("540x420")
        win.configure(fg_color=COLOR_BG)
        win.grab_set()

        ctk.CTkLabel(
            win,
            text="ℹ  NIST PURGE — Information Only",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLOR_INFO,
        ).pack(pady=(20, 8), padx=20)

        text = ctk.CTkTextbox(
            win, font=ctk.CTkFont(family="Courier", size=11),
            fg_color="#0d0d1a", text_color=COLOR_TEXT, wrap="word"
        )
        text.pack(fill="both", expand=True, padx=20, pady=8)
        text.insert("end", NIST_PURGE_TEXT)
        text.configure(state="disabled")

        ctk.CTkButton(
            win, text="Close", command=win.destroy,
            fg_color=COLOR_INFO, font=ctk.CTkFont(size=13)
        ).pack(pady=12)

    def _delete_audit_log(self):
        if not messagebox.askyesno(
            "Delete Audit Log",
            "Securely delete the audit log file?\n\nThis will erase all erasure records.",
        ):
            return
        self._log("Deleting audit log...", COLOR_WARNING)
        ok = delete_audit_log()
        if ok:
            self._log("✔ Audit log securely deleted.", COLOR_SAFE)
        else:
            self._log("⚠ Audit log not found or already deleted.", COLOR_DIM)

    def _start_erase(self):
        path = self._selected_path.get().strip()
        if not path:
            messagebox.showerror("No Target", "Please select a file or folder first.")
            return

        if not os.path.exists(path):
            messagebox.showerror("Not Found", f"Target does not exist:\n{path}")
            return

        is_dir = os.path.isdir(path)
        if is_dir and not self._recursive.get():
            if not messagebox.askyesno(
                "Folder Selected",
                "You selected a folder. Enable recursive deletion and erase all files inside?",
            ):
                return
            self._recursive.set(True)

        method = self._method.get()
        method_name = {
            "nist_clear": "NIST SP 800-88 CLEAR",
            "gutmann": "Gutmann 35-pass (LEGACY)",
            "dod3": "DoD 3-pass (DEPRECATED)",
            "dod7": "DoD 7-pass (DEPRECATED)",
        }.get(method, method)

        warning_extra = ""
        if method == "gutmann":
            warning_extra = "\n\n⚠ LEGACY METHOD: Not recommended for SSDs. Educational only."
        elif method in ("dod3", "dod7"):
            warning_extra = "\n\n⚠ DEPRECATED METHOD: Obsolete per NIST SP 800-88 Rev. 2."

        confirmed = messagebox.askyesno(
            "Confirm Secure Deletion",
            f"WARNING: This action is IRREVERSIBLE.\n\n"
            f"Target: {path}\n"
            f"Method: {method_name}\n"
            f"{warning_extra}\n\n"
            f"Are you absolutely sure?",
        )
        if not confirmed:
            self._log("Erasure cancelled by user.", COLOR_DIM)
            return

        self._stop_event.clear()
        self._is_erasing = True
        self._erase_btn.configure(state="disabled")
        self._abort_btn.configure(state="normal")
        self._progress_bar.set(0)
        self._progress_label.configure(text="Starting...")

        masked = _mask_filename(os.path.basename(path))
        self._log(f"Starting erasure: {masked} [{method_name}]", COLOR_WARNING)

        self._erase_thread = threading.Thread(
            target=self._run_erase,
            args=(path, method, is_dir or self._recursive.get()),
            daemon=True,
        )
        self._erase_thread.start()

    def _run_erase(self, path: str, method: str, is_dir: bool):
        def progress(pct: float, msg: str):
            self.after(0, lambda: self._update_progress(pct, msg))

        try:
            if is_dir:
                self._run_directory_erase(path, method, progress)
            else:
                result = self._run_file_erase(path, method, progress)
                self._log_file_result(result)
        except Exception as ex:
            err = str(ex)
            self.after(0, lambda e=err: self._log(f"✖ Error: {e}", COLOR_DANGER))
        finally:
            self.after(0, self._on_erase_complete)

    def _resolve_erase_params(self, method: str):
        if method == "gutmann":
            return "gutmann", 3
        if method == "dod7":
            return "dod", 7
        if method == "dod3":
            return "dod", 3
        return "nist_clear", 3

    def _log_file_result(self, result):
        status = result.get("status")
        masked = result.get("masked_name", "???")

        status_map = {
            "SUCCESS": (
                f"✔ {masked} — Securely erased.",
                COLOR_SAFE,
            ),
            "BLOCKED_BLACKLIST": (
                f"✖ {masked} — BLOCKED: Accidental deletion prevented (critical system path).",
                COLOR_DANGER,
            ),
            "ABORTED": (
                f"⚠ {masked} — Aborted by user.",
                COLOR_WARNING,
            ),
        }

        msg, color = status_map.get(
            status,
            (f"✖ {masked} — {status}", COLOR_DANGER),
        )
        self.after(0, lambda m=msg, c=color: self._log(m, c))

    def _run_directory_erase(self, path: str, method: str, progress):
        engine_method, passes = self._resolve_erase_params(method)
        results = erase_directory(
            path,
            method=engine_method,
            passes=passes,
            randomize_name=self._randomize.get(),
            progress_callback=progress,
            stop_event=self._stop_event,
        )

        success = sum(1 for r in results if r.get("status") == "SUCCESS")
        failed = len(results) - success
        msg = f"✔ Erased {success} files. {failed} failed."
        color = COLOR_SAFE if failed == 0 else COLOR_WARNING
        self.after(0, lambda m=msg, c=color: self._log(m, c))

    def _run_file_erase(self, path: str, method: str, progress):
        engine_method, passes = self._resolve_erase_params(method)

        if engine_method == "gutmann":
            return gutmann_35pass(path, self._randomize.get(), progress, self._stop_event)

        if engine_method == "nist_clear":
            return nist_clear(path, self._randomize.get(), progress, self._stop_event)

        return dod_overwrite(path, passes, self._randomize.get(), progress, self._stop_event)

    def _update_progress(self, pct: float, msg: str):
        self._progress_bar.set(pct)
        self._progress_label.configure(text=msg[:80])

    def _on_erase_complete(self):
        self._is_erasing = False
        self._erase_btn.configure(state="normal")
        self._abort_btn.configure(state="disabled")
        self._selected_path.set("")
        self._log(f"Audit log: ~/{AUDIT_LOG_FILE} (SHA-256 anonymized)", COLOR_INFO)

    def _abort_erase(self):
        if self._is_erasing:
            self._stop_event.set()
            self._log("⚠ Abort signal sent. Waiting for current pass to finish...", COLOR_WARNING)
            self._progress_label.configure(text="Aborting...")

    def _safe_exit(self):
        if self._is_erasing:
            confirm = messagebox.askyesno(
                "Erase In Progress",
                "An erasure operation is currently running.\n\n"
                "Exiting now may leave the target file in an intermediate state.\n\n"
                "Are you sure you want to exit?",
            )
            if not confirm:
                return
            self._stop_event.set()

        self.destroy()


def main():
    app = SDETApp()
    app.mainloop()


if __name__ == "__main__":
    main()
