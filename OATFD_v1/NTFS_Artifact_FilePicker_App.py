# -*- coding: utf-8 -*-
r"""Explicit file-picker GUI for NTFS artifacts."""
import os, sys, subprocess, threading, tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from pathlib import Path
APP_DIR = Path(__file__).resolve().parent
ENGINE = APP_DIR / "artifact_filepicker_engine.py"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NTFS Artifact Parser - Explicit File Picker")
        self.geometry("1220x850")
        self.case_var = tk.StringVar()
        self.mft_var = tk.StringVar()
        self.usn_var = tk.StringVar()
        self.prefetch_var = tk.StringVar()
        self.logcsv_var = tk.StringVar()
        self.lnkw_var = tk.StringVar()
        self.lnko_var = tk.StringVar()
        self.keyword_var = tk.StringVar()
        self.all_files_var = tk.BooleanVar(value=True)
        self.running = False
        self.buttons = []
        self.build()

    def row(self, parent, label, var, r, browse=None):
        tk.Label(parent, text=label, anchor="w").grid(row=r, column=0, sticky="w", padx=8, pady=4)
        tk.Entry(parent, textvariable=var).grid(row=r, column=1, sticky="we", padx=8, pady=4)
        if browse:
            tk.Button(parent, text="Browse", command=browse).grid(row=r, column=2, padx=8, pady=4)

    def build(self):
        top = tk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)
        top.grid_columnconfigure(1, weight=1)

        self.row(top, "Case Folder", self.case_var, 0, self.browse_case)
        self.row(top, "$MFT file", self.mft_var, 1, lambda: self.browse_file(self.mft_var))
        self.row(top, "$UsnJrnl_$J file", self.usn_var, 2, lambda: self.browse_file(self.usn_var))
        self.row(top, "Prefetch folder", self.prefetch_var, 3, lambda: self.browse_dir(self.prefetch_var))
        self.row(top, "$LogFile CSV / NLT_LogFile / LogFileJoined", self.logcsv_var, 4, lambda: self.browse_csv(self.logcsv_var))
        self.row(top, "LNK WindowsRecent folder", self.lnkw_var, 5, lambda: self.browse_dir(self.lnkw_var))
        self.row(top, "LNK OfficeRecent folder", self.lnko_var, 6, lambda: self.browse_dir(self.lnko_var))
        self.row(top, "Target Path Keyword", self.keyword_var, 7, None)

        opt = tk.Frame(self)
        opt.pack(fill="x", padx=10)
        tk.Checkbutton(opt, text="Scan all files from MFT (--all-files)", variable=self.all_files_var).pack(side="left")

        b1 = tk.Frame(self)
        b1.pack(fill="x", padx=10, pady=5)
        self.btn(b1, "Auto Fill From Case Folder", self.autofill, 24)
        self.btn(b1, "Status", lambda: self.action("status"), 12)
        self.btn(b1, "Use Existing CSV", lambda: self.action("use-existing"), 16)
        self.btn(b1, "Parse $MFT", lambda: self.action("parse-mft"), 14)
        self.btn(b1, "Parse $UsnJrnl_$J", lambda: self.action("parse-usn"), 18)
        self.btn(b1, "Parse Prefetch", lambda: self.action("parse-prefetch"), 14)

        b2 = tk.Frame(self)
        b2.pack(fill="x", padx=10, pady=5)
        self.btn(b2, "Parse LNK", lambda: self.action("parse-lnk"), 12)
        self.btn(b2, "Import $LogFile CSV", lambda: self.action("import-logfile"), 18)
        self.btn(b2, "Parse All", lambda: self.action("parse-all"), 12)
        self.btn(b2, "Detect + Timeline", lambda: self.action("detect"), 18)
        self.btn(b2, "Open INPUT_PYTHON", self.open_input, 18)
        self.btn(b2, "Open Output", self.open_output, 14)
        tk.Button(b2, text="Clear Log", command=lambda: self.log.delete("1.0", tk.END), width=12).pack(side="left", padx=5)

        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.log.pack(fill="both", expand=True, padx=10, pady=10)
        self.write("NTFS Artifact Parser - explicit file picker is ready.\n")
        self.write("Select the Case Folder, then click Auto Fill From Case Folder. If some fields are still empty, choose the $MFT and $UsnJrnl_$J files manually.\n")
        self.write("The folder picker shows folders only, not files. this version provides dedicated Browse actions for the $MFT and $UsnJrnl_$J files.\n\n")
        self.check_tools()

    def btn(self, parent, text, cmd, width):
        b = tk.Button(parent, text=text, command=cmd, width=width)
        b.pack(side="left", padx=5, pady=2)
        self.buttons.append(b)

    def check_tools(self):
        self.write("[BUNDLED TOOLS]\n")
        for name in ["MFTECmd.exe", "PECmd.exe", "LECmd.exe"]:
            p = APP_DIR / "TOOLS" / name
            self.write(f"{'[OK]' if p.exists() else '[MISS]'} {p}\n")
        self.write("\n")

    def browse_case(self):
        p = filedialog.askdirectory()
        if p:
            self.case_var.set(p)
            self.autofill()

    def browse_file(self, var):
        p = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if p:
            var.set(p)

    def browse_csv(self, var):
        p = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if p:
            var.set(p)

    def browse_dir(self, var):
        p = filedialog.askdirectory()
        if p:
            var.set(p)

    def find_file(self, case, names):
        roots = [case, case/"RAW_ARTIFACTS", case/"INPUT_PYTHON", case/"Parsed_CSV"]
        for root in roots:
            if root.exists():
                for name in names:
                    p = root / name
                    if p.exists() and p.is_file():
                        return p
        for name in names:
            try:
                matches = [p for p in case.rglob(name) if p.is_file()]
                if matches:
                    matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                    return matches[0]
            except Exception:
                pass
        return None

    def find_dir(self, case, names):
        roots = [case, case/"RAW_ARTIFACTS", case/"Parsed_CSV"]
        for root in roots:
            if root.exists():
                for name in names:
                    p = root / name
                    if p.exists() and p.is_dir():
                        return p
        lname = {x.lower() for x in names}
        try:
            for p in case.rglob("*"):
                if p.is_dir() and p.name.lower() in lname:
                    return p
        except Exception:
            pass
        return None

    def autofill(self):
        case_s = self.case_var.get().strip()
        if not case_s:
            return
        case = Path(case_s)
        mft = self.find_file(case, ["$MFT", "MFT"])
        usn = self.find_file(case, ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin"])
        pf = self.find_dir(case, ["Prefetch"])
        logcsv = self.find_file(case, ["logfile_parsed.csv", "logfile_parsed*.csv", "NLT_LogFile*.csv", "LogFileJoined.csv", "LogFile.csv"])
        lnkw = self.find_dir(case, ["LNK_WindowsRecent", "WindowsRecent"])
        lnko = self.find_dir(case, ["LNK_OfficeRecent", "OfficeRecent"])
        if mft: self.mft_var.set(str(mft))
        if usn: self.usn_var.set(str(usn))
        if pf: self.prefetch_var.set(str(pf))
        if logcsv: self.logcsv_var.set(str(logcsv))
        if lnkw: self.lnkw_var.set(str(lnkw))
        if lnko: self.lnko_var.set(str(lnko))
        self.write("[AUTO FILL]\n")
        for label, p in [("$MFT", mft), ("$UsnJrnl_$J", usn), ("Prefetch", pf), ("$LogFile CSV", logcsv), ("LNK Windows", lnkw), ("LNK Office", lnko)]:
            self.write(f"{'[FOUND]' if p else '[MISS]'} {label}: {p if p else ''}\n")
        self.write("\n")

    def write(self, t):
        self.log.insert(tk.END, t)
        self.log.see(tk.END)
        self.update_idletasks()

    def set_running(self, v):
        self.running = v
        st = "disabled" if v else "normal"
        for b in self.buttons:
            b.config(state=st)

    def build_cmd(self, act):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showwarning("Missing input", "Please fill in the Case Folder first.")
            return None
        cmd = [sys.executable, str(ENGINE), "--case", case]
        if self.mft_var.get().strip(): cmd += ["--mft-file", self.mft_var.get().strip()]
        if self.usn_var.get().strip(): cmd += ["--usn-file", self.usn_var.get().strip()]
        if self.prefetch_var.get().strip(): cmd += ["--prefetch-dir", self.prefetch_var.get().strip()]
        if self.logcsv_var.get().strip(): cmd += ["--logfile-csv", self.logcsv_var.get().strip()]
        if self.lnkw_var.get().strip(): cmd += ["--lnk-windows-dir", self.lnkw_var.get().strip()]
        if self.lnko_var.get().strip(): cmd += ["--lnk-office-dir", self.lnko_var.get().strip()]
        if self.keyword_var.get().strip(): cmd += ["--target-path-keyword", self.keyword_var.get().strip()]
        if self.all_files_var.get(): cmd.append("--all-files")
        cmd.append(act)
        return cmd

    def action(self, act):
        cmd = self.build_cmd(act)
        if cmd:
            self.run_cmd(cmd)

    def run_cmd(self, cmd):
        if self.running:
            messagebox.showwarning("Still running", "A process is still running.")
            return
        self.set_running(True)
        self.write("[CMD] " + " ".join(f'"{c}"' if " " in c else c for c in cmd) + "\n\n")
        def worker():
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
                for line in p.stdout:
                    self.write(line)
                code = p.wait()
                self.write(f"\n[EXIT CODE] {code}\n")
                self.write("[DONE]\n" if code == 0 else "[ERROR]\n")
            except Exception as e:
                self.write(f"[EXCEPTION] {e}\n")
            finally:
                self.set_running(False)
        threading.Thread(target=worker, daemon=True).start()

    def open_input(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showwarning("Missing input", "Please fill in the Case Folder first.")
            return
        p = Path(case) / "INPUT_PYTHON"
        p.mkdir(parents=True, exist_ok=True)
        os.startfile(str(p))

    def open_output(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showwarning("Missing input", "Please fill in the Case Folder first.")
            return
        p = Path(case) / "OATFD_OUTPUT"
        p.mkdir(parents=True, exist_ok=True)
        os.startfile(str(p))

if __name__ == "__main__":
    App().mainloop()
