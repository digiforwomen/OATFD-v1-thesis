# -*- coding: utf-8 -*-
r"""GUI explicit file picker + bundled LogFileParser64."""
import os, sys, subprocess, threading, webbrowser, tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
ENGINE = APP_DIR / "artifact_filepicker_lfp_engine.py"
VISUAL = APP_DIR / "visual_report_generator.py"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OATFD v1.0 - Thesis Edition")
        self.geometry("1250x880")
        self.case_var = tk.StringVar()
        self.mft_var = tk.StringVar()
        self.usn_var = tk.StringVar()
        self.prefetch_var = tk.StringVar()
        self.rawlog_var = tk.StringVar()
        self.logcsv_var = tk.StringVar()
        self.lnkw_var = tk.StringVar()
        self.lnko_var = tk.StringVar()
        self.i30_var = tk.StringVar()
        self.keyword_var = tk.StringVar()
        self.timezone_var = tk.StringVar(value="7.00")
        self.mftrecord_var = tk.StringVar(value="1024")
        self.all_files_var = tk.BooleanVar(value=True)
        self.force_usn_only_var = tk.BooleanVar(value=False)  # hidden/deprecated: auto mode only
        self.usn_profile_var = tk.StringVar(value="auto")      # hidden/deprecated: auto profile
        self.clear_unselected_var = tk.BooleanVar(value=False)
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
        self.row(top, "$UsnJrnl_$J raw / USN CSV", self.usn_var, 2, lambda: self.browse_file(self.usn_var))
        self.row(top, "Prefetch folder", self.prefetch_var, 3, lambda: self.browse_dir(self.prefetch_var))
        self.row(top, "raw $LogFile file", self.rawlog_var, 4, lambda: self.browse_file(self.rawlog_var))
        self.row(top, "$LogFile CSV / LogFileJoined / NLT_LogFile", self.logcsv_var, 5, lambda: self.browse_csv(self.logcsv_var))
        self.row(top, "LNK WindowsRecent folder", self.lnkw_var, 6, lambda: self.browse_dir(self.lnkw_var))
        self.row(top, "LNK OfficeRecent folder", self.lnko_var, 7, lambda: self.browse_dir(self.lnko_var))
        self.row(top, "$I30 CSV / i30_all_physical.csv", self.i30_var, 8, lambda: self.browse_csv(self.i30_var))
        self.row(top, "Target Path Keyword", self.keyword_var, 9, None)

        params = tk.Frame(self)
        params.pack(fill="x", padx=10)
        tk.Label(params, text="LogFileParser TimeZone").pack(side="left", padx=5)
        tk.Entry(params, textvariable=self.timezone_var, width=8).pack(side="left", padx=5)
        tk.Label(params, text="MFT Record Size").pack(side="left", padx=5)
        tk.Entry(params, textvariable=self.mftrecord_var, width=8).pack(side="left", padx=5)
        tk.Checkbutton(params, text="Scan all active files from MFT (--all-files, universal target mode)", variable=self.all_files_var).pack(side="left", padx=15)
        tk.Checkbutton(params, text="Clean unselected stale CSV (manual only)", variable=self.clear_unselected_var).pack(side="left", padx=8)

        b1 = tk.Frame(self)
        b1.pack(fill="x", padx=10, pady=5)
        self.btn(b1, "Auto Fill From Case", self.autofill, 20)
        self.btn(b1, "Clear Dataset", self.clear_dataset, 14)
        self.btn(b1, "Status", lambda: self.action("status"), 10)
        self.btn(b1, "Use Existing CSV", lambda: self.action("use-existing"), 16)
        self.btn(b1, "Parse $MFT", lambda: self.action("parse-mft"), 12)
        self.btn(b1, "Parse $UsnJrnl_$J", lambda: self.action("parse-usn"), 18)
        self.btn(b1, "Parse Prefetch", lambda: self.action("parse-prefetch"), 14)

        b2 = tk.Frame(self)
        b2.pack(fill="x", padx=10, pady=5)
        self.btn(b2, "Parse raw $LogFile", lambda: self.action("parse-raw-logfile"), 18)
        self.btn(b2, "Import $LogFile CSV", lambda: self.action("import-logfile"), 18)
        self.btn(b2, "Parse LNK", lambda: self.action("parse-lnk"), 12)
        self.btn(b2, "Parse All", lambda: self.action("parse-all"), 12)
        self.btn(b2, "Detect + Timeline", lambda: self.action("detect"), 18)
        self.btn(b2, "Generate Visual Report", self.generate_visual_report, 22)
        self.btn(b2, "Open Visual Report", self.open_visual_report, 18)
        self.btn(b2, "Open INPUT_PYTHON", self.open_input, 18)
        self.btn(b2, "Open Output", self.open_output, 14)
        tk.Button(b2, text="Clear Log", command=lambda: self.log.delete("1.0", tk.END), width=12).pack(side="left", padx=5)

        self.log = scrolledtext.ScrolledText(self, wrap=tk.WORD)
        self.log.pack(fill="both", expand=True, padx=10, pady=10)

        self.write("NTFS Artifact Parser LOWLEVEL + Full LogFileParser is ready.\n")
        self.write("This version can parse a raw $LogFile using the bundled TOOLS\\LogFileParser64.exe.\n")
        self.write("LNK parsing now uses the internal Python parser, not LECmd, to avoid sqlite3.exe popup windows.\n")
        self.write("SQLite database import for LogFileParser is disabled; the CSV output is used instead.\n")
        self.write("A sqlite3.exe stub and sqlite3.dll are included so LogFileParser does not show SQLite popups during raw $LogFile parsing.\n")
        self.write("Universal one-click workflow: select any available artifacts → Detect + Timeline → Generate Visual Report. If only one artifact is available, the application automatically analyzes that artifact only.\n")
        self.write("Thesis Rule v1.0 is active: strict path-aware USN/$LogFile matching, evidence-driven scoring, normal-operation grammar, $I30 directory-index support, archive/recycle/context guards, time-zone-safe reasoning, and raw-vs-unique reporting.\n")
        self.write("Universal target mode is active: the application does not block extensions such as .lnk, .pf, .e01, .csv, .exe, or .dll as targets.\n")
        self.write("Use Target Path Keyword to narrow the analysis to a folder or dataset when the case is large or mixed.\n\n")
        self.check_tools()

    def btn(self, parent, text, cmd, width):
        b = tk.Button(parent, text=text, command=cmd, width=width)
        b.pack(side="left", padx=5, pady=2)
        self.buttons.append(b)

    def check_tools(self):
        self.write("[BUNDLED TOOLS]\n")
        for name in ["MFTECmd.exe", "PECmd.exe", "LECmd.exe", "LogFileParser64.exe", "LogFileParser.exe"]:
            p = APP_DIR / "TOOLS" / name
            label = "[OK]" if p.exists() else ("[OPTIONAL]" if name == "sqlite3.exe" else "[MISS]")
            self.write(f"{label} {p}\n")
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
        roots = [case, case/"RAW_ARTIFACTS", case/"INPUT_PYTHON", case/"Parsed_CSV", case/"Parsed_CSV"/"LogFile"]
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
        usn = self.find_file(case, ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*", "usn_parsed.csv", "usn_parsed*.csv", "NLT_UsnJrnl*.csv", "*UsnJrnl*.csv", "*USN*.csv"])
        pf = self.find_dir(case, ["Prefetch"])
        rawlog = self.find_file(case, ["$LogFile", "LogFile"])
        logcsv = self.find_file(case, ["LogFileJoined.csv", "LogFile.csv", "logfile_parsed.csv", "logfile_parsed*.csv", "NLT_LogFile*.csv"])
        lnkw = self.find_dir(case, ["LNK_WindowsRecent", "WindowsRecent"])
        lnko = self.find_dir(case, ["LNK_OfficeRecent", "OfficeRecent"])
        i30 = self.find_file(case, ["i30_parsed.csv", "i30_all_physical.csv", "i30_all*.csv", "i30_percobaan*.csv", "*i30*.csv", "*I30*.csv"])
        # Penting untuk dataset Jung Oh: saat pindah dari folder multi-artefak ke folder USN-only,
        # field lama wajib dikosongkan. Kalau tidak, Detect akan mencampur artefak folder sebelumnya.
        self.mft_var.set(str(mft) if mft else "")
        self.usn_var.set(str(usn) if usn else "")
        self.prefetch_var.set(str(pf) if pf else "")
        self.rawlog_var.set(str(rawlog) if rawlog else "")
        self.logcsv_var.set(str(logcsv) if logcsv else "")
        self.lnkw_var.set(str(lnkw) if lnkw else "")
        self.lnko_var.set(str(lnko) if lnko else "")
        self.i30_var.set(str(i30) if i30 else "")
        self.write("[AUTO FILL]\n")
        for label, p in [("$MFT", mft), ("$UsnJrnl_$J / USN CSV", usn), ("Prefetch", pf), ("raw $LogFile", rawlog), ("$LogFile CSV", logcsv), ("LNK Windows", lnkw), ("LNK Office", lnko), ("$I30 CSV", i30)]:
            self.write(f"{'[FOUND]' if p else '[MISS]'} {label}: {p if p else ''}\n")
        self.write("\n")

    def clear_dataset(self):
        """Clear all dataset/path fields so user can switch case without restarting.
        This does not delete any evidence files from disk. It only resets UI inputs and log view.
        """
        for var in [self.case_var, self.mft_var, self.usn_var, self.prefetch_var, self.rawlog_var, self.logcsv_var, self.lnkw_var, self.lnko_var, self.i30_var, self.keyword_var]:
            var.set("")
        self.all_files_var.set(True)
        self.clear_unselected_var.set(False)
        self.force_usn_only_var.set(False)
        self.usn_profile_var.set("auto")
        self.log.delete("1.0", tk.END)
        self.write("[CLEAR] Dataset/input fields have been cleared. Select a new Case Folder, then click Auto Fill From Case or browse for artifacts manually.\n")
        self.write("[INFO] Clear Dataset does not delete artifact or output files on disk. Clean unselected stale CSV is disabled by default; enable it only if you want to remove older CSV files that were not manually selected.\n\n")
        self.check_tools()

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

        # v1.0: Universal One-Click Detect.
        # There is no Force USN-only UI anymore. Detect always sends whatever artifacts
        # are selected. If only one artifact exists, the engine analyzes that artifact only;
        # if multiple artifacts exist, it performs cross-artifact correlation where possible.
        cmd = [sys.executable, str(ENGINE), "--case", case]
        if self.mft_var.get().strip(): cmd += ["--mft-file", self.mft_var.get().strip()]
        if self.usn_var.get().strip(): cmd += ["--usn-file", self.usn_var.get().strip()]
        if self.prefetch_var.get().strip(): cmd += ["--prefetch-dir", self.prefetch_var.get().strip()]
        if self.rawlog_var.get().strip(): cmd += ["--raw-logfile-file", self.rawlog_var.get().strip()]
        if self.logcsv_var.get().strip(): cmd += ["--logfile-csv", self.logcsv_var.get().strip()]
        if self.lnkw_var.get().strip(): cmd += ["--lnk-windows-dir", self.lnkw_var.get().strip()]
        if self.lnko_var.get().strip(): cmd += ["--lnk-office-dir", self.lnko_var.get().strip()]
        if self.i30_var.get().strip(): cmd += ["--i30-csv", self.i30_var.get().strip()]
        cmd += ["--usn-profile", "auto"]

        if self.keyword_var.get().strip(): cmd += ["--target-path-keyword", self.keyword_var.get().strip()]
        if self.timezone_var.get().strip(): cmd += ["--timezone", self.timezone_var.get().strip()]
        if self.mftrecord_var.get().strip(): cmd += ["--mft-record-size", self.mftrecord_var.get().strip()]
        if self.clear_unselected_var.get() and act == "detect":
            cmd.append("--clear-unselected-inputs")
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
                if code == 0 and len(cmd) > 0 and cmd[-1] == "detect":
                    self.write("\n[INFO] Detection is complete. Click Generate Visual Report to create the visual dashboard.\n")
            except Exception as e:
                self.write(f"[EXCEPTION] {e}\n")
            finally:
                self.set_running(False)
        threading.Thread(target=worker, daemon=True).start()

    def generate_visual_report(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showwarning("Missing input", "Please fill in the Case Folder first.")
            return
        if not VISUAL.exists():
            messagebox.showerror("Error", f"Visual generator not found: {VISUAL}")
            return
        cmd = [sys.executable, str(VISUAL), "--case", case]
        self.run_cmd(cmd)

    def open_visual_report(self):
        case = self.case_var.get().strip()
        if not case:
            messagebox.showwarning("Missing input", "Please fill in the Case Folder first.")
            return
        p = Path(case) / "MINI_NLT_OUTPUT" / "visual_dashboard.html"
        if not p.exists():
            messagebox.showwarning("Visual report not available", "Click Generate Visual Report after running Detect + Timeline.")
            return

        # Hindari error Windows "This app can't run on your PC" jika asosiasi .html rusak.
        browsers = [
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Google" / "Chrome" / "Application" / "chrome.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        ]
        for b in browsers:
            if b.exists():
                subprocess.Popen([str(b), str(p)])
                self.write(f"[OPEN] Visual report opened in browser: {b}\n")
                return

        try:
            webbrowser.open(p.as_uri())
            self.write(f"[OPEN] Visual report: {p}\n")
        except Exception as e:
            self.write(f"[WARN] Could not open the HTML report automatically: {e}\n")
            self.write(f"[INFO] Open this file manually: {p}\n")
            os.startfile(str(p.parent))

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
        p = Path(case) / "MINI_NLT_OUTPUT"
        p.mkdir(parents=True, exist_ok=True)
        os.startfile(str(p))

if __name__ == "__main__":
    App().mainloop()
