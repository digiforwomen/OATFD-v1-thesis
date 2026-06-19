# -*- coding: utf-8 -*-
r"""
Explicit artifact parser engine.

Memakai input file/folder eksplisit:
- --mft-file
- --usn-file
- --prefetch-dir
- --lnk-windows-dir
- --lnk-office-dir
- --logfile-csv

Tujuan: menghindari masalah folder picker yang tidak menampilkan file $MFT/$UsnJrnl_$J/$LogFile.
"""

from __future__ import annotations
import argparse, csv, re, shutil, subprocess, sys
from datetime import datetime
from pathlib import Path

try:
    csv.field_size_limit(2**31 - 1)
except OverflowError:
    csv.field_size_limit(10**8)

APP_DIR = Path(__file__).resolve().parent
TOOLS_DIR = APP_DIR / "TOOLS"
MFTECMD = TOOLS_DIR / "MFTECmd.exe"
PECMD = TOOLS_DIR / "PECmd.exe"
LECMD = TOOLS_DIR / "LECmd.exe"
MINI_NLT = APP_DIR / "mini_nlt_prototype.py"

def log(x): print(x, flush=True)
def ensure(p: Path): p.mkdir(parents=True, exist_ok=True)
def case_dirs(case: Path):
    for d in ["Parsed_CSV/MFT", "Parsed_CSV/USN", "Parsed_CSV/Prefetch", "Parsed_CSV/LNK", "Parsed_CSV/LogFile", "INPUT_PYTHON", "OATFD_OUTPUT"]:
        ensure(case / d)

def run(args):
    log("[CMD] " + " ".join(f'"{a}"' if " " in str(a) else str(a) for a in args))
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    except OSError as e:
        log(f"[WARN] The external parser could not be executed: {e}")
        return 999
    if p.stdout:
        print(p.stdout, end="", flush=True)
    log(f"[EXIT] {p.returncode}")
    return p.returncode

def copy_file(src: Path, dst: Path) -> bool:
    if not src.exists():
        log(f"[MISS] {src}")
        return False
    ensure(dst.parent)
    shutil.copy2(src, dst)
    log(f"[COPY] {src} -> {dst}")
    return True

def find_file(case: Path, names):
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

def find_dir(case: Path, names):
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

def parse_mft(case: Path, mft_file: str=""):
    case_dirs(case)
    src = Path(mft_file) if mft_file else find_file(case, ["$MFT", "MFT"])
    if not src or not src.exists():
        log("[ERROR] $MFT file not found. Please select the $MFT file explicitly.")
        return False
    if not MFTECMD.exists():
        log(f"[ERROR] MFTECmd.exe is missing: {MFTECMD}")
        return False
    out = case/"Parsed_CSV"/"MFT"
    rc = run([str(MFTECMD), "-f", str(src), "--csv", str(out), "--csvf", "mft_parsed.csv"])
    return rc == 0 and copy_file(out/"mft_parsed.csv", case/"INPUT_PYTHON"/"mft_parsed.csv")

def parse_usn(case: Path, usn_file: str=""):
    case_dirs(case)
    src = Path(usn_file) if usn_file else find_file(case, ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin"])
    if not src or not src.exists():
        log("[ERROR] $UsnJrnl_$J file not found. Please select the $UsnJrnl_$J file explicitly.")
        return False
    if not MFTECMD.exists():
        log(f"[ERROR] MFTECmd.exe is missing: {MFTECMD}")
        return False
    out = case/"Parsed_CSV"/"USN"
    rc = run([str(MFTECMD), "-f", str(src), "--csv", str(out), "--csvf", "usn_parsed.csv"])
    return rc == 0 and copy_file(out/"usn_parsed.csv", case/"INPUT_PYTHON"/"usn_parsed.csv")

def parse_prefetch(case: Path, prefetch_dir: str=""):
    case_dirs(case)
    src = Path(prefetch_dir) if prefetch_dir else find_dir(case, ["Prefetch"])
    if not src or not src.exists() or not src.is_dir():
        log("[ERROR] Prefetch folder not found. Please select the Prefetch folder explicitly.")
        return False
    if not PECMD.exists():
        log(f"[ERROR] PECmd.exe is missing: {PECMD}")
        return False
    out = case/"Parsed_CSV"/"Prefetch"
    rc = run([str(PECMD), "-d", str(src), "--csv", str(out), "--csvf", "prefetch_all_parsed.csv"])
    return rc == 0 and copy_file(out/"prefetch_all_parsed.csv", case/"INPUT_PYTHON"/"prefetch_all_parsed.csv")

def parse_lnk(case: Path, win_dir: str="", office_dir: str=""):
    case_dirs(case)
    if not LECMD.exists():
        log(f"[ERROR] LECmd.exe is missing: {LECMD}")
        return False
    out = case/"Parsed_CSV"/"LNK"
    ok = False
    w = Path(win_dir) if win_dir else find_dir(case, ["LNK_WindowsRecent", "WindowsRecent"])
    o = Path(office_dir) if office_dir else find_dir(case, ["LNK_OfficeRecent", "OfficeRecent"])
    if w and w.exists():
        rc = run([str(LECMD), "-d", str(w), "--csv", str(out), "--csvf", "lnk_windows_recent_parsed.csv"])
        if rc == 0:
            ok = copy_file(out/"lnk_windows_recent_parsed.csv", case/"INPUT_PYTHON"/"lnk_windows_recent_parsed.csv") or ok
    else:
        log("[SKIP] LNK_WindowsRecent folder was not selected or found.")
    if o and o.exists():
        rc = run([str(LECMD), "-d", str(o), "--csv", str(out), "--csvf", "lnk_office_recent_parsed.csv"])
        if rc == 0:
            ok = copy_file(out/"lnk_office_recent_parsed.csv", case/"INPUT_PYTHON"/"lnk_office_recent_parsed.csv") or ok
    else:
        log("[SKIP] LNK_OfficeRecent folder was not selected or found.")
    return ok

def read_csv_auto(path: Path):
    for enc in ["utf-8-sig", "utf-16", "utf-16le", "latin1"]:
        for sep in [",", "\t", ";"]:
            try:
                with path.open("r", encoding=enc, newline="") as f:
                    sample = f.read(12000); f.seek(0)
                    if sep != "," and sep not in sample: continue
                    r = csv.DictReader(f, delimiter=sep)
                    if not r.fieldnames or len(r.fieldnames) <= 1: continue
                    return [{str(k).strip().replace("\ufeff",""):("" if v is None else str(v).strip()) for k,v in row.items() if k is not None} for row in r]
            except Exception:
                pass
    raise RuntimeError(f"Gagal membaca CSV {path}")

def parse_dt_any(x):
    t = str(x or "").strip()
    if not t: return ""
    m = re.search(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?", t)
    if m: return f"{m.group(1)} {m.group(2)}"
    m = re.search(r"(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2})(\s*[AP]M)?", t, re.I)
    if m:
        raw = (m.group(1)+" "+m.group(2)+(m.group(3) or "")).strip()
        for fmt in ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S"]:
            try: return datetime.strptime(raw, fmt).isoformat(sep=" ")
            except Exception: pass
    return ""

def import_logfile(case: Path, logfile_csv: str=""):
    case_dirs(case)
    src = Path(logfile_csv) if logfile_csv else find_file(case, ["logfile_parsed.csv", "NLT_LogFile*.csv", "LogFileJoined.csv", "LogFile.csv"])
    if not src or not src.exists():
        log("[ERROR] No $LogFile CSV has been selected. Please choose logfile_parsed.csv / NLT_LogFile / LogFileJoined / LogFile.csv.")
        return False
    rows = read_csv_auto(src)
    out_rows = []
    time_cols = ["EventTime(UTC+7)", "EventTime", "Time", "TimeStamp", "Timestamp", "EventTimeUTC", "CurrentTime", "CreateTime", "ModifiedTime", "ModifiedTIme", "MFT_ModifiedTime", "AccessTime"]
    event_cols = ["Event", "Operation", "RedoOperation", "Redo", "Description", "Detail", "Type"]
    name_cols = ["FileName", "Filename", "Name", "FullPath", "Path", "TargetName"]
    for r in rows:
        et = ""
        for c in time_cols:
            if c in r:
                et = parse_dt_any(r.get(c, ""))
                if et: break
        if not et:
            for v in r.values():
                et = parse_dt_any(v)
                if et: break
        event = next((r.get(c, "").strip() for c in event_cols if r.get(c, "").strip()), "LogFileEvent")
        target = next((r.get(c, "").strip() for c in name_cols if r.get(c, "").strip()), "")
        detail = " | ".join(f"{k}={v}" for k,v in r.items() if v)
        if len(detail) > 3000: detail = detail[:3000] + "..."
        out_rows.append({"EventTime(UTC+7)":et, "Event":event, "Detail":detail, "Source":f"normalized:{src.name}", "TargetName":target})
    dst = case/"INPUT_PYTHON"/"logfile_parsed.csv"
    ensure(dst.parent)
    with dst.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["EventTime(UTC+7)", "Event", "Detail", "Source", "TargetName"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(out_rows)
    copy_file(src, case/"Parsed_CSV"/"LogFile"/src.name)
    log(f"[NORMALIZE] {src} -> {dst} ({len(out_rows)} rows)")
    return True

def use_existing(case: Path):
    case_dirs(case)
    mapping = {
        "mft_parsed.csv": ["mft_parsed.csv", "mft_parsed*.csv"],
        "usn_parsed.csv": ["usn_parsed.csv", "usn_parsed*.csv"],
        "prefetch_all_parsed.csv": ["prefetch_all_parsed.csv", "prefetch_all_parsed*.csv"],
        "lnk_windows_recent_parsed.csv": ["lnk_windows_recent_parsed.csv", "lnk_windows_recent_parsed*.csv"],
        "lnk_office_recent_parsed.csv": ["lnk_office_recent_parsed.csv", "lnk_office_recent_parsed*.csv"],
        "i30_parsed.csv": ["i30_parsed.csv", "i30_all_physical.csv", "i30_all*.csv", "*i30*.csv", "*I30*.csv"],
    }
    ok = False
    for dest, pats in mapping.items():
        found = None
        for pat in pats:
            for root in [case/"INPUT_PYTHON", case/"Parsed_CSV", case]:
                if root.exists():
                    matches = [p for p in root.rglob(pat) if p.is_file() and p != case/"INPUT_PYTHON"/dest]
                    if matches:
                        matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                        found = matches[0]; break
            if found: break
        if found:
            ok = copy_file(found, case/"INPUT_PYTHON"/dest) or ok
        else:
            log(f"[MISS] {dest}")
    # logfile needs normalization
    logc = find_file(case, ["logfile_parsed.csv", "logfile_parsed*.csv", "NLT_LogFile*.csv", "LogFileJoined.csv", "LogFile.csv"])
    if logc and logc != case/"INPUT_PYTHON"/"logfile_parsed.csv":
        ok = import_logfile(case, str(logc)) or ok
    elif (case/"INPUT_PYTHON"/"logfile_parsed.csv").exists():
        ok = True
    else:
        ensure((case/"INPUT_PYTHON").parent)
        log("[MISS] logfile_parsed.csv")
    return ok

def empty_log(case):
    p = case/"INPUT_PYTHON"/"logfile_parsed.csv"
    if not p.exists():
        ensure(p.parent)
        with p.open("w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerow(["EventTime(UTC+7)", "Event", "Detail", "Source", "TargetName"])
        log(f"[PLACEHOLDER] {p}")


def write_placeholder_csv(path: Path, header):
    if not path.exists():
        ensure(path.parent)
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerow(header)
        log(f"[PLACEHOLDER] {path}")

def empty_mft(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"mft_parsed.csv", ["EntryNumber","SequenceNumber","InUse","IsDirectory","IsAds","FileName","Extension","ParentPath","Created0x10","LastModified0x10","LastAccess0x10","LastRecordChange0x10","Created0x30","LastModified0x30","LastAccess0x30","LastRecordChange0x30","SI<FN","uSecZeros","LogfileSequenceNumber"])

def empty_usn(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"usn_parsed.csv", ["UpdateTimestamp","Name","FullPath","ParentPath","UpdateReasons","SourceInfo","FileAttribute","USN","FileReferenceNumber","ParentFileReferenceNumber"])

def empty_prefetch(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"prefetch_all_parsed.csv", ["SourceFilename","ExecutableName","RunCount","LastRun","PreviousRun0","PreviousRun1","PreviousRun2"])

def detect(case: Path, all_files=True, keyword="", mft_file="", usn_file="", prefetch_dir="", raw_logfile_file="", logfile_csv="", win_dir="", office_dir=""):
    case_dirs(case)
    if not (case/"INPUT_PYTHON"/"mft_parsed.csv").exists(): empty_mft(case)
    if not (case/"INPUT_PYTHON"/"usn_parsed.csv").exists(): empty_usn(case)
    if not (case/"INPUT_PYTHON"/"prefetch_all_parsed.csv").exists(): empty_prefetch(case)
    if not (case/"INPUT_PYTHON"/"i30_parsed.csv").exists():
        write_placeholder_csv(case/"INPUT_PYTHON"/"i30_parsed.csv", ["record_type","parent_path","parent_mft_ref","parent_sequence","file_name","attributes","child_mft_ref","child_sequence","logical_size","allocated_size","i30_created_utc","i30_modified_utc","i30_accessed_utc","i30_changed_utc"])
    log("[INFO] Artifact-flexible detect: missing artifacts are unavailable evidence, not fatal errors.")
    empty_log(case)
    if not MINI_NLT.exists():
        log(f"[ERROR] mini_nlt_prototype.py is missing: {MINI_NLT}")
        return False
    cmd = [sys.executable, str(MINI_NLT), "--input", str(case/"INPUT_PYTHON"), "--detect-only"]
    if all_files: cmd.append("--all-files")
    if keyword: cmd += ["--target-path-keyword", keyword]
    cmd += ["--tool-roots", str(TOOLS_DIR)]
    return run(cmd) == 0

def status(case: Path, mft_file="", usn_file="", prefetch_dir="", log_csv="", win_dir="", office_dir=""):
    case_dirs(case)
    pairs = [
        ("$MFT raw", Path(mft_file) if mft_file else find_file(case, ["$MFT", "MFT"])),
        ("$UsnJrnl_$J raw", Path(usn_file) if usn_file else find_file(case, ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin"])),
        ("Prefetch folder", Path(prefetch_dir) if prefetch_dir else find_dir(case, ["Prefetch"])),
        ("$LogFile CSV", Path(log_csv) if log_csv else find_file(case, ["logfile_parsed.csv", "NLT_LogFile*.csv", "LogFileJoined.csv", "LogFile.csv"])),
        ("LNK Windows folder", Path(win_dir) if win_dir else find_dir(case, ["LNK_WindowsRecent", "WindowsRecent"])),
        ("LNK Office folder", Path(office_dir) if office_dir else find_dir(case, ["LNK_OfficeRecent", "OfficeRecent"])),
        ("mft_parsed.csv", case/"INPUT_PYTHON"/"mft_parsed.csv"),
        ("usn_parsed.csv", case/"INPUT_PYTHON"/"usn_parsed.csv"),
        ("prefetch_all_parsed.csv", case/"INPUT_PYTHON"/"prefetch_all_parsed.csv"),
        ("logfile_parsed.csv", case/"INPUT_PYTHON"/"logfile_parsed.csv"),
        ("timeline_events.csv", case/"OATFD_OUTPUT"/"timeline_events.csv"),
        ("detection_matrix.csv", case/"OATFD_OUTPUT"/"detection_matrix.csv"),
    ]
    for label, p in pairs:
        exists = bool(p and p.exists())
        log(f"{'[FOUND]' if exists else '[MISS]'} {label}: {p if p else ''}")

def parse_all(case, mft="", usn="", pf="", logcsv="", win="", office="", all_files=True, keyword=""):
    parse_mft(case, mft)
    parse_usn(case, usn)
    parse_prefetch(case, pf)
    parse_lnk(case, win, office)
    if logcsv: import_logfile(case, logcsv)
    else: 
        try: import_logfile(case, "")
        except Exception: empty_log(case)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--mft-file", default="")
    ap.add_argument("--usn-file", default="")
    ap.add_argument("--prefetch-dir", default="")
    ap.add_argument("--lnk-windows-dir", default="")
    ap.add_argument("--lnk-office-dir", default="")
    ap.add_argument("--logfile-csv", default="")
    ap.add_argument("--target-path-keyword", default="")
    ap.add_argument("--all-files", action="store_true")
    ap.add_argument("action", choices=["status", "parse-mft", "parse-usn", "parse-prefetch", "parse-lnk", "import-logfile", "use-existing", "parse-all", "detect"])
    a = ap.parse_args()
    case = Path(a.case)
    if a.action == "status": status(case, a.mft_file, a.usn_file, a.prefetch_dir, a.logfile_csv, a.lnk_windows_dir, a.lnk_office_dir); return 0
    if a.action == "parse-mft": return 0 if parse_mft(case, a.mft_file) else 1
    if a.action == "parse-usn": return 0 if parse_usn(case, a.usn_file) else 1
    if a.action == "parse-prefetch": return 0 if parse_prefetch(case, a.prefetch_dir) else 1
    if a.action == "parse-lnk": return 0 if parse_lnk(case, a.lnk_windows_dir, a.lnk_office_dir) else 1
    if a.action == "import-logfile": return 0 if import_logfile(case, a.logfile_csv) else 1
    if a.action == "use-existing": return 0 if use_existing(case) else 1
    if a.action == "parse-all": parse_all(case, a.mft_file, a.usn_file, a.prefetch_dir, a.logfile_csv, a.lnk_windows_dir, a.lnk_office_dir, a.all_files, a.target_path_keyword); return 0
    if a.action == "detect": return 0 if detect(case, a.all_files, a.target_path_keyword, a.mft_file, a.usn_file, a.prefetch_dir, a.raw_logfile_file, a.logfile_csv, a.lnk_windows_dir, a.lnk_office_dir) else 1

if __name__ == "__main__":
    raise SystemExit(main())
