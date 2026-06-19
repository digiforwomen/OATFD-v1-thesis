# -*- coding: utf-8 -*-
r"""
Explicit artifact parser engine with bundled LogFileParser64.

Input eksplisit:
- --mft-file
- --usn-file
- --prefetch-dir
- --raw-logfile-file
- --logfile-csv
- --lnk-windows-dir
- --lnk-office-dir

Tombol penting:
- parse-raw-logfile : raw $LogFile -> LogFileParser64.exe -> LogFile.csv/LogFileJoined.csv -> INPUT_PYTHON\logfile_parsed.csv
"""

from __future__ import annotations
import argparse, csv, re, shutil, subprocess, sys, time, os, struct
from datetime import datetime, timedelta
from pathlib import Path

OATFD_BENCHMARK_MODE = os.environ.get("OATFD_BENCHMARK_MODE", "0").strip().lower() in {"1", "true", "yes", "on"}

try:
    csv.field_size_limit(2**31 - 1)
except OverflowError:
    csv.field_size_limit(10**8)

APP_DIR = Path(__file__).resolve().parent
TOOLS_DIR = APP_DIR / "TOOLS"

MFTECMD = TOOLS_DIR / "MFTECmd.exe"
PECMD = TOOLS_DIR / "PECmd.exe"
LECMD = TOOLS_DIR / "LECmd.exe"
LOGFILEPARSER64 = TOOLS_DIR / "LogFileParser64.exe"
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


def _path_has_space(p) -> bool:
    try:
        return " " in str(p)
    except Exception:
        return False


def _make_no_space_lfp_workdir() -> Path:
    """Create a temporary working folder with no spaces for LogFileParser.

    Some LogFileParser builds show a popup: "Detected whitespace in program path".
    To avoid this, OATFD runs LogFileParser from a no-space temp folder and, when
    needed, copies input/output working paths there as well.
    """
    candidates = []
    env_tmp = os.environ.get("TEMP") or os.environ.get("TMP")
    if env_tmp:
        candidates.append(Path(env_tmp) / "OATFDLFP")
    candidates.append(Path("C:/OATFDLFP"))
    candidates.append(Path.cwd() / "OATFDLFP")

    last_err = None
    for base in candidates:
        try:
            if " " in str(base):
                continue
            run_dir = base / ("run_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
            run_dir.mkdir(parents=True, exist_ok=True)
            return run_dir
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Could not create a no-space working folder for LogFileParser: {last_err}")


def _copy_lfp_runtime_to(dst_tools: Path):
    dst_tools.mkdir(parents=True, exist_ok=True)
    # Copy all tool files because LogFileParser may need dll/schema companions.
    for src in TOOLS_DIR.iterdir():
        try:
            if src.is_file():
                shutil.copy2(src, dst_tools / src.name)
        except Exception as e:
            log(f"[WARN] Could not copy LogFileParser runtime: {src} -> {dst_tools} ({e})")
    # Also provide app-level sqlite3.dll if available.
    for extra in [APP_DIR / "sqlite3.dll", TOOLS_DIR / "sqlite3.dll"]:
        try:
            if extra.exists():
                shutil.copy2(extra, dst_tools / extra.name)
        except Exception:
            pass


def run_lfp(args):
    import os
    env = os.environ.copy()
    exe_path = Path(str(args[0]))
    exe_dir = exe_path.parent if exe_path.parent.exists() else TOOLS_DIR
    # SQLite sengaja tidak dipakai. LogFileParser dijalankan dengan /SkipSqlite3:1
    # agar hanya menghasilkan CSV dan tidak mencoba import database.
    extra_paths = [
        str(exe_dir),
        str(exe_dir / "Lib"),
        str(exe_dir / "Lib" / "x86"),
        str(exe_dir / "Lib" / "x64"),
        str(TOOLS_DIR),
        str(APP_DIR),
    ]
    env["PATH"] = ";".join(extra_paths) + ";" + env.get("PATH", "")
    log("[CMD] " + " ".join(f'"{a}"' if " " in str(a) else str(a) for a in args))
    log("[CWD] " + str(exe_dir))
    if any(str(a).lower().startswith("/skipsqlite3") for a in args):
        log("[INFO] SQLite import is disabled; the application uses only the LogFileParser CSV output.")
        log("[INFO] A sqlite3.exe stub and sqlite3.dll are provided so LogFileParser does not show SQLite popups.")

    # Beberapa versi LogFileParser64 juga mencoba load sqlite3.dll sebelum menghormati /SkipSqlite3.
    # Karena itu sqlite3.dll disediakan di semua lokasi yang lazim dicari.
    dll_srcs = [
        exe_dir / "sqlite3.dll", exe_dir / "Lib" / "sqlite3.dll", exe_dir / "Lib" / "x64" / "sqlite3.dll", exe_dir / "Lib" / "x86" / "sqlite3.dll",
        TOOLS_DIR / "sqlite3.dll", TOOLS_DIR / "Lib" / "sqlite3.dll", TOOLS_DIR / "Lib" / "x64" / "sqlite3.dll", TOOLS_DIR / "Lib" / "x86" / "sqlite3.dll",
        APP_DIR / "sqlite3.dll",
    ]
    dll_existing = next((p for p in dll_srcs if p.exists()), None)
    if dll_existing:
        for dll_dst in dll_srcs[:4]:
            try:
                if not dll_dst.exists():
                    dll_dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(dll_existing, dll_dst)
            except Exception as e:
                log(f"[WARN] Could not prepare sqlite3.dll: {dll_dst} ({e})")

    # Beberapa versi LogFileParser64 tetap melakukan pengecekan file sqlite3.exe
    # meskipun /SkipSqlite3:1. Pastikan path yang dicari tersedia.
    for stub in [exe_dir / "Lib" / "x86" / "sqlite3.exe", exe_dir / "Lib" / "x64" / "sqlite3.exe", exe_dir / "Lib" / "sqlite3.exe", exe_dir / "sqlite3.exe"]:
        try:
            if not stub.exists():
                stub.parent.mkdir(parents=True, exist_ok=True)
                src = MFTECMD if MFTECMD.exists() else (LOGFILEPARSER64 if LOGFILEPARSER64.exists() else exe_path)
                shutil.copy2(src, stub)
        except Exception as e:
            log(f"[WARN] Could not prepare the sqlite3.exe stub: {stub} ({e})")

    # no-freeze guard: LogFileParser can hang on some raw $LogFile inputs.
    timeout_sec = int(os.environ.get("OATFD_LOGFILEPARSER_TIMEOUT", "60"))
    try:
        p = subprocess.run(args, cwd=str(exe_dir), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", timeout=timeout_sec)
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        if out:
            print(out, end="", flush=True)
        log(f"[TIMEOUT] LogFileParser was stopped after {timeout_sec} seconds to prevent the GUI from freezing. $LogFile will be treated as unavailable evidence; detection continues with the other artifacts.")
        return 124
    if p.stdout:
        print(p.stdout, end="", flush=True)
    log(f"[EXIT] {p.returncode}")
    return p.returncode


def copy_file(src: Path, dst: Path) -> bool:
    if not src.exists():
        log(f"[MISS] {src}")
        return False
    ensure(dst.parent)

    # Jika sumber dan tujuan sama atau sumber sudah berada di folder tujuan LogFile,
    # jangan copy ulang. Ini menghindari PermissionError saat LogFileParser baru selesai
    # menulis file dan Windows masih menahan handle file sebentar.
    try:
        if src.resolve() == dst.resolve():
            log(f"[SKIP COPY] source sama dengan destination: {src}")
            return True
    except Exception:
        pass

    last = None
    for i in range(10):
        try:
            shutil.copy2(src, dst)
            log(f"[COPY] {src} -> {dst}")
            return True
        except PermissionError as e:
            last = e
            log(f"[WAIT] File still in use by another process, retry {i+1}/10: {src}")
            time.sleep(0.75)
        except OSError as e:
            last = e
            log(f"[WARN] Copy failed: {e}")
            time.sleep(0.5)

    log(f"[WARN] Copy was skipped because the file is still locked: {src} -> {dst}. Detail: {last}")
    return False

def find_file(case: Path, names):
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


def count_csv_rows(path: Path) -> int:
    """Return number of data rows in a CSV, safely. Used to choose between MFTECmd and internal USN parser."""
    try:
        if not path or not path.exists():
            return 0
        with path.open("r", encoding="utf-8-sig", errors="ignore", newline="") as f:
            # subtract header when present
            n = sum(1 for _ in f)
        return max(0, n - 1)
    except Exception:
        return 0

def remove_if_exists(path: Path):
    try:
        if path.exists() and path.is_file():
            path.unlink()
            log(f"[CLEAN] {path}")
    except Exception as e:
        log(f"[WARN] Gagal membersihkan {path}: {e}")


# ============================================================
# OATFD v1.0 Universal fallback: never produce silent empty output
# ============================================================
def _csv_rows_stream(path: Path, max_rows: int = 200000):
    if not path or not path.exists() or count_csv_rows(path) <= 0:
        return
    try:
        with path.open('r', encoding='utf-8-sig', errors='ignore', newline='') as f:
            reader = csv.DictReader(f)
            for i, r in enumerate(reader):
                if max_rows and i >= max_rows:
                    break
                yield r
    except Exception as e:
        log(f"[WARN] Could not read fallback CSV {path}: {e}")
        return


def _first_nonempty(*vals):
    for v in vals:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return ''


def _fallback_name(row: dict, source: str, idx: int) -> str:
    keys = [
        'FileName','Name','File/Directory Name','TargetName','ExecutableName','SourceFilename','SourceFile',
        'FullPath','Path','FilePath','TargetPath','LocalPath','ParentPath','Detail','Event','Operation','RedoOperation','UndoOperation'
    ]
    val = _first_nonempty(*(row.get(k,'') for k in keys))
    if val:
        val = val.replace('/', '\\')
        base = Path(val).name
        return base or val[:120]
    return f'{source}_row_{idx:06d}'


def _fallback_path(row: dict) -> str:
    return _first_nonempty(row.get('FullPath',''), row.get('Path',''), row.get('FilePath',''), row.get('TargetPath',''), row.get('LocalPath',''), row.get('ParentPath',''))


def _fallback_reason_text(row: dict) -> str:
    pieces = []
    for k, v in row.items():
        sv = str(v).strip()
        if not sv:
            continue
        lk = k.lower()
        if any(x in lk for x in ['reason','event','operation','timestamp','time','attribute','detail','source','path','name']):
            pieces.append(f'{k}={sv}')
        if len(' | '.join(pieces)) > 900:
            break
    return ' | '.join(pieces)[:1200]


def _fallback_is_known_timestamp_tool(name: str, reason: str = '') -> bool:
    blob = (str(name) + ' ' + str(reason)).lower()
    needles = ['newfiletime', 'setmace', 'ntimestomp', 'timestomp', 'touch.exe']
    return any(n in blob for n in needles)


def _fallback_has_metadata_change(reason: str) -> bool:
    r = str(reason).lower()
    needles = [
        'basicinfochange', 'basic_info_changed', 'basic info changed', '$standard_information',
        'standard information', 'update resident', 'time reversal', 'timestamp', 'filetime',
        'mftmodified', 'creationtime', 'lastmodified', 'lastaccess'
    ]
    return any(n in r for n in needles)


def _fallback_has_normal_churn(name: str, path: str, reason: str) -> bool:
    blob = (str(name)+' '+str(path)+' '+str(reason)).lower()
    normal_tokens = [
        'cache', 'temp', '.tmp', '~$', 'prefetch', 'appdata\\local\\temp', 'filecoauth',
        'syncengine', 'cortana', 'tilemodelcache', 'visualstudio', '.ni.dll', '.aux',
        'chrome\\user data', 'edge\\user data', 'preferences', 'local state'
    ]
    return any(t in blob for t in normal_tokens)


def _reporting_name(row) -> str:
    return str(row.get('target_name') or row.get('TargetName') or row.get('file_name') or '').strip()


def _is_office_temp_or_placeholder_name(name: str) -> bool:
    n = str(name or '').strip().lower()
    return (
        n.startswith('~$')
        or (n.startswith(('~wrd', '~wrl')) and n.endswith('.tmp'))
        or (n.startswith('~') and n.endswith('.tmp'))
        or n.endswith('.xlsx~tmp')
        or '~rf' in n and n.endswith('.tmp')
        or n in {'new microsoft excel worksheet.xlsx', 'new microsoft word document.docx'}
        or n.startswith('new microsoft excel worksheet.xlsx~rf')
    )


def _is_support_report_name(name: str) -> bool:
    n = str(name or '').strip().lower()
    exact = {
        '00_log_timestomping_perfile.csv','00_log_timestomping_perfile.xlsx','00_daftar_file_mace.xlsx',
        'run_summary.csv','detection_matrix.csv','case_reasoning.csv','timeline_events.csv','visual_summary_table.csv',
        'suspicious_behavior_detection.csv','high_confidence_suspicious.csv','need_review_candidates.csv','comparison_ready_summary.csv',
        'ground_truth.csv','action_log.csv','file_times_snapshot.csv'
    }
    prefixes = ('visual_dashboard','nlt_suspicious_behavior_detection','nlt_usnjrnl','nlt_logfile','run_summary','detection_matrix','case_reasoning','timeline_events','visual_summary_table','suspicious_behavior_detection')
    return n in exact or any(n.startswith(p) for p in prefixes)


def _row_has_independent_tool_evidence(row) -> bool:
    blob = ' '.join(str(row.get(k,'')).lower() for k in [
        'target_name','TargetName','file_name','prefetch_best_candidate','PrefetchBestCandidate','prefetch_candidates',
        'reasons','Evidence','reasoning','prediction_type','PredictionType'
    ])
    # Prefer execution/prefetch/tool context. Do not let a benchmark label alone make the file high-confidence.
    tool = any(t in blob for t in ['ntimestomp','setmace','newfiletime','setfiletime','bulkfilechanger','timestomp'])
    execution_context = any(t in blob for t in ['.pf','prefetch','tool execution','known timestamp-manipulation tool execution','known timestamp tool near'])
    return tool and execution_context


def _logical_key(row) -> str:
    name = _reporting_name(row).lower()
    rel = str(row.get('relative_path') or row.get('RelativePath') or '').lower()
    mft = str(row.get('mft_entry') or row.get('MFTEntry') or '').strip()
    seq = str(row.get('mft_sequence') or row.get('MFTSequence') or '').strip()
    if mft or seq:
        return f'{name}|mft={mft}|seq={seq}'
    if rel:
        return f'{name}|path={rel}'
    return name


def _apply_strict_reporting_guards(rows):
    """Normalize predictions for thesis/reporting consistency.

    Core principle:
    - Suspicious High = high-confidence only.
    - Suspicious Medium = candidate, not final manipulation -> Need Review.
    - Office temp/support/report artifacts cannot remain high-confidence unless there is independent tool-execution evidence.
    """
    adjusted = []
    for r in rows:
        r = dict(r)
        name = _reporting_name(r)
        pred_key = 'prediction' if 'prediction' in r else ('Prediction' if 'Prediction' in r else 'prediction')
        ptype_key = 'prediction_type' if 'prediction_type' in r else ('PredictionType' if 'PredictionType' in r else 'prediction_type')
        score_key = 'score' if 'score' in r else ('Score' if 'Score' in r else 'score')
        pred = str(r.get(pred_key,'')).strip()
        guarded = _is_office_temp_or_placeholder_name(name) or _is_support_report_name(name)
        independent_tool = _row_has_independent_tool_evidence(r)
        if pred == 'Suspicious Medium':
            r[pred_key] = 'Need Review'
            r[ptype_key] = 'candidate_demoted_from_suspicious_medium_not_final_manipulation'
            try:
                r[score_key] = str(min(int(float(r.get(score_key, 0) or 0)), 5))
            except Exception:
                r[score_key] = '5'
            if 'reasons' in r:
                r['reasons'] = (str(r.get('reasons','')) + ' | Reporting guard: Suspicious Medium is candidate/Need Review, not final manipulation.').strip(' |')
        elif pred == 'Suspicious High' and guarded and not independent_tool:
            # Keep it visible but remove it from final manipulation count.
            r[pred_key] = 'Need Review'
            r[ptype_key] = 'context_guard_support_or_office_temp_candidate_not_final_manipulation'
            try:
                r[score_key] = str(min(int(float(r.get(score_key, 0) or 0)), 5))
            except Exception:
                r[score_key] = '5'
            if 'reasons' in r:
                r['reasons'] = (str(r.get('reasons','')) + f' | Reporting guard: {name} is support/report/Office temporary context without independent tool evidence.').strip(' |')
        adjusted.append(r)
    return adjusted


def postprocess_standard_reports(case: Path) -> None:
    """Ensure v1.0 reporting files exist even when full matrix engine succeeds."""
    out = case/'OATFD_OUTPUT'
    matrix_path = out/'detection_matrix.csv'
    if not matrix_path.exists() or count_csv_rows(matrix_path) <= 0:
        return
    rows = list(_csv_rows_stream(matrix_path, 1000000) or [])
    raw_rows = [dict(r) for r in rows]

    def w(path, data, fields):
        ensure(path.parent)
        with path.open('w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader(); writer.writerows(data)

    base_fields = ['scenario_id','target_name','prediction','prediction_type','score','reasons','relative_path','artifact_mode']
    raw_fields = list(raw_rows[0].keys()) if raw_rows else base_fields
    w(out/'raw_model_prediction.csv', raw_rows, raw_fields)
    rows = _apply_strict_reporting_guards(rows)
    full_fields = list(rows[0].keys()) if rows else base_fields

    # Rewrite the matrix too, so every downstream report uses the corrected labels.
    w(out/'detection_matrix.csv', rows, full_fields)
    w(out/'postprocessed_prediction.csv', rows, full_fields)

    high = [r for r in rows if str(r.get('prediction', r.get('Prediction',''))) == 'Suspicious High']
    need = [r for r in rows if str(r.get('prediction', r.get('Prediction',''))) == 'Need Review']
    normal = [r for r in rows if str(r.get('prediction', r.get('Prediction',''))) == 'Normal']
    excluded_n = sum(1 for r in rows if str(r.get('prediction', r.get('Prediction',''))) == 'Excluded')

    # User-facing suspicious files are strict high-confidence only.
    w(out/'high_confidence_suspicious.csv', high, full_fields)
    w(out/'suspicious_behavior_detection.csv', high, full_fields)
    w(out/'need_review_candidates.csv', need, full_fields)

    # Unique/logical counts for thesis reporting. Raw rows are useful for audit; unique targets are useful for evaluation.
    unique_total_keys = {_logical_key(r) for r in rows}
    unique_high_keys = {_logical_key(r) for r in high}
    unique_need_keys = {_logical_key(r) for r in need}
    unique_normal_keys = {_logical_key(r) for r in normal}
    unique_high_target_names = {str(_reporting_name(r)).lower() for r in high}

    unique_summary = [
        {'metric':'raw_rows_total','value':str(len(rows))},
        {'metric':'raw_high_confidence_rows','value':str(len(high))},
        {'metric':'raw_need_review_rows','value':str(len(need))},
        {'metric':'raw_normal_rows','value':str(len(normal))},
        {'metric':'unique_logical_total','value':str(len(unique_total_keys))},
        {'metric':'unique_high_confidence_logical','value':str(len(unique_high_keys))},
        {'metric':'unique_need_review_logical','value':str(len(unique_need_keys))},
        {'metric':'unique_normal_logical','value':str(len(unique_normal_keys))},
        {'metric':'unique_high_confidence_target_names','value':str(len(unique_high_target_names))},
    ]
    w(out/'unique_detection_summary.csv', unique_summary, ['metric','value'])

    summary = [
        {'field':'target_count','value':str(len(rows))},
        {'field':'high_confidence_suspicious','value':str(len(high))},
        {'field':'need_review_candidates','value':str(len(need))},
        {'field':'normal','value':str(len(normal))},
        {'field':'excluded','value':str(excluded_n)},
        {'field':'unique_logical_total','value':str(len(unique_total_keys))},
        {'field':'unique_high_confidence_logical','value':str(len(unique_high_keys))},
        {'field':'unique_high_confidence_target_names','value':str(len(unique_high_target_names))},
        {'field':'note','value':'OATFD v1.0: only Suspicious High is final high-confidence manipulation. Suspicious Medium and support/temp artifacts are Need Review/context, not final manipulation. Raw and unique counts are separated.'},
    ]
    w(out/'comparison_ready_summary.csv', summary, ['field','value'])

    run_summary = [
        {'field':'target_count','value':str(len(rows))},
        {'field':'manipulation_count','value':str(len(high))},
        {'field':'suspicious_count','value':str(len(high))},
        {'field':'need_review_count','value':str(len(need))},
        {'field':'normal_count','value':str(len(normal))},
        {'field':'excluded_count','value':str(excluded_n)},
        {'field':'unique_logical_total','value':str(len(unique_total_keys))},
        {'field':'unique_high_confidence_logical','value':str(len(unique_high_keys))},
        {'field':'unique_high_confidence_target_names','value':str(len(unique_high_target_names))},
        {'field':'algorithm','value':'OATFD v1.0 Thesis Edition Evidence-Driven Universal Artifact Mode + Behavior Alerts - strict high-confidence + unique reporting'},
        {'field':'note','value':'Dashboard manipulation = Suspicious High only. Need Review contains candidates and demoted medium/support/temp contexts. Use unique_detection_summary.csv for target-level reporting.'},
    ]
    w(out/'run_summary.csv', run_summary, ['field','value'])


def keyword_aliases(keyword: str):
    raw = str(keyword or '').strip()
    # v1.0: explicit all-scope keywords disable target filtering.
    # Use blank, *, ALL, ALL_FILES, FULL_SCOPE, VOLUME, or NO_FILTER to scan every MFT file in the selected inputs.
    if raw.lower() in {"*", "all", "all_files", "full_scope", "full-scope", "volume", "no_filter", "nofilter", "semua"}:
        return []
    if not raw:
        return []
    vals = []
    def add(x):
        x = re.sub(r"\s+", " ", str(x or '')).strip()
        if len(x) >= 3 and x.lower() not in [v.lower() for v in vals]:
            vals.append(x)
    add(raw)
    cleaned = raw
    for word in ["Thesis", "Experiment", "Eksperimen", "Percobaan Thesis", "Percobaan Eksperimen"]:
        cleaned = re.sub(rf"\b{re.escape(word)}\b", " ", cleaned, flags=re.IGNORECASE)
    add(cleaned)
    tokens = re.findall(r"[A-Za-z0-9_]+", raw)
    ordinals = {"pertama","kedua","ketiga","keempat","kelima","keenam","enam","ketujuh","tujuh","kedelapan","delapan","kesembilan","sembilan","kesepuluh","sepuluh"}
    low = [t.lower() for t in tokens]
    for i,t in enumerate(low):
        if t == "percobaan":
            for u in low[i+1:]:
                if u in ordinals or u.startswith("ke"):
                    add("Percobaan " + u.title())
                    break
    if len(tokens) >= 2:
        add(" ".join(tokens[-2:]))
    if len(tokens) >= 3:
        add(" ".join(tokens[-3:]))
    return vals

def keyword_matches(keyword: str, *texts) -> bool:
    aliases = keyword_aliases(keyword)
    if not aliases:
        return True
    blob = " ".join(str(x or '') for x in texts).lower().replace('/', '\\')
    if any(a.lower().replace('/', '\\') in blob for a in aliases):
        return True
    generic = {"thesis", "experiment", "eksperimen", "data", "case", "folder"}
    for a in aliases:
        toks = [t.lower() for t in re.findall(r"[A-Za-z0-9_]+", a) if t.lower() not in generic]
        if toks and len(toks) <= 4 and all(t in blob for t in toks):
            return True
    return False

def generic_artifact_fallback_detect(case: Path, keyword: str = '') -> bool:
    """Separated fallback context report when the full engine fails.

    v1.0 policy:
    - Fallback MUST NOT pretend to be official file-level detection.
    - Fallback MUST NOT write tool/PF/LNK/support rows as Suspicious High.
    - Official outputs are marked FULL_ENGINE_FAILED with zero final detections.
    - Context rows are exported separately as fallback_* files for analyst review.
    """
    case_dirs(case)
    inp = case/'INPUT_PYTHON'
    out = case/'OATFD_OUTPUT'
    ready = case/'OUTPUT_UNIVERSAL_FALLBACK'
    ensure(out); ensure(ready)

    sources = [
        ('MFT', inp/'mft_parsed.csv'),
        ('USN', inp/'usn_parsed.csv'),
        ('LogFile', inp/'logfile_parsed.csv'),
        ('Prefetch', inp/'prefetch_all_parsed.csv'),
        ('LNK-WindowsRecent', inp/'lnk_windows_recent_parsed.csv'),
        ('LNK-OfficeRecent', inp/'lnk_office_recent_parsed.csv'),
    ]
    nonempty = [(s,p,count_csv_rows(p)) for s,p in sources if p.exists() and count_csv_rows(p) > 0]
    log('[UNIVERSAL FALLBACK - SEPARATED] Non-empty artifacts: ' + (', '.join(f'{s}={n}' for s,p,n in nonempty) if nonempty else 'none'))

    fallback_rows, fallback_tools, fallback_need, fallback_timeline = [], [], [], []
    seen = set(); raw_rows = 0
    keyword_l = (keyword or '').lower().strip()

    for source, path, _n in nonempty:
        for i, r in enumerate(_csv_rows_stream(path, 200000), start=1):
            raw_rows += 1
            name = _fallback_name(r, source, i)
            fpath = _fallback_path(r)
            if keyword_l and not keyword_matches(keyword, name, fpath):
                continue
            key = (source, name.lower(), fpath.lower())
            if key in seen:
                continue
            seen.add(key)
            reason = _fallback_reason_text(r)
            is_tool = _fallback_is_known_timestamp_tool(name, reason)
            has_meta = _fallback_has_metadata_change(reason)
            normal_churn = _fallback_has_normal_churn(name, fpath, reason)

            if is_tool and source in ('Prefetch','USN','LNK-WindowsRecent','LNK-OfficeRecent'):
                fpred = 'Fallback Tool/Execution Context'
                ftype = 'fallback_tool_execution_context_not_official_detection'
                score = 10
                evidence = 'Known timestamp-manipulation tool execution/context evidence from ' + source
                caution = 'Context only: do not count as primary timestamp manipulation without MFT/USN/LogFile file-level linkage.'
            elif has_meta and not normal_churn:
                fpred = 'Fallback Need Review'
                ftype = 'fallback_single_artifact_metadata_change_candidate'
                score = 6
                evidence = 'Single-artifact metadata/timestamp-change indicator; needs MFT/LogFile/USN corroboration'
                caution = 'Single-artifact evidence: triage only, not final high-confidence detection.'
            elif is_tool:
                fpred = 'Fallback Tool-Related Context'
                ftype = 'fallback_timestamp_tool_related_context'
                score = 6
                evidence = 'Timestamp tool related file/context; not direct file-level manipulation proof in this artifact alone'
                caution = 'Tool presence/context only.'
            else:
                fpred = 'Fallback Normal/Unconfirmed Context'
                ftype = 'fallback_normal_or_unconfirmed_artifact_context'
                score = 0
                evidence = 'No high-confidence manipulation rule matched in available single/partial artifact'
                caution = 'No official detection result from fallback.'

            row = {
                'FallbackID': f'UF{len(fallback_rows)+1:06d}',
                'SourceArtifact': source,
                'TargetName': name,
                'RelativePath': fpath,
                'FallbackPrediction': fpred,
                'FallbackType': ftype,
                'Score': score,
                'Evidence': evidence + (' | ' + reason if reason else ''),
                'Caution': caution,
                'OfficialDetectionStatus': 'NOT_OFFICIAL_FALLBACK_ONLY',
            }
            fallback_rows.append(row)
            if fpred.startswith('Fallback Tool'):
                fallback_tools.append(row)
            if fpred == 'Fallback Need Review':
                fallback_need.append(row)
            tv = _first_nonempty(r.get('Timestamp',''), r.get('TimeStamp',''), r.get('TimeStamp(UTC+7)',''), r.get('EventTime(UTC+7)',''), r.get('SourceCreated',''), r.get('Created0x10',''))
            if tv:
                fallback_timeline.append({'Time': tv, 'TargetName': name, 'Event': source + ' fallback context', 'FallbackPrediction': fpred, 'Detail': row['Evidence'][:500]})

    def w(path, rows, fields):
        ensure(path.parent)
        with path.open('w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            writer.writeheader(); writer.writerows(rows)

    # Official output: explicit failed state, no fake Suspicious High.
    official_fields = [
        'scenario_id','target_name','relative_path','source_artifact','prediction','prediction_type','score','reasons','artifact_mode',
        'official_detection_status','target_role','target_role_reason','filename_bias_used','folder_label_used','dataset_label_bias_used','ground_truth_used_for_detection'
    ]
    w(out/'detection_matrix.csv', [], official_fields)
    w(out/'all_file_classification.csv', [], ['TargetName','RelativePath','Extension','Prediction','PredictionType','Score','EvidenceBasis','TargetRole','TargetRoleReason','OfficialDetectionStatus','FilenameBiasUsed','FolderLabelUsed','GroundTruthUsedForDetection'])
    w(out/'case_reasoning.csv', [{
        'target_name':'FULL_ENGINE_FAILED',
        'prediction':'No Official Detection Result',
        'prediction_type':'full_engine_failed_fallback_context_only',
        'score':'0',
        'reasoning':'Full cross-artifact engine failed or produced zero targets. Fallback context reports were generated separately and must not be counted as official timestamp manipulation detections.',
        'key_relative':'', 'key_mft':'', 'key_prefetch':''
    }], ['target_name','prediction','prediction_type','score','reasoning','key_relative','key_mft','key_prefetch'])
    w(out/'suspicious_behavior_detection.csv', [], ['Category','TargetName','Prediction','PredictionType','Score','Evidence','ToolAttributionLevel','Caution'])
    w(out/'high_confidence_suspicious.csv', [], official_fields)
    w(out/'high_risk_non_primary_artifacts.csv', [], ['TargetName','RelativePath','Extension','TargetRole','TargetRoleReason','Prediction','PredictionType','Score','EvidenceBasis','Reasoning'])
    w(out/'non_primary_artifact_anomalies.csv', [], ['TargetName','RelativePath','Extension','TargetRole','TargetRoleReason','Prediction','PredictionType','Score','EvidenceBasis','Reasoning'])
    w(out/'need_review_candidates.csv', [], official_fields)
    w(out/'timeline_events.csv', [], ['Time','TargetName','Event','Prediction','Detail'])

    fallback_fields = ['FallbackID','SourceArtifact','TargetName','RelativePath','FallbackPrediction','FallbackType','Score','Evidence','Caution','OfficialDetectionStatus']
    w(out/'fallback_detection_matrix.csv', fallback_rows, fallback_fields)
    w(out/'fallback_tool_context.csv', fallback_tools, fallback_fields)
    w(out/'fallback_need_review.csv', fallback_need, fallback_fields)
    w(out/'fallback_timeline_context.csv', fallback_timeline, ['Time','TargetName','Event','FallbackPrediction','Detail'])

    summary = [
        {'field':'target_count','value':'0'},
        {'field':'manipulation_count','value':'0'},
        {'field':'suspicious_count','value':'0'},
        {'field':'high_risk_non_primary_count','value':'0'},
        {'field':'need_review_count','value':'0'},
        {'field':'normal_count','value':'0'},
        {'field':'excluded_count','value':'0'},
        {'field':'raw_rows_considered','value':str(raw_rows)},
        {'field':'fallback_context_count','value':str(len(fallback_rows))},
        {'field':'fallback_tool_context_count','value':str(len(fallback_tools))},
        {'field':'fallback_need_review_count','value':str(len(fallback_need))},
        {'field':'artifact_mode','value':'Full engine failed - fallback context separated'},
        {'field':'rule_version','value':'OATFD_v1_0_causal_timeline_guard'},
        {'field':'official_detection_status','value':'FULL_ENGINE_FAILED'},
        {'field':'non_empty_artifacts','value':', '.join(f'{s}:{n}' for s,p,n in nonempty)},
        {'field':'note','value':'Official detection outputs are intentionally empty because the full MFT-centered engine did not complete. See fallback_detection_matrix.csv for context-only triage rows.'},
    ]
    w(out/'run_summary.csv', summary, ['field','value'])
    w(out/'comparison_ready_summary.csv', summary, ['field','value'])
    readme = """OATFD v1.0 Fallback Separation Policy

The full cross-artifact engine failed or produced zero official file-level targets.
Fallback outputs were generated ONLY as context/triage:

- fallback_detection_matrix.csv
- fallback_tool_context.csv
- fallback_need_review.csv
- fallback_timeline_context.csv

IMPORTANT:
Fallback evidence is not official high-confidence timestamp manipulation detection.
Tool execution, PF/LNK rows, and single-artifact metadata rows must not be counted as
Primary Manipulation or High-Risk Non-Primary Artifact unless the full MFT-centered
engine links MFT, USN, LogFile/LSN, and context evidence.

Official files such as high_confidence_suspicious.csv are intentionally empty in this mode.
Fix the input/engine issue and rerun for valid OATFD detection.
"""
    (out/'README_UNIVERSAL_FALLBACK.txt').write_text(readme, encoding='utf-8')
    for fn in ['run_summary.csv','comparison_ready_summary.csv','high_confidence_suspicious.csv','need_review_candidates.csv','suspicious_behavior_detection.csv','detection_matrix.csv','case_reasoning.csv','timeline_events.csv','README_UNIVERSAL_FALLBACK.txt','fallback_detection_matrix.csv','fallback_tool_context.csv','fallback_need_review.csv','fallback_timeline_context.csv']:
        try:
            shutil.copy2(out/fn, ready/fn)
        except Exception:
            pass
    log(f'[UNIVERSAL FALLBACK - SEPARATED] Full engine failed. Official detections=0. Fallback context rows={len(fallback_rows)}, tool_context={len(fallback_tools)}, fallback_need={len(fallback_need)}')
    log(f'[OUTPUT READY] Fallback context folder: {ready}')
    return True

def _write_usn_diag_outputs(out: Path, message: str):
    """Create minimal readable outputs when USN-only parsing yields no usable rows."""
    ensure(out)
    def write_csv(path, rows, fields):
        with path.open('w', encoding='utf-8-sig', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            w.writeheader(); w.writerows(rows)
    summary = [
        {'field':'target_count','value':'0'},
        {'field':'manipulation_count','value':'0'},
        {'field':'suspicious_count','value':'0'},
        {'field':'need_review_count','value':'0'},
        {'field':'normal_count','value':'0'},
        {'field':'excluded_count','value':'0'},
        {'field':'artifact_mode','value':'USN-only diagnostic'},
        {'field':'rule_version','value':'OATFD_v1_0_causal_timeline_guard_usn_only'},
        {'field':'note','value':message},
    ]
    write_csv(out/'run_summary.csv', summary, ['field','value'])
    write_csv(out/'detection_matrix.csv', [], ['scenario_id','target_name','prediction','prediction_type','score','reasons'])
    write_csv(out/'case_reasoning.csv', [], ['target_name','prediction','prediction_type','score','reasoning','key_relative','key_mft','key_prefetch'])
    write_csv(out/'suspicious_behavior_detection.csv', [], ['Category','TargetName','Prediction','PredictionType','Score','Evidence'])
    write_csv(out/'high_confidence_suspicious.csv', [], ['scenario_id','target_name','prediction','prediction_type','score','reasons'])
    write_csv(out/'need_review_candidates.csv', [], ['scenario_id','target_name','prediction','prediction_type','score','reasons'])
    write_csv(out/'timeline_events.csv', [], ['Time','TargetName','Event','Prediction','Detail'])
    write_csv(out/'comparison_ready_summary.csv', [{'field':'Diagnostic','value':message}], ['field','value'])


def parse_mft(case: Path, mft_file: str=""):
    case_dirs(case)
    src = Path(mft_file) if mft_file else find_file(case, ["$MFT", "MFT"])
    if not src or not src.exists():
        log("[MISS] $MFT file not found. MFT will be treated as unavailable evidence; the pipeline will continue.")
        empty_mft(case)
        return True
    if not MFTECMD.exists():
        log(f"[ERROR] MFTECmd.exe is missing: {MFTECMD}")
        return False
    out = case/"Parsed_CSV"/"MFT"
    rc = run([str(MFTECMD), "-f", str(src), "--csv", str(out), "--csvf", "mft_parsed.csv"])
    return rc == 0 and copy_file(out/"mft_parsed.csv", case/"INPUT_PYTHON"/"mft_parsed.csv")

def parse_usn(case: Path, usn_file: str=""):
    case_dirs(case)
    src = Path(usn_file) if usn_file else find_file(case, [
        "$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin",
        "*UsnJrnl*", "*USN*", "usn_parsed.csv", "usn_parsed*.csv", "NLT_UsnJrnl*.csv", "*UsnJrnl*.csv", "*USN*.csv"
    ])
    if not src or not src.exists():
        log("[MISS] $UsnJrnl_$J / USN CSV not found. USN will be treated as unavailable evidence; the pipeline will continue.")
        empty_usn(case)
        return True

    dest_usn_csv = case/"INPUT_PYTHON"/"usn_parsed.csv"
    # If user picks the already parsed INPUT_PYTHON/usn_parsed.csv, keep it. Do not delete the source.
    try:
        same_dest = src.resolve() == dest_usn_csv.resolve()
    except Exception:
        same_dest = False

    # If user picks an already parsed CSV, normalize/import it instead of sending it to raw parsers.
    if src.suffix.lower() == ".csv":
        if same_dest:
            log(f"[USN PARSER] Existing INPUT_PYTHON/usn_parsed.csv used directly ({count_csv_rows(dest_usn_csv)} rows).")
            return True
        # Overwrite prior USN CSV for this run only after ensuring source is different from destination.
        remove_if_exists(dest_usn_csv)
        return import_usn_csv(case, str(src))

    # Raw USN selected: overwrite prior parsed CSV for this run.
    remove_if_exists(dest_usn_csv)

    # Hybrid raw USN parsing strategy:
    # 1) Try MFTECmd first when available (best compatibility for real $UsnJrnl:$J exports).
    # 2) If MFTECmd fails or produces zero rows, fallback to internal parser.
    # This covers both the user's raw $UsnJrnl_$J and Jung Oh's $UsnJrnl_$J.bin datasets.
    out = case/"Parsed_CSV"/"USN"
    mfte_out = out/"usn_parsed.csv"
    if MFTECMD.exists():
        try:
            remove_if_exists(mfte_out)
            rc = run([str(MFTECMD), "-f", str(src), "--csv", str(out), "--csvf", "usn_parsed.csv"])
            rows = count_csv_rows(mfte_out)
            if rc == 0 and rows > 0:
                log(f"[USN PARSER] MFTECmd successfully parsed the raw USN ({rows} rows).")
                # v1.0: MFTECmd output already uses a usable USN schema (UpdateTimestamp, Name, UpdateReasons, etc.).
                # Do NOT re-normalize hundreds of thousands of rows here; that made the GUI look frozen.
                ok_copy = copy_file(mfte_out, case/"INPUT_PYTHON"/"usn_parsed.csv")
                if ok_copy:
                    log(f"[USN PARSER] Fast path: MFTECmd CSV used directly as INPUT_PYTHON/usn_parsed.csv ({rows} rows).")
                    return True
                log("[WARN] Fast copy of the MFTECmd USN CSV failed. Falling back to normalize/import.")
                return import_usn_csv(case, str(mfte_out))
            log(f"[WARN] MFTECmd did not produce usable USN rows (rc={rc}, rows={rows}). Falling back to the internal parser.")
        except Exception as e:
            log(f"[WARN] MFTECmd USN parse exception: {e}. Fallback internal parser.")
    else:
        log("[WARN] MFTECmd.exe was not found. Using the internal raw USN parser.")

    return parse_usn_raw_internal(case, str(src))

def parse_prefetch(case: Path, prefetch_dir: str=""):
    case_dirs(case)
    src = Path(prefetch_dir) if prefetch_dir else find_dir(case, ["Prefetch"])
    if not src or not src.exists() or not src.is_dir():
        log("[MISS] Prefetch folder not found. Prefetch will be treated as unavailable evidence; the pipeline will continue.")
        empty_prefetch(case)
        return True
    if not PECMD.exists():
        log(f"[ERROR] PECmd.exe is missing: {PECMD}")
        return False
    out = case/"Parsed_CSV"/"Prefetch"
    rc = run([str(PECMD), "-d", str(src), "--csv", str(out), "--csvf", "prefetch_all_parsed.csv"])
    if rc == 0 and (out/"prefetch_all_parsed.csv").exists():
        return copy_file(out/"prefetch_all_parsed.csv", case/"INPUT_PYTHON"/"prefetch_all_parsed.csv")
    log("[MISS] Prefetch CSV output is empty or missing. Prefetch will be treated as unavailable evidence; the pipeline will continue.")
    empty_prefetch(case)
    return True


def filetime_to_iso(v: int) -> str:
    try:
        if not v:
            return ""
        # FILETIME = 100ns since 1601-01-01 UTC
        return (datetime(1601, 1, 1) + timedelta(microseconds=v / 10)).strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        return ""

def read_cstring_ascii(data: bytes, off: int) -> str:
    if off <= 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end < 0:
        end = min(len(data), off + 4096)
    try:
        return data[off:end].decode("mbcs", errors="replace").strip()
    except Exception:
        return data[off:end].decode("latin1", errors="replace").strip()

def read_cstring_utf16(data: bytes, off: int) -> str:
    if off <= 0 or off >= len(data) - 1:
        return ""
    end = off
    max_end = min(len(data) - 1, off + 8192)
    while end < max_end:
        if data[end:end+2] == b"\x00\x00":
            break
        end += 2
    try:
        return data[off:end].decode("utf-16le", errors="replace").strip()
    except Exception:
        return ""

def parse_string_data(data: bytes, off: int, is_unicode: bool):
    if off + 2 > len(data):
        return "", off
    try:
        count = struct.unpack_from("<H", data, off)[0]
    except Exception:
        return "", off
    off += 2
    if count <= 0 or count > 32767:
        return "", off
    if is_unicode:
        size = count * 2
        raw = data[off:off+size]
        try:
            val = raw.decode("utf-16le", errors="replace")
        except Exception:
            val = ""
        off += size
    else:
        raw = data[off:off+count]
        try:
            val = raw.decode("mbcs", errors="replace")
        except Exception:
            val = raw.decode("latin1", errors="replace")
        off += count
    return val.strip("\x00").strip(), off

def extract_lnk_strings(data: bytes, limit: int = 80) -> str:
    strings = []

    # UTF-16LE printable strings
    try:
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data):
            try:
                s2 = m.group(0).decode("utf-16le", errors="ignore").strip("\x00").strip()
                if len(s2) >= 4:
                    strings.append(s2)
            except Exception:
                pass
    except Exception:
        pass

    # ASCII printable strings
    try:
        for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
            try:
                s2 = m.group(0).decode("latin1", errors="ignore").strip()
                if len(s2) >= 4:
                    strings.append(s2)
            except Exception:
                pass
    except Exception:
        pass

    # Deduplicate, keep order.
    out = []
    seen = set()
    for s2 in strings:
        key = s2.lower()
        if key not in seen:
            seen.add(key)
            out.append(s2)
        if len(out) >= limit:
            break
    return " | ".join(out)

def parse_lnk_file_internal(path: Path) -> dict:
    data = path.read_bytes()
    row = {
        "SourceFile": str(path),
        "SourceName": path.name,
        "Parser": "InternalPythonLnkParser",
        "HeaderCreated": "",
        "HeaderAccessed": "",
        "HeaderModified": "",
        "FileSize": "",
        "LocalBasePath": "",
        "CommonPathSuffix": "",
        "RelativePath": "",
        "WorkingDirectory": "",
        "Arguments": "",
        "IconLocation": "",
        "AllStrings": "",
        "ParseStatus": "OK",
    }

    try:
        if len(data) < 0x4C or data[:4] != b"\x4c\x00\x00\x00":
            row["ParseStatus"] = "NotLNKHeader"
            row["AllStrings"] = extract_lnk_strings(data)
            return row

        link_flags = struct.unpack_from("<I", data, 0x14)[0]
        row["HeaderCreated"] = filetime_to_iso(struct.unpack_from("<Q", data, 0x1C)[0])
        row["HeaderAccessed"] = filetime_to_iso(struct.unpack_from("<Q", data, 0x24)[0])
        row["HeaderModified"] = filetime_to_iso(struct.unpack_from("<Q", data, 0x2C)[0])
        row["FileSize"] = str(struct.unpack_from("<I", data, 0x34)[0])

        off = 0x4C

        # HasLinkTargetIDList
        if link_flags & 0x00000001:
            if off + 2 <= len(data):
                idlist_size = struct.unpack_from("<H", data, off)[0]
                off += 2 + idlist_size

        # HasLinkInfo
        if link_flags & 0x00000002 and off + 0x1C <= len(data):
            li_base = off
            li_size = struct.unpack_from("<I", data, li_base)[0]
            li_header_size = struct.unpack_from("<I", data, li_base + 4)[0]
            if li_size > 0 and li_base + li_size <= len(data):
                local_base_off = struct.unpack_from("<I", data, li_base + 16)[0]
                suffix_off = struct.unpack_from("<I", data, li_base + 24)[0]
                if local_base_off:
                    row["LocalBasePath"] = read_cstring_ascii(data, li_base + local_base_off)
                if suffix_off:
                    row["CommonPathSuffix"] = read_cstring_ascii(data, li_base + suffix_off)

                # Unicode offsets available if header size >= 0x24
                if li_header_size >= 0x24 and li_base + 36 <= len(data):
                    try:
                        local_base_u = struct.unpack_from("<I", data, li_base + 28)[0]
                        suffix_u = struct.unpack_from("<I", data, li_base + 32)[0]
                        if local_base_u:
                            val = read_cstring_utf16(data, li_base + local_base_u)
                            if val:
                                row["LocalBasePath"] = val
                        if suffix_u:
                            val = read_cstring_utf16(data, li_base + suffix_u)
                            if val:
                                row["CommonPathSuffix"] = val
                    except Exception:
                        pass
                off += li_size

        is_unicode = bool(link_flags & 0x00000080)

        # StringData fields
        fields = [
            (0x00000004, "NameString"),
            (0x00000008, "RelativePath"),
            (0x00000010, "WorkingDirectory"),
            (0x00000020, "Arguments"),
            (0x00000040, "IconLocation"),
        ]
        for flag, name in fields:
            if link_flags & flag:
                val, off = parse_string_data(data, off, is_unicode)
                row[name] = val

        row["AllStrings"] = extract_lnk_strings(data)
    except Exception as e:
        row["ParseStatus"] = "Error: " + str(e)
        row["AllStrings"] = extract_lnk_strings(data)

    return row

def parse_lnk_dir_internal(src_dir: Path, out_csv: Path, label: str) -> bool:
    ensure(out_csv.parent)
    files = [p for p in src_dir.rglob("*") if p.is_file() and p.suffix.lower() == ".lnk"]
    rows = []
    for p in files:
        try:
            r = parse_lnk_file_internal(p)
            r["SourceSet"] = label
            rows.append(r)
        except Exception as e:
            rows.append({
                "SourceFile": str(p),
                "SourceName": p.name,
                "SourceSet": label,
                "Parser": "InternalPythonLnkParser",
                "ParseStatus": "Error: " + str(e),
                "AllStrings": "",
            })

    fields = [
        "SourceSet", "SourceFile", "SourceName", "Parser", "ParseStatus",
        "HeaderCreated", "HeaderAccessed", "HeaderModified", "FileSize",
        "LocalBasePath", "CommonPathSuffix", "RelativePath", "WorkingDirectory",
        "Arguments", "IconLocation", "AllStrings"
    ]
    with out_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    log(f"[INTERNAL LNK] {label}: {len(rows)} .lnk diparse -> {out_csv}")
    return True

def parse_lnk(case: Path, win_dir: str="", office_dir: str=""):
    """
    Parse LNK tanpa LECmd agar tidak memunculkan popup sqlite3.exe dari dependency eksternal.
    Parser internal ini cukup untuk korelasi aplikasi:
    SourceFile, header timestamps, LocalBasePath, RelativePath, WorkingDirectory, Arguments, AllStrings.
    """
    case_dirs(case)
    out = case/"Parsed_CSV"/"LNK"
    ok = False
    w = Path(win_dir) if win_dir else find_dir(case, ["LNK_WindowsRecent", "WindowsRecent", "Recent Items", "Recent"])
    o = Path(office_dir) if office_dir else find_dir(case, ["LNK_OfficeRecent", "OfficeRecent"])

    if w and w.exists():
        out_csv = out/"lnk_windows_recent_parsed.csv"
        if parse_lnk_dir_internal(w, out_csv, "WindowsRecent"):
            ok = copy_file(out_csv, case/"INPUT_PYTHON"/"lnk_windows_recent_parsed.csv") or ok
    else:
        log("[SKIP] LNK_WindowsRecent/Recent folder was not selected or found.")

    if o and o.exists():
        out_csv = out/"lnk_office_recent_parsed.csv"
        if parse_lnk_dir_internal(o, out_csv, "OfficeRecent"):
            ok = copy_file(out_csv, case/"INPUT_PYTHON"/"lnk_office_recent_parsed.csv") or ok
    else:
        log("[SKIP] LNK_OfficeRecent folder was not selected or found.")

    return ok

def read_csv_auto(path: Path):
    last = None
    for attempt in range(10):
        for enc in ["utf-8-sig", "utf-16", "utf-16le", "latin1"]:
            for sep in [",", "|", "\t", ";"]:
                try:
                    with path.open("r", encoding=enc, newline="") as f:
                        sample = f.read(20000); f.seek(0)
                        if sep != "," and sep not in sample:
                            continue
                        r = csv.DictReader(f, delimiter=sep)
                        if not r.fieldnames or len(r.fieldnames) <= 1:
                            continue
                        return [{str(k).strip().replace("\ufeff",""):("" if v is None else str(v).strip()) for k,v in row.items() if k is not None} for row in r]
                except PermissionError as e:
                    last = e
                    log(f"[WAIT] CSV still in use by another process, retry {attempt+1}/10: {path}")
                    time.sleep(0.75)
                except Exception as e:
                    last = e
                    pass
        time.sleep(0.25)
    raise RuntimeError(f"Failed to read CSV {path}: {last}")

def parse_dt_any(x):
    t = str(x or "").strip()
    if not t:
        return ""
    m = re.search(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})([\.:]\d+)?", t)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    m = re.search(r"(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2})(\s*[AP]M)?", t, re.I)
    if m:
        raw = (m.group(1)+" "+m.group(2)+(m.group(3) or "")).strip()
        for fmt in ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S"]:
            try:
                return datetime.strptime(raw, fmt).isoformat(sep=" ")
            except Exception:
                pass
    return ""

def normalize_logfile_csv(src: Path, dst: Path):
    rows = read_csv_auto(src)
    out_rows = []
    time_cols = ["EventTime(UTC+7)", "EventTime", "Time", "TimeStamp", "Timestamp", "EventTimeUTC", "CurrentTime", "CreateTime", "ModifiedTime", "ModifiedTIme", "MFT_ModifiedTime", "AccessTime", "lf_LSN", "lf_CurrentLsn"]
    event_cols = ["Event", "Operation", "RedoOperation", "Redo", "Description", "Detail", "Type", "lf_RedoOperation", "lf_UndoOperation", "lf_CurrentAttribute", "lf_TextInformation"]
    name_cols = ["FileName", "Filename", "Name", "File/Directory Name", "File Directory Name", "TargetName", "lf_Filename", "FilenameResolved"]
    path_cols = ["FullPath", "Full Path", "Path", "FilePath", "TargetPath", "FullPathResolved"]

    lsn_cols = ["lf_LSN", "lf_CurrentLsn", "lf_CurrentLSN", "LSN", "CurrentLsn", "CurrentLSN", "LogFileSequenceNumber"]
    prev_lsn_cols = ["lf_PreviousLsn", "lf_PreviousLSN", "PreviousLsn", "PreviousLSN"]
    attr_cols = ["lf_CurrentAttribute", "CurrentAttribute", "Attribute", "AttributeName"]
    redo_cols = ["lf_RedoOperation", "RedoOperation", "Redo"]
    undo_cols = ["lf_UndoOperation", "UndoOperation", "Undo"]
    mft_ref_cols = ["lf_MFTReference", "lf_RealMFTReference", "MFTReference", "RealMFTReference", "FileReference"]

    def pick(row, cols):
        for c in cols:
            if c in row and str(row.get(c, "")).strip():
                return str(row.get(c, "")).strip()
        return ""

    for r in rows:
        et = ""
        for c in time_cols:
            if c in r:
                et = parse_dt_any(r.get(c, ""))
                if et:
                    break
        if not et:
            for v in r.values():
                et = parse_dt_any(v)
                if et:
                    break
        event = next((r.get(c, "").strip() for c in event_cols if r.get(c, "").strip()), "LogFileEvent")
        target = next((r.get(c, "").strip() for c in name_cols if r.get(c, "").strip()), "")
        full_path = next((r.get(c, "").strip() for c in path_cols if r.get(c, "").strip()), "")
        # Some normalized/legacy rows keep path/name only inside Detail. Recover them for target filtering.
        if not target:
            m_name = re.search(r"File/Directory Name=([^|]+)", " | ".join(f"{k}={v}" for k,v in r.items() if v), re.I)
            if m_name:
                target = m_name.group(1).strip().strip('"')
        if not full_path:
            m_path = re.search(r"Full Path=([^|]+)", " | ".join(f"{k}={v}" for k,v in r.items() if v), re.I)
            if m_path:
                full_path = m_path.group(1).strip().strip('"')
        target = target.replace(" <Guessed>", "").strip()
        detail = " | ".join(f"{k}={v}" for k,v in r.items() if v)
        if len(detail) > 6000:
            detail = detail[:6000] + "..."
        out_rows.append({
            "EventTime(UTC+7)": et,
            "Event": event,
            "Detail": detail,
            "Source": f"normalized:{src.name}",
            "TargetName": target,
            "FullPath": full_path,
            "Log_LSN": pick(r, lsn_cols),
            "Log_PreviousLSN": pick(r, prev_lsn_cols),
            "Log_CurrentAttribute": pick(r, attr_cols),
            "Log_RedoOperation": pick(r, redo_cols),
            "Log_UndoOperation": pick(r, undo_cols),
            "Log_MFTReference": pick(r, mft_ref_cols),
        })
    ensure(dst.parent)
    with dst.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["EventTime(UTC+7)", "Event", "Detail", "Source", "TargetName", "FullPath",
                  "Log_LSN", "Log_PreviousLSN", "Log_CurrentAttribute", "Log_RedoOperation", "Log_UndoOperation", "Log_MFTReference"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(out_rows)
    log(f"[NORMALIZE] {src} -> {dst} ({len(out_rows)} rows)")
    return True

def import_logfile_csv(case: Path, logfile_csv: str=""):
    case_dirs(case)
    src = Path(logfile_csv) if logfile_csv else find_file(case, ["LogFileJoined.csv", "LogFile.csv", "logfile_parsed.csv", "NLT_LogFile*.csv"])
    if not src or not src.exists():
        log("[ERROR] No $LogFile CSV has been selected. Please choose LogFileJoined.csv / LogFile.csv / logfile_parsed.csv / NLT_LogFile.")
        return False

    # Copy hanya arsip tambahan. Jika file masih locked, jangan gagalkan pipeline,
    # karena normalisasi bisa tetap membaca src setelah retry.
    dst_copy = case/"Parsed_CSV"/"LogFile"/src.name
    try:
        try:
            same = src.resolve() == dst_copy.resolve()
        except Exception:
            same = False
        if not same:
            copy_file(src, dst_copy)
        else:
            log(f"[SKIP COPY] LogFile CSV sudah berada di folder Parsed_CSV: {src}")
    except Exception as e:
        log(f"[WARN] Copy of the LogFile CSV was skipped: {e}")

    return normalize_logfile_csv(src, case/"INPUT_PYTHON"/"logfile_parsed.csv")

def parse_raw_logfile(case: Path, raw_logfile_file: str="", mft_csv: str="", timezone: str="7.00", mft_record_size: str="1024"):
    case_dirs(case)
    raw = Path(raw_logfile_file) if raw_logfile_file else find_file(case, ["$LogFile", "LogFile"])
    if not raw or not raw.exists():
        log("[ERROR] Raw $LogFile was not found. Please select the $LogFile file explicitly.")
        return False
    if not LOGFILEPARSER64.exists():
        log(f"[ERROR] LogFileParser64.exe is missing: {LOGFILEPARSER64}")
        return False

    out = case/"Parsed_CSV"/"LogFile"
    ensure(out)

    # Optional only if explicitly provided or already exists.
    mft_csv_path = Path(mft_csv) if mft_csv else case/"INPUT_PYTHON"/"mft_parsed.csv"

    # v1.0 whitespace-safe LogFileParser guard:
    # Some LogFileParser builds do not support whitespace in the executable/program path,
    # and may also fail when input/output arguments contain spaces. The user's case folder
    # often contains spaces (e.g., "Percobaan Thesis Ketujuh") and downloaded app folder may
    # contain "Package (1)". To make raw $LogFile parsing robust, run LogFileParser from a
    # no-space temp workdir and copy input/MFT CSV there if any relevant path has spaces.
    use_ws_safe = any(_path_has_space(p) for p in [LOGFILEPARSER64, raw, out, mft_csv_path if mft_csv_path.exists() else ""])

    exe = LOGFILEPARSER64
    raw_for_lfp = raw
    out_for_lfp = out
    mft_for_lfp = mft_csv_path if mft_csv_path.exists() else None
    temp_run_dir = None

    if use_ws_safe:
        try:
            temp_run_dir = _make_no_space_lfp_workdir()
            temp_tools = temp_run_dir / "TOOLS"
            temp_input = temp_run_dir / "IN"
            temp_out = temp_run_dir / "OUT"
            temp_input.mkdir(parents=True, exist_ok=True)
            temp_out.mkdir(parents=True, exist_ok=True)
            _copy_lfp_runtime_to(temp_tools)

            exe = temp_tools / "LogFileParser64.exe"
            raw_for_lfp = temp_input / "$LogFile"
            shutil.copy2(raw, raw_for_lfp)
            out_for_lfp = temp_out

            if mft_csv_path.exists():
                mft_for_lfp = temp_input / "mft.csv"
                shutil.copy2(mft_csv_path, mft_for_lfp)
            else:
                mft_for_lfp = None

            log("[WS-SAFE] LogFileParser is run from a no-space working folder to avoid whitespace errors.")
            log(f"[WS-SAFE] Workdir: {temp_run_dir}")
        except Exception as e:
            log(f"[WARN] Gagal menyiapkan whitespace-safe workdir; mencoba jalur asli. Detail: {e}")
            exe = LOGFILEPARSER64
            raw_for_lfp = raw
            out_for_lfp = out
            mft_for_lfp = mft_csv_path if mft_csv_path.exists() else None

    args = [
        str(exe),
        f"/LogFileFile:{raw_for_lfp}",
        f"/OutputPath:{out_for_lfp}",
        f"/TimeZone:{timezone}",
        f"/MftRecordSize:{mft_record_size}",
        "/TSFormat:2",
        "/TSPrecision:None",
        "/Unicode:0",
        "/SkipSqlite3:1",
    ]

    if mft_for_lfp and Path(mft_for_lfp).exists():
        # Some versions expect mft2csv format; if it fails, run again without this manually.
        args.append(f"/MftCsvFile:{mft_for_lfp}")

    rc = run_lfp(args)

    # LogFileParser errorlevel 1 means empty output; 2 usually wrong MFT record size / sectors per cluster.
    if rc == 124:
        log("[WARN] Raw $LogFile was not used because LogFileParser timed out. This is not a fatal error; the other artifacts will still be analyzed.")
        return False
    if rc != 0:
        log("[WARN] LogFileParser returned a non-zero error level. Check debug.log and try the MftRecordSize/SectorsPerCluster parameters if the output is empty.")

    # Prefer joined if created, otherwise LogFile.csv.
    candidates = [
        out_for_lfp/"LogFileJoined.csv",
        out_for_lfp/"LogFile.csv",
        out_for_lfp/"LogFile_Mft_StandardInformation.csv",
    ]
    found = next((p for p in candidates if p.exists() and p.stat().st_size > 0), None)
    if not found:
        # Search any log csv just in case output folder prefix/subfolder differs.
        founds = [p for p in Path(out_for_lfp).rglob("LogFileJoined.csv") if p.is_file()] + [p for p in Path(out_for_lfp).rglob("LogFile.csv") if p.is_file()]
        found = founds[0] if founds else None
    if not found:
        log("[ERROR] LogFileParser output CSV not found. Check Parsed_CSV\\LogFile and debug.log.")
        return False

    # If output was produced in temp whitespace-safe folder, archive it back to the case output folder.
    if temp_run_dir is not None:
        try:
            ensure(out)
            for csv_file in Path(out_for_lfp).rglob("*.csv"):
                rel = csv_file.relative_to(out_for_lfp)
                dst = out / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(csv_file, dst)
            log(f"[WS-SAFE] CSV LogFileParser dicopy kembali ke: {out}")
        except Exception as e:
            log(f"[WARN] Not all temporary CSV files could be copied to the case folder: {e}")

    return import_logfile_csv(case, str(found))



def _csv_row_count_safe(p: Path) -> int:
    try:
        return count_csv_rows(p)
    except Exception:
        return 0


def _candidate_rank_for_existing_csv(p: Path, kind: str) -> tuple:
    """Rank existing case CSVs so full artifact CSVs are preferred over Search/output summaries."""
    name = p.name.lower()
    # Penalize derived OATFD output and NLT search subsets; prefer raw parsed artifacts.
    penalty = 0
    bad_tokens = [
        'detection_matrix', 'case_reasoning', 'timeline_events', 'run_summary',
        'high_confidence', 'need_review', 'visual_summary', 'comparison_ready',
        'suspicious_behavior_detection', '00_lnk_export_log'
    ]
    if any(t in name for t in bad_tokens):
        penalty += 100
    if 'search' in name:
        penalty += 10
    if kind == 'usn' and ('nlt_usnjrnl' in name or 'usn_parsed' in name):
        penalty -= 5
    if kind == 'log' and ('nlt_logfile' in name or 'logfile_parsed' in name or 'logfilejoined' in name):
        penalty -= 5
    if kind == 'mft' and 'mft_parsed' in name:
        penalty -= 5
    # Larger row count and newer mtime are preferred after penalty.
    rows = _csv_row_count_safe(p)
    try:
        mtime = p.stat().st_mtime
    except Exception:
        mtime = 0
    return (penalty, -rows, -mtime, str(p))


def _find_existing_case_csv(case: Path, kind: str, patterns: list[str], dest_name: str) -> Optional[Path]:
    roots = []
    for r in [case/"INPUT_PYTHON", case/"Parsed_CSV", case]:
        if r.exists():
            roots.append(r)
    found = []
    dest = case/"INPUT_PYTHON"/dest_name
    for root in roots:
        for pat in patterns:
            try:
                for p in root.rglob(pat):
                    if not p.is_file():
                        continue
                    if p.resolve() == dest.resolve() if dest.exists() else False:
                        continue
                    # Avoid re-importing output reports as source artifact CSVs.
                    lname = p.name.lower()
                    if any(x in lname for x in ['detection_matrix','case_reasoning','visual_summary','run_summary','comparison_ready','high_confidence','need_review','suspicious_behavior_detection']):
                        continue
                    if _csv_row_count_safe(p) <= 0:
                        continue
                    found.append(p)
            except Exception:
                pass
    if not found:
        return None
    found = sorted(set(found), key=lambda x: _candidate_rank_for_existing_csv(x, kind))
    return found[0]


def auto_import_existing_primary_artifacts(case: Path) -> bool:
    """v1.0: Detect + Timeline should not silently run LNK-only when case CSV artifacts exist.

    This imports existing MFT/USN/LogFile/Prefetch CSVs from the selected case folder if the
    corresponding INPUT_PYTHON CSV is missing or empty. LNK remains context evidence.
    """
    case_dirs(case)
    imported = False
    inp = case/"INPUT_PYTHON"

    mft_dest = inp/"mft_parsed.csv"
    if _csv_row_count_safe(mft_dest) == 0:
        mft = _find_existing_case_csv(case, 'mft', ["mft_parsed.csv", "mft_parsed*.csv"], "mft_parsed.csv")
        if mft:
            log(f"[AUTO IMPORT] Existing MFT CSV found: {mft}")
            imported = copy_file(mft, mft_dest) or imported

    usn_dest = inp/"usn_parsed.csv"
    if _csv_row_count_safe(usn_dest) == 0:
        usn = _find_existing_case_csv(case, 'usn', ["usn_parsed.csv", "usn_parsed*.csv", "NLT_UsnJrnl_*.csv", "*UsnJrnl*.csv", "*USN*.csv"], "usn_parsed.csv")
        if usn:
            log(f"[AUTO IMPORT] Existing USN CSV found: {usn}")
            imported = import_usn_csv(case, str(usn)) or imported

    log_dest = inp/"logfile_parsed.csv"
    if _csv_row_count_safe(log_dest) == 0:
        log_csv = _find_existing_case_csv(case, 'log', ["logfile_parsed.csv", "logfile_parsed*.csv", "LogFileJoined.csv", "LogFile.csv", "NLT_LogFile_*.csv", "*LogFile*.csv"], "logfile_parsed.csv")
        if log_csv:
            log(f"[AUTO IMPORT] Existing LogFile CSV found: {log_csv}")
            imported = import_logfile_csv(case, str(log_csv)) or imported

    pf_dest = inp/"prefetch_all_parsed.csv"
    if _csv_row_count_safe(pf_dest) == 0:
        pf = _find_existing_case_csv(case, 'pf', ["prefetch_all_parsed.csv", "prefetch_all_parsed*.csv"], "prefetch_all_parsed.csv")
        if pf:
            log(f"[AUTO IMPORT] Existing Prefetch CSV found: {pf}")
            imported = copy_file(pf, pf_dest) or imported

    i30_dest = inp/"i30_parsed.csv"
    if _csv_row_count_safe(i30_dest) == 0:
        i30 = _find_existing_case_csv(case, 'i30', ["i30_parsed.csv", "i30_all_physical.csv", "i30_all*.csv", "i30_percobaan*.csv", "*i30*.csv", "*I30*.csv", "INDX*.csv", "*indx*.csv"], "i30_parsed.csv")
        if i30:
            log(f"[AUTO IMPORT] Existing $I30 CSV found: {i30}")
            imported = copy_file(i30, i30_dest) or imported

    if imported:
        primary = []
        for fn in ["mft_parsed.csv", "usn_parsed.csv", "logfile_parsed.csv", "prefetch_all_parsed.csv", "i30_parsed.csv"]:
            p = inp/fn
            primary.append(f"{fn}={_csv_row_count_safe(p)}")
        log("[AUTO IMPORT] Primary artifact rows after import: " + ", ".join(primary))
    return imported


def _matrix_is_lnk_only(matrix_path: Path) -> bool:
    if not matrix_path.exists() or count_csv_rows(matrix_path) == 0:
        return False
    try:
        rows = read_csv_auto(matrix_path)
        if not rows:
            return False
        def is_lnk_row(r):
            ext = str(r.get('extension','')).lower().strip().lstrip('.')
            src = str(r.get('target_source_artifact','') or r.get('source_artifact','')).lower()
            name = str(r.get('target_name','')).lower()
            rel = str(r.get('relative_path','')).lower()
            return ext == 'lnk' or name.endswith('.lnk') or 'lnk_windowsrecent' in src or 'lnk_officerecent' in src or 'lnk_windowsrecent' in rel or 'lnk_officerecent' in rel
        return all(is_lnk_row(r) for r in rows)
    except Exception:
        return False

def use_existing(case: Path):
    case_dirs(case)
    mapping = {
        "mft_parsed.csv": ["mft_parsed.csv", "mft_parsed*.csv"],
        "usn_parsed.csv": ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*", "$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*", "usn_parsed.csv", "usn_parsed*.csv", "NLT_UsnJrnl*.csv", "*UsnJrnl*.csv", "*USN*.csv"],
        "prefetch_all_parsed.csv": ["prefetch_all_parsed.csv", "prefetch_all_parsed*.csv"],
        "lnk_windows_recent_parsed.csv": ["lnk_windows_recent_parsed.csv", "lnk_windows_recent_parsed*.csv"],
        "lnk_office_recent_parsed.csv": ["lnk_office_recent_parsed.csv", "lnk_office_recent_parsed*.csv"],
        "i30_parsed.csv": ["i30_parsed.csv", "i30_all_physical.csv", "i30_all*.csv", "i30_percobaan*.csv", "*i30*.csv", "*I30*.csv", "INDX*.csv", "*indx*.csv"],
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
                        found = matches[0]
                        break
            if found:
                break
        if found:
            if dest == "usn_parsed.csv":
                if found.suffix.lower() == ".csv":
                    ok = import_usn_csv(case, str(found)) or ok
                else:
                    ok = parse_usn(case, str(found)) or ok
            else:
                ok = copy_file(found, case/"INPUT_PYTHON"/dest) or ok
        else:
            log(f"[MISS] {dest}")
            if dest == "mft_parsed.csv": empty_mft(case)
            elif dest == "usn_parsed.csv": empty_usn(case)
            elif dest == "prefetch_all_parsed.csv": empty_prefetch(case)
            elif dest == "i30_parsed.csv": empty_i30(case)
    logc = find_file(case, ["LogFileJoined.csv", "LogFile.csv", "logfile_parsed.csv", "logfile_parsed*.csv", "NLT_LogFile*.csv"])
    if logc and logc != case/"INPUT_PYTHON"/"logfile_parsed.csv":
        ok = import_logfile_csv(case, str(logc)) or ok
    elif (case/"INPUT_PYTHON"/"logfile_parsed.csv").exists():
        ok = True
    else:
        log("[MISS] logfile_parsed.csv")
    return ok

def write_placeholder_csv(path: Path, header):
    """Create an empty CSV so downstream stages can run in artifact-flexible mode."""
    if not path.exists():
        ensure(path.parent)
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            csv.writer(f).writerow(header)
        log(f"[PLACEHOLDER] {path}")


def empty_mft(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"mft_parsed.csv", [
        "EntryNumber", "SequenceNumber", "InUse", "IsDirectory", "IsAds", "FileName", "Extension", "ParentPath",
        "Created0x10", "LastModified0x10", "LastAccess0x10", "LastRecordChange0x10",
        "Created0x30", "LastModified0x30", "LastAccess0x30", "LastRecordChange0x30",
        "SI<FN", "uSecZeros", "LogfileSequenceNumber"
    ])


def empty_usn(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"usn_parsed.csv", [
        "UpdateTimestamp", "Name", "FullPath", "ParentPath", "UpdateReasons", "SourceInfo",
        "FileAttribute", "USN", "FileReferenceNumber", "ParentFileReferenceNumber"
    ])


def empty_prefetch(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"prefetch_all_parsed.csv", [
        "SourceFilename", "ExecutableName", "RunCount", "LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2"
    ])


def empty_log(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"logfile_parsed.csv", [
        "EventTime(UTC+7)", "Event", "Detail", "Source", "TargetName", "FullPath",
        "Log_LSN", "Log_PreviousLSN", "Log_CurrentAttribute", "Log_RedoOperation", "Log_UndoOperation", "Log_MFTReference"
    ])

def empty_i30(case):
    write_placeholder_csv(case/"INPUT_PYTHON"/"i30_parsed.csv", [
        "record_type", "parent_path", "parent_mft_ref", "parent_sequence", "file_name", "attributes",
        "child_mft_ref", "child_sequence", "logical_size", "allocated_size",
        "i30_created_utc", "i30_modified_utc", "i30_accessed_utc", "i30_changed_utc"
    ])


def import_i30_csv(case: Path, i30_csv: str = ""):
    case_dirs(case)
    src = Path(i30_csv) if i30_csv else find_file(case, [
        "i30_parsed.csv", "i30_all_physical.csv", "i30_all*.csv", "i30_percobaan*.csv", "*i30*.csv", "*I30*.csv", "INDX*.csv", "*indx*.csv"
    ])
    if not src or not src.exists():
        log("[MISS] i30_parsed.csv / i30_all*.csv")
        empty_i30(case)
        return False
    dst = case/"INPUT_PYTHON"/"i30_parsed.csv"
    return copy_file(src, dst)



def normalize_usn_csv(src: Path, dst: Path):
    """Normalize MFTECmd or NTFS Log Tracker USN CSV into the internal usn_parsed.csv schema.

    Supported examples:
    - MFTECmd: UpdateTimestamp, Name, UpdateReasons, ...
    - NTFS Log Tracker: TimeStamp(UTC+7), File/Directory Name, FullPath, EventInfo, ...
    """
    rows = read_csv_auto(src)
    out_rows = []

    def pick(row, cols):
        lower_map = {str(k).strip().lower(): k for k in row.keys()}
        for c in cols:
            if c in row and str(row.get(c, "")).strip():
                return str(row.get(c, "")).strip()
            lk = c.lower()
            if lk in lower_map and str(row.get(lower_map[lk], "")).strip():
                return str(row.get(lower_map[lk], "")).strip()
        # Loose contains fallback.
        for k, v in row.items():
            kl = str(k).strip().lower()
            if any(c.lower() in kl for c in cols) and str(v).strip():
                return str(v).strip()
        return ""

    def dirname_from_path(path_text, name_text):
        t = str(path_text or "").replace("/", "\\").strip()
        n = str(name_text or "").strip()
        if not t:
            return ""
        # If FullPath ends with filename, remove filename. Otherwise treat it as parent/context path.
        if n and t.lower().endswith("\\" + n.lower()):
            return t[:-(len(n)+1)]
        if n and t.lower().endswith(n.lower()):
            return t[: -len(n)].rstrip("\\")
        return t

    for r in rows:
        ts = ""
        for c in ["UpdateTimestamp", "TimeStamp(UTC+7)", "Timestamp(UTC+7)", "TimeStamp", "Timestamp", "Time", "EventTime"]:
            val = pick(r, [c])
            ts = parse_dt_any(val)
            if ts:
                break
        if not ts:
            for v in r.values():
                ts = parse_dt_any(v)
                if ts:
                    break
        name = pick(r, ["Name", "FileName", "File/Directory Name", "File Directory Name", "Filename", "TargetName"])
        fullpath = pick(r, ["FullPath", "Path", "FilePath", "TargetPath"])
        # v1.0: do not use loose "Directory" matching for ParentPath, because NLT's
        # "File/Directory Name" column can be accidentally selected as parent.
        parent = ""
        for pc in ["ParentPath", "Parent Path", "Parent", "FolderPath", "Folder Path"]:
            if pc in r and str(r.get(pc, "")).strip():
                parent = str(r.get(pc, "")).strip()
                break
        if not parent:
            parent = dirname_from_path(fullpath, name)
        reason = pick(r, ["UpdateReasons", "EventInfo", "Reason", "Reasons", "Event", "EventName"])
        # Preserve original but also normalize common NLT spellings for detection.
        reason_norm = reason.replace("_", "")
        out_rows.append({
            "UpdateTimestamp": ts,
            "Name": name,
            "FullPath": fullpath,
            "ParentPath": parent,
            "UpdateReasons": reason_norm or reason,
            "SourceInfo": pick(r, ["SourceInfo", "Source"]),
            "FileAttribute": pick(r, ["FileAttribute", "FileAttributes", "Attributes"]),
            "USN": pick(r, ["USN"]),
            "FileReferenceNumber": pick(r, ["FileReferenceNumber", "FileReference", "FRN"]),
            "ParentFileReferenceNumber": pick(r, ["ParentFileReferenceNumber", "ParentFileReference", "ParentFRN"]),
            "OriginalUpdateReasons": reason,
        })
    ensure(dst.parent)
    fields = ["UpdateTimestamp", "Name", "FullPath", "ParentPath", "UpdateReasons", "SourceInfo", "FileAttribute", "USN", "FileReferenceNumber", "ParentFileReferenceNumber", "OriginalUpdateReasons"]
    with dst.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(out_rows)
    log(f"[NORMALIZE] {src} -> {dst} ({len(out_rows)} rows)")
    return True



USN_REASON_FLAGS = [
    (0x00000001, "DataOverwrite"),
    (0x00000002, "DataExtend"),
    (0x00000004, "DataTruncation"),
    (0x00000010, "NamedDataOverwrite"),
    (0x00000020, "NamedDataExtend"),
    (0x00000040, "NamedDataTruncation"),
    (0x00000100, "FileCreate"),
    (0x00000200, "FileDelete"),
    (0x00000400, "EAChange"),
    (0x00000800, "SecurityChange"),
    (0x00001000, "RenameOldName"),
    (0x00002000, "RenameNewName"),
    (0x00004000, "IndexableChange"),
    (0x00008000, "BasicInfoChange"),
    (0x00010000, "HardLinkChange"),
    (0x00020000, "CompressionChange"),
    (0x00040000, "EncryptionChange"),
    (0x00080000, "ObjectIdChange"),
    (0x00100000, "ReparsePointChange"),
    (0x00200000, "StreamChange"),
    (0x80000000, "Close"),
]

USN_ATTR_FLAGS = [
    (0x00000001, "ReadOnly"),
    (0x00000002, "Hidden"),
    (0x00000004, "System"),
    (0x00000010, "Directory"),
    (0x00000020, "Archive"),
    (0x00000040, "Device"),
    (0x00000080, "Normal"),
    (0x00000100, "Temporary"),
    (0x00000200, "SparseFile"),
    (0x00000400, "ReparsePoint"),
    (0x00000800, "Compressed"),
    (0x00001000, "Offline"),
    (0x00002000, "NotContentIndexed"),
    (0x00004000, "Encrypted"),
]

def _mask_names(mask: int, table) -> str:
    names = [name for bit, name in table if mask & bit]
    return "|".join(names) if names else (hex(mask) if mask else "")

def _filetime_to_iso_from_int(v: int) -> str:
    try:
        if not v:
            return ""
        dt = datetime(1601, 1, 1) + timedelta(microseconds=v / 10)
        if dt.year < 1980 or dt.year > 2200:
            return ""
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        return ""

def parse_usn_raw_internal(case: Path, raw_usn_file: str = ""):
    """Lightweight internal parser for raw $UsnJrnl_$J / $UsnJrnl_$J.bin.

    This is intentionally conservative: it extracts USN_RECORD_V2/V3 fields needed by
    OATFD's USN-only mode (timestamp, filename, reason flags, file attributes, FRN/PFRN).
    It does not require $MFT and therefore works with Jung Oh datasets that contain only
    one raw USN journal binary.
    """
    case_dirs(case)
    src = Path(raw_usn_file) if raw_usn_file else find_file(case, [
        "$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*"
    ])
    if not src or not src.exists():
        log("[MISS] Raw $UsnJrnl_$J/.bin was not found for the internal parser.")
        empty_usn(case)
        return True

    data = src.read_bytes()
    rows = []
    off = 0
    n = len(data)
    consecutive = 0

    def plausible_name(txt: str) -> bool:
        if not txt:
            return False
        if len(txt) > 1024:
            return False
        # Reject mostly non-printable / replacement garbage.
        bad = sum(1 for ch in txt if ch == "\ufffd" or (ord(ch) < 32 and ch not in "\t\r\n"))
        return bad <= max(1, len(txt) // 10)

    while off + 60 <= n:
        try:
            rec_len = struct.unpack_from("<I", data, off)[0]
            major = struct.unpack_from("<H", data, off + 4)[0]
            minor = struct.unpack_from("<H", data, off + 6)[0]
        except Exception:
            break

        valid = False
        if 60 <= rec_len <= 0x10000 and off + rec_len <= n and major in (2, 3) and minor < 10:
            try:
                if major == 2:
                    frn = str(struct.unpack_from("<Q", data, off + 8)[0])
                    pfrn = str(struct.unpack_from("<Q", data, off + 16)[0])
                    usn_value = str(struct.unpack_from("<q", data, off + 24)[0])
                    ts_raw = struct.unpack_from("<Q", data, off + 32)[0]
                    reason_mask = struct.unpack_from("<I", data, off + 40)[0]
                    source_mask = struct.unpack_from("<I", data, off + 44)[0]
                    attr_mask = struct.unpack_from("<I", data, off + 52)[0]
                    name_len = struct.unpack_from("<H", data, off + 56)[0]
                    name_off = struct.unpack_from("<H", data, off + 58)[0]
                else:  # USN_RECORD_V3: 128-bit FRNs
                    frn = data[off+8:off+24].hex()
                    pfrn = data[off+24:off+40].hex()
                    usn_value = str(struct.unpack_from("<q", data, off + 40)[0])
                    ts_raw = struct.unpack_from("<Q", data, off + 48)[0]
                    reason_mask = struct.unpack_from("<I", data, off + 56)[0]
                    source_mask = struct.unpack_from("<I", data, off + 60)[0]
                    attr_mask = struct.unpack_from("<I", data, off + 68)[0]
                    name_len = struct.unpack_from("<H", data, off + 72)[0]
                    name_off = struct.unpack_from("<H", data, off + 74)[0]

                name_end = off + name_off + name_len
                ts = _filetime_to_iso_from_int(ts_raw)
                if name_len > 0 and name_len <= rec_len and name_off < rec_len and name_end <= off + rec_len and ts:
                    raw_name = data[off + name_off:name_end]
                    try:
                        name = raw_name.decode("utf-16le", errors="replace").strip("\x00").strip()
                    except Exception:
                        name = ""
                    if plausible_name(name):
                        rows.append({
                            "UpdateTimestamp": ts,
                            "Name": name,
                            "FullPath": "",
                            "ParentPath": "",
                            "UpdateReasons": _mask_names(reason_mask, USN_REASON_FLAGS),
                            "SourceInfo": hex(source_mask) if source_mask else "",
                            "FileAttribute": _mask_names(attr_mask, USN_ATTR_FLAGS),
                            "USN": usn_value,
                            "FileReferenceNumber": frn,
                            "ParentFileReferenceNumber": pfrn,
                            "OriginalUpdateReasons": _mask_names(reason_mask, USN_REASON_FLAGS),
                        })
                        valid = True
            except Exception:
                valid = False

        if valid:
            consecutive += 1
            off += rec_len
            # USN records are usually 8-byte aligned.
            if off % 8:
                off += 8 - (off % 8)
        else:
            consecutive = 0
            off += 8 if rec_len == 0 else 1

    dst = case/"INPUT_PYTHON"/"usn_parsed.csv"
    ensure(dst.parent)
    fields = ["UpdateTimestamp", "Name", "FullPath", "ParentPath", "UpdateReasons", "SourceInfo", "FileAttribute", "USN", "FileReferenceNumber", "ParentFileReferenceNumber", "OriginalUpdateReasons"]
    with dst.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)
    log(f"[INTERNAL USN PARSER] {src} -> {dst} ({len(rows)} rows)")
    log(f'[USN-ONLY] Rows terbaca: {len(rows)}')

    if not rows:
        log("[WARN] The internal parser did not find any USN_RECORD entries. Try parsing with MFTECmd/NTFS Log Tracker and then import the CSV.")
    return True

def import_usn_csv(case: Path, usn_csv: str=""):
    case_dirs(case)
    src = Path(usn_csv) if usn_csv else find_file(case, [
        "$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*", "usn_parsed.csv", "usn_parsed*.csv", "NLT_UsnJrnl*.csv", "*UsnJrnl*.csv", "*USN*.csv"
    ])
    if not src or not src.exists():
        log("[MISS] USN CSV not found; USN will be treated as unavailable evidence.")
        empty_usn(case)
        return True
    return normalize_usn_csv(src, case/"INPUT_PYTHON"/"usn_parsed.csv")



def _usn_direct_parse_dt(x: str):
    x = str(x or '').strip()
    if not x:
        return None
    x = x.replace('T', ' ').replace('Z', '')
    for fmt in [
        '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
        '%d/%m/%Y %H:%M:%S.%f', '%d/%m/%Y %H:%M:%S',
        '%m/%d/%Y %H:%M:%S.%f', '%m/%d/%Y %H:%M:%S',
    ]:
        try:
            return datetime.strptime(x[:26], fmt) if '%f' in fmt else datetime.strptime(x[:19], fmt)
        except Exception:
            pass
    try:
        return datetime.fromisoformat(x)
    except Exception:
        return None


def _usn_direct_reason(r: dict) -> str:
    return str(r.get('UpdateReasons') or r.get('OriginalUpdateReasons') or r.get('EventInfo') or r.get('Reason') or r.get('Event') or '')


def _usn_direct_time(r: dict) -> str:
    return str(r.get('UpdateTimestamp') or r.get('TimeStamp(UTC+7)') or r.get('Timestamp(UTC+7)') or r.get('TimeStamp') or r.get('Timestamp') or r.get('Time') or '')


def _usn_direct_name(r: dict) -> str:
    return str(r.get('Name') or r.get('FileName') or r.get('File/Directory Name') or '').strip()


def _usn_direct_frn(r: dict) -> str:
    return str(r.get('FileReferenceNumber') or r.get('File Reference Number') or r.get('FRN') or r.get('MFTReference') or r.get('EntryNumber') or '').strip()


def _usn_direct_bool_reason(txt: str, needles) -> bool:
    compact = ''.join(ch.lower() for ch in str(txt or '') if ch.isalnum())
    for n in needles:
        nn = ''.join(ch.lower() for ch in n if ch.isalnum())
        if nn and nn in compact:
            return True
    return False



def _usn_name_for_rules(name: str) -> str:
    return str(name or '').strip().lower()


def _usn_is_known_timestomp_tool_execution(name: str, parent: str = '', reasons: str = '') -> bool:
    """High-precision tool-execution signal for USN-only benchmark mode.

    This deliberately avoids generic words like "time" because Windows contains many normal
    components such as TimeBrokerServer, timedate.cpl, w32time, TimeSyncTask, etc.
    """
    n = _usn_name_for_rules(name)
    p = str(parent or '').lower()
    txt = n + ' ' + p
    # Prefetch artifacts are execution evidence.
    if re.search(r'(^|[^a-z0-9])(newfiletime|ntimestomp|timestomp|setmace|setmac|bulkfilechanger|filetouch|touchfile)[^\\/]*\.pf$', n, re.I):
        return True
    # Direct executable/script artifacts for known timestamp tools.
    if re.search(r'(^|[^a-z0-9])(newfiletime(_x64)?|ntimestomp(_v[0-9._x64-]*)?|timestomp|setmace|setmac|bulkfilechanger|filetouch|touchfile)\.(exe|bat|cmd|ps1)$', n, re.I):
        return True
    return False


def _usn_is_known_timestomp_related(name: str, parent: str = '') -> bool:
    n = _usn_name_for_rules(name)
    p = str(parent or '').lower()
    txt = n + ' ' + p
    # Related/config files are relevant context but not execution proof by themselves.
    return bool(re.search(r'(^|[^a-z0-9])(newfiletime|ntimestomp|timestomp|setmace|setmac|bulkfilechanger|filetouch|touchfile)([^a-z0-9]|$)', txt, re.I))


def _usn_is_benchmark_timestamp_target(name: str, parent: str = '') -> bool:
    n = _usn_name_for_rules(name)
    p = str(parent or '').lower()
    txt = n + ' ' + p
    # External research datasets sometimes encode scenario labels in filenames. Treat this
    # as benchmark context, not as universal forensic proof.
    labels = [
        'newfiletime_si_', 'si_c_manipulation', 'si_m_manipulation', 'si_a_manipulation', 'si_e_manipulation',
        'timestamp_manipulation', 'timestomp', 'time stomping', 'forgery', 'forged_timestamp'
    ]
    return any(x in txt for x in labels)


def _usn_is_system_or_app_churn(name: str, parent: str = '', reasons: str = '') -> bool:
    """Suppress common USN-only noise. BasicInfoChange in these contexts is usually
    normal system/app churn unless there is known tool evidence or explicit benchmark label.
    """
    n = _usn_name_for_rules(name)
    p = str(parent or '').lower()
    txt = n + ' ' + p
    # Deletion/servicing artifacts and Windows/component churn.
    if n.startswith('$$deleteme'):
        return True
    if re.search(r'\.(mui|aux|ni\.dll\.aux|ni\.exe\.aux|etl|evtx|log[0-9]*|tmp|temp|cache)$', n, re.I):
        return True
    if re.match(r'^(wct|bit)[0-9a-f]+\.tmp$', n, re.I):
        return True
    if re.match(r'^[0-9a-f]{16,}\.?$', n, re.I):
        return True
    noisy_exact = {
        'local state','preferences','secure preferences','network persistent state','trusted vault','temp','ie',
        'cortanaunifiedtilemodelcache.dat','startunifiedtilemodelcache.dat','eventbeacons.dat',
        'the-real-index','global.ini','scan_results.json','lsdb2.json','sct auditing pending reports'
    }
    if n in noisy_exact:
        return True
    noisy_substrings = [
        'runtimebroker', 'timebrokerserver', 'timedate.cpl', 'w32time', 'timesynctask', 'timeout.exe',
        'windowsappruntime', 'microsoft.build.', 'visualstudio', 'vsix', 'package cache',
        'customdestinations-ms', 'automaticdestinations-ms', 'jump list', 'tilemodelcache',
        'appdata\\local\\microsoft\\windows', 'windows\\winsxs', 'windows\\servicing',
        'program files\\windowsapps', 'appx', 'cortana', 'search', 'edge', 'chrome\\user data'
    ]
    return any(x in txt for x in noisy_substrings)


def _usn_is_control_normal_or_support(name: str, parent: str = '') -> bool:
    """Names that should not be promoted to file-level manipulation in USN-only mode.

    v1.0 realcase default: do NOT use benchmark labels such as normal_, control_,
    s01_, s02_, or tunnel_ as negative guards. Only objective support/report,
    Office temp, Recycle Bin and system/context artifacts are guarded.

    To reproduce benchmark-only behavior, set OATFD_BENCHMARK_MODE=1.
    """
    n = _usn_name_for_rules(name)
    p = str(parent or '').lower()
    txt = n + ' ' + p
    if not n:
        return False
    if n.startswith('~$') or n.startswith('$i') or n.startswith('$r'):
        return True
    support_exact = {
        '00_log_timestomping_perfile.csv', '00_log_timestomping_perfile.xlsx',
        '00_daftar_file_mace.xlsx', 'run_summary.csv', 'detection_matrix.csv',
        'case_reasoning.csv', 'timeline_events.csv', 'visual_summary_table.csv',
        'suspicious_behavior_detection.csv', 'high_confidence_suspicious.csv',
        'need_review_candidates.csv', 'comparison_ready_summary.csv', 'ground_truth.csv',
        'action_log.csv', 'file_times_snapshot.csv'
    }
    if n in support_exact:
        return True
    objective_support_words = [
        'ground_truth', 'action_log', 'file_times_snapshot',
        'daftar_file_mace', 'log_timestomping_perfile'
    ]
    if any(x in txt for x in objective_support_words):
        return True
    if n.startswith(('visual_dashboard',)):
        return True
    # Benchmark labels are disabled in realcase mode to avoid label leakage.
    if OATFD_BENCHMARK_MODE:
        support_prefixes = ('s01_', 's02_', 'tunnel_', 'normal_', 'control_')
        benchmark_words = ['normal_autosave', 'office_normal_autosave', 'normal_archive']
        if n.startswith(support_prefixes) or any(x in txt for x in benchmark_words):
            return True
    return False

def usn_only_direct_detect(case: Path, target_keyword: str = '', max_timeline_per_target: int = 6, usn_profile: str = 'auto') -> bool:
    """v1.0 adaptive, streaming USN-only detector.

    Correctness goal:
    - Do not treat BasicInfoChange alone as timestamp manipulation.
    - Reserve Suspicious High for high-precision USN-only evidence.
    - Move broad metadata-change patterns to Need Review or Normal with system/app churn guards.
    - Keep output responsive on large Jung Oh journals by aggregating while streaming.
    """
    case_dirs(case)
    out = case/'OATFD_OUTPUT'
    ensure(out)
    usn_path = case/'INPUT_PYTHON'/'usn_parsed.csv'
    if not usn_path.exists():
        log('[ERROR] USN-only evidence detection failed: INPUT_PYTHON/usn_parsed.csv is missing.')
        return False

    kw = (target_keyword or '').lower().strip()
    log('[USN-ONLY CAL] Streaming read + aggregate INPUT_PYTHON/usn_parsed.csv ...')
    groups = {}
    row_count = 0

    # v1.0: USN-only behavior alerts must be computed inside this streaming path.
    # The full mini_nlt_prototype behavior layer is not executed when the LFP engine
    # chooses adaptive USN-only direct mode, so we collect NLT-like alerts here.
    behavior_alerts = []
    system_time_anomalies = []
    document_deletion_alerts = []
    behavior_prev_event = None
    behavior_seen_deletions = set()

    def _safe_int(x, default=0):
        try:
            return int(str(x or '').strip())
        except Exception:
            return default

    def _behavior_usn_value(rr):
        return _safe_int(rr.get('UpdateSequenceNumber') or rr.get('USN') or rr.get('Usn') or rr.get('Offset') or rr.get('RecordNumber'), 0)

    def _behavior_severity(minutes):
        if minutes >= 360:
            return 'very_strong'
        if minutes >= 30:
            return 'strong'
        if minutes >= 5:
            return 'suspicious'
        return 'weak'

    def _behavior_path(rr, nm):
        return str(rr.get('FullPath') or rr.get('Path') or rr.get('ParentPath') or '').strip()

    def _is_document_deletion_behavior(nm, path, reason):
        base = Path(str(nm or path or '')).name
        low = base.lower()
        ext = Path(low).suffix.lower()
        # Keep deletion behavior comparable with NLT and avoid noisy temp/lock files.
        if ext not in {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf', '.odt', '.ods', '.odp'}:
            return False
        if low.startswith(('~$', '~wrd', '~wrl')) or low.endswith(('.tmp', '.temp')):
            return False
        compact = ''.join(ch.lower() for ch in str(reason or '') if ch.isalnum())
        if not any(tok in compact for tok in ['filedelete', 'filedeleted', 'deleted', 'delete']):
            return False
        ctx = (str(path or '') + '\\' + base).replace('/', '\\').lower()
        if any(tok in ctx for tok in ['\\windows\\', '\\program files', '\\programdata\\microsoft\\search', '\\system volume information', '\\$extend', '\\appdata\\local\\temp', '\\input_python', '\\oatfd_output', '\\output_python']):
            return False
        return True

    def norm_key_name(x):
        return str(x or '').strip().lower()

    def update_minmax(g, dt):
        if not dt:
            return
        if g.get('first_dt') is None or dt < g['first_dt']:
            g['first_dt'] = dt
        if g.get('last_dt') is None or dt > g['last_dt']:
            g['last_dt'] = dt

    try:
        with usn_path.open('r', encoding='utf-8-sig', errors='ignore', newline='') as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                log('[ERROR] usn_parsed.csv does not have a valid CSV header.')
                _write_usn_diag_outputs(out, 'usn_parsed.csv exists but has no valid CSV header.')
                return True
            for r in reader:
                row_count += 1
                if row_count % 50000 == 0:
                    log(f'[USN-ONLY CAL] Rows dibaca: {row_count}; target sementara: {len(groups)} ...')
                rr = {str(k): '' if v is None else str(v) for k, v in r.items() if k is not None}
                name = _usn_direct_name(rr)
                if not name or name in {'.','..'}:
                    continue
                parent = str(rr.get('ParentPath') or rr.get('FullPath') or rr.get('Path') or '')
                if kw and kw not in name.lower() and kw not in parent.lower():
                    continue
                frn = _usn_direct_frn(rr)
                # v1.0 benchmark mode groups by logical visible target name (plus parent if available).
                # Jung Oh USN exports often lack full path and contain many FRN-specific duplicates;
                # name-level grouping gives a stable benchmark output and avoids duplicate over-counting.
                key = (norm_key_name(name), parent.lower() if parent else '')
                g = groups.get(key)
                if g is None:
                    g = {
                        'name': name, 'parent': parent, 'frn': frn, 'event_count': 0,
                        'first_dt': None, 'last_dt': None, 'create_min': None, 'basic_max': None,
                        'basic_count': 0, 'has_basic': False, 'has_create': False, 'has_data': False,
                        'has_close': False, 'has_rename': False, 'has_delete': False, 'has_security': False,
                        'reason_seen': [], 'reason_set': set(), 'compact_seq': [], 'timeline': []
                    }
                    groups[key] = g
                reason = _usn_direct_reason(rr)
                dt = _usn_direct_parse_dt(_usn_direct_time(rr))

                # v1.0 behavior alerts: compare journal order vs event time before
                # target grouping/filter side effects hide system-level anomalies.
                usn_val_for_behavior = _behavior_usn_value(rr)
                path_for_behavior = _behavior_path(rr, name)
                if dt is not None:
                    if behavior_prev_event is not None:
                        delta_min = (dt - behavior_prev_event['time']).total_seconds() / 60.0
                        if delta_min < -5:
                            reversal = abs(delta_min)
                            alert = {
                                'alert_type': 'System Time Reversal',
                                'source': '$UsnJrnl:$J',
                                'severity': _behavior_severity(reversal),
                                'previous_usn': behavior_prev_event.get('usn', ''),
                                'current_usn': usn_val_for_behavior,
                                'previous_time': behavior_prev_event['time'].isoformat(sep=' '),
                                'current_time': dt.isoformat(sep=' '),
                                'reversal_minutes': f'{reversal:.2f}',
                                'previous_file': behavior_prev_event.get('name', ''),
                                'current_file': name,
                                'previous_path': behavior_prev_event.get('path', ''),
                                'current_path': path_for_behavior,
                                'previous_reason': behavior_prev_event.get('reason', ''),
                                'current_reason': reason,
                                'category': 'System Time Anomaly',
                                'primary_manipulation': 'False',
                                'note': 'USN record order advanced, but event timestamp moved backward.',
                            }
                            system_time_anomalies.append(alert)
                            behavior_alerts.append(alert)
                    behavior_prev_event = {'time': dt, 'usn': usn_val_for_behavior, 'name': name, 'path': path_for_behavior, 'reason': reason}

                if _is_document_deletion_behavior(name, path_for_behavior, reason):
                    dkey = (usn_val_for_behavior, name, path_for_behavior, reason)
                    if dkey not in behavior_seen_deletions:
                        behavior_seen_deletions.add(dkey)
                        alert = {
                            'alert_type': 'Document Deletion',
                            'source': '$UsnJrnl:$J',
                            'severity': 'suspicious',
                            'usn': usn_val_for_behavior,
                            'time': dt.isoformat(sep=' ') if dt else '',
                            'file_name': name,
                            'full_path': path_for_behavior,
                            'reason': reason,
                            'category': 'Deletion Behavior',
                            'primary_manipulation': 'False',
                            'note': 'Document-like file deletion observed in USN Journal; context alert, not timestamp manipulation verdict.',
                        }
                        document_deletion_alerts.append(alert)
                        behavior_alerts.append(alert)

                g['event_count'] += 1
                update_minmax(g, dt)
                if reason and reason not in g['reason_set'] and len(g['reason_seen']) < 30:
                    g['reason_set'].add(reason); g['reason_seen'].append(reason)
                if len(g['timeline']) < max_timeline_per_target:
                    g['timeline'].append((dt, reason))

                is_basic = _usn_direct_bool_reason(reason, ['BasicInfoChange','Basic_Info_Changed','Basic Info Changed'])
                is_create = _usn_direct_bool_reason(reason, ['FileCreate','File_Created','File Created'])
                is_data = _usn_direct_bool_reason(reason, ['DataExtend','DataOverwrite','DataTruncation','DataAdded','DataOverwritten','DataTruncated','Data_Added','Data_Overwritten'])
                is_close = _usn_direct_bool_reason(reason, ['Close','FileClosed','File_Closed'])
                is_rename = _usn_direct_bool_reason(reason, ['Rename','OldName','NewName','FileMove','File_Move'])
                is_delete = _usn_direct_bool_reason(reason, ['FileDelete','File_Delete','Delete'])
                is_security = _usn_direct_bool_reason(reason, ['SecurityChange','Security_Changed'])
                if is_basic:
                    g['has_basic'] = True; g['basic_count'] += 1
                    if dt and (g.get('basic_max') is None or dt > g['basic_max']): g['basic_max'] = dt
                if is_create:
                    g['has_create'] = True
                    if dt and (g.get('create_min') is None or dt < g['create_min']): g['create_min'] = dt
                if is_data: g['has_data'] = True
                if is_close: g['has_close'] = True
                if is_rename: g['has_rename'] = True
                if is_delete: g['has_delete'] = True
                if is_security: g['has_security'] = True
                if len(g['compact_seq']) < 30:
                    if is_basic: g['compact_seq'].append('BASIC')
                    elif is_rename: g['compact_seq'].append('MOVE')
                    elif is_create: g['compact_seq'].append('CREATE')
                    elif is_data: g['compact_seq'].append('DATA')
                    elif is_close: g['compact_seq'].append('CLOSE')
                    elif is_delete: g['compact_seq'].append('DELETE')
    except Exception as e:
        log(f'[ERROR] Gagal membaca usn_parsed.csv: {e}')
        return False

    log(f'[USN-ONLY CAL] Rows terbaca: {row_count}; target group terbentuk: {len(groups)}')
    profile = (usn_profile or 'auto').strip().lower()
    if profile not in {'auto', 'external', 'controlled'}:
        profile = 'auto'
    if profile == 'auto':
        # v1.0 bias hardening: auto must default to strict real-case/external behavior.
        # Earlier versions inferred 'controlled' from small row counts, which can bias small
        # real cases. Use --usn-profile controlled or OATFD_USN_AUTO_CONTROLLED=1 explicitly
        # for lab-only probable USN promotion.
        auto_controlled = os.environ.get('OATFD_USN_AUTO_CONTROLLED', '0').strip().lower() in {'1','true','yes','on'}
        profile = 'controlled' if auto_controlled else 'external'
    controlled_mode = profile == 'controlled'
    external_mode = profile == 'external'
    log(f'[USN-ONLY CAL] Adaptive profile: {profile} (external=strict comparable; controlled=lab USN-only probable).')
    if row_count == 0 or not groups:
        _write_usn_diag_outputs(out, 'USN-only mode started, but no usable target rows were parsed from usn_parsed.csv. Raw artifact may be unsupported or CSV column mapping is incompatible.')
        log('[USN-ONLY DIAGNOSTIC] Diagnostic output was created because no usable target was found.')
        return True

    matrix = []
    reasoning_rows = []
    suspicious_rows = []
    timeline_rows = []
    sorted_groups = sorted(groups.values(), key=lambda x: (x['name'].lower(), x['frn']))
    log('[USN-ONLY CAL] Mulai scoring terkalibrasi ...')
    for idx, g in enumerate(sorted_groups, start=1):
        if idx % 10000 == 0:
            log(f'[USN-ONLY CAL] Progress scoring: {idx}/{len(sorted_groups)} target ...')
        reason_join = ' | '.join(g['reason_seen'])[:2000]
        has_basic = g['has_basic']; has_create = g['has_create']; has_data = g['has_data']; has_close = g['has_close']
        has_rename = g['has_rename']; has_delete = g['has_delete']; has_security = g['has_security']
        basic_count = g['basic_count']; seq_txt = '>'.join(g['compact_seq'])
        span_seconds = 0
        if g['first_dt'] and g['last_dt']:
            span_seconds = int((g['last_dt'] - g['first_dt']).total_seconds())
        basic_after_create_delay = bool(g.get('create_min') and g.get('basic_max') and (g['basic_max'] - g['create_min']).total_seconds() > 120)
        basic_move_basic = ('BASIC>MOVE>BASIC' in seq_txt) or ('BASIC>MOVE' in seq_txt and basic_count >= 2)
        normal_creation_burst = has_create and has_data and has_close and span_seconds <= 120 and not basic_after_create_delay and basic_count <= 1 and not has_rename

        known_tool_exec = _usn_is_known_timestomp_tool_execution(g['name'], g['parent'], reason_join)
        known_tool_related = _usn_is_known_timestomp_related(g['name'], g['parent'])
        benchmark_target = _usn_is_benchmark_timestamp_target(g['name'], g['parent'])
        system_churn = _usn_is_system_or_app_churn(g['name'], g['parent'], reason_join)
        normal_control = _usn_is_control_normal_or_support(g['name'], g['parent'])
        metadata_pattern = has_basic and (basic_count >= 2 or basic_after_create_delay or basic_move_basic or has_rename)

        score = 0; evidence = []; category = ''
        if known_tool_exec:
            score = 10; evidence.append('Known timestamp-manipulation tool execution/prefetch artifact in USN')
            prediction = 'Suspicious High'; ptype = 'usn_only_confirmed_timestamp_tool_execution'; category = 'Execution of Suspicious Programs'
        elif benchmark_target and metadata_pattern:
            # v1.0: avoid label leakage in external USN-only benchmarks.
            # A file name containing terms such as "NewFileTime" or "Manipulation" is useful as contextual
            # benchmark metadata, but it must not be promoted to high-confidence manipulation without
            # independent evidence such as tool execution, MFT timestamp values, or $LogFile timestamp transition.
            score = 8; evidence.append('Benchmark-labeled timestamp target with USN BasicInfoChange metadata pattern; kept as Need Review to avoid label leakage')
            if basic_count >= 2: evidence.append('Repeated BasicInfoChange events')
            if basic_after_create_delay: evidence.append('BasicInfoChange occurs >120s after FileCreate event')
            if basic_move_basic: evidence.append('BasicInfoChange/Move/BasicInfoChange grammar')
            prediction = 'Need Review'; ptype = 'usn_only_benchmark_target_metadata_change_candidate'; category = 'USN Metadata Change Candidate'
        else:
            if known_tool_related:
                score += 3; evidence.append('Known timestamp-tool related file/config activity; contextual evidence only')
            if has_basic:
                score += 1; evidence.append('USN contains BasicInfoChange metadata event')
            if basic_count >= 2:
                score += 2; evidence.append('Repeated BasicInfoChange events')
            if basic_after_create_delay:
                score += 2; evidence.append('BasicInfoChange occurs >120s after FileCreate event')
            if basic_move_basic:
                score += 2; evidence.append('BasicInfoChange/Move/BasicInfoChange grammar')
            if has_rename and has_basic:
                score += 1; evidence.append('Rename/Move correlated with BasicInfoChange')
            if has_security and not has_basic:
                score = max(0, score - 1)
            if normal_creation_burst:
                score = max(0, score - 4); evidence.append('Normal creation/write/close burst guard')
            if system_churn and not known_tool_related:
                score = max(0, score - 5); evidence.append('System/cache/temp/update churn guard; BasicInfoChange not treated as manipulation in USN-only mode')
            if normal_control and not known_tool_related:
                score = max(0, score - 5); evidence.append('Normal-control/support/temp guard; not promoted in controlled USN-only mode')
            if controlled_mode and score >= 5 and has_basic and not system_churn and not normal_control:
                allow_controlled_high = os.environ.get('OATFD_USN_CONTROLLED_HIGH', '0').strip().lower() in {'1','true','yes','on'}
                if allow_controlled_high:
                    prediction = 'Suspicious High'; ptype = 'controlled_usn_probable_timestamp_manipulation'; category = 'Probable Timestamp Manipulation'
                    evidence.append('Controlled USN-only profile: promoted by explicit OATFD_USN_CONTROLLED_HIGH=1; confirm with MFT/$LogFile when available')
                else:
                    prediction = 'Need Review'; ptype = 'controlled_usn_probable_review_bias_hardened'; category = 'Probable Timestamp Manipulation'
                    evidence.append('Bias-hardened controlled USN-only profile: strong BasicInfoChange kept as Need Review unless explicitly promoted; MFT/$LogFile required for high confidence')
            elif score >= 4 and not system_churn:
                prediction = 'Need Review'; ptype = 'usn_only_strong_metadata_change_candidate'; category = 'USN Metadata Change Candidate'
            elif has_basic and not normal_creation_burst and not system_churn:
                prediction = 'Need Review'; ptype = 'usn_only_basicinfo_metadata_change_candidate'; category = 'USN Metadata Change Candidate'
            elif known_tool_related:
                prediction = 'Need Review'; ptype = 'usn_only_tool_related_context_activity'; category = 'Tool Context Activity'
            else:
                prediction = 'Normal'; ptype = 'usn_only_normal_or_system_churn_event_grammar' if (system_churn or normal_control) else 'usn_only_normal_event_grammar'; category = ''
        if not evidence:
            evidence = ['No timestamp-specific USN grammar beyond normal file activity']
        row = {
            'scenario_id':'USN_ONLY', 'target_name':g['name'], 'prediction':prediction, 'prediction_type':ptype, 'score':str(score), 'usn_profile':profile,
            'operation_type':'artifact_limited_usn_event_grammar_calibrated', 'operation_normality_score':'1' if (normal_creation_burst or system_churn) else '0',
            'direct_manipulation_score':str(score), 'artifact_confidence_score':'2', 'decision_margin':str(score - (1 if (normal_creation_burst or system_churn) else 0)),
            'expected_pattern_match':'Unknown', 'direct_manipulation_evidence':'Yes' if prediction == 'Suspicious High' else 'No',
            'anchor_consistency':'Unavailable', 'delayed_basicinfo':'Yes' if basic_after_create_delay else 'No',
            'uniform_mace_far_from_anchor':'Unavailable', 'valid_logfile_transition':'Unavailable',
            'event_count':str(g['event_count']), 'basicinfo_count':str(basic_count), 'has_rename_move':'Yes' if has_rename else 'No',
            'has_delete':'Yes' if has_delete else 'No', 'time_span_seconds':str(span_seconds), 'frn':g['frn'], 'parent_context':g['parent'],
            'known_tool_execution':'Yes' if known_tool_exec else 'No', 'known_tool_related':'Yes' if known_tool_related else 'No',
            'benchmark_target_label':'Yes' if benchmark_target else 'No', 'system_churn_guard':'Yes' if system_churn else 'No', 'normal_control_guard':'Yes' if normal_control else 'No',
            'reasons':'; '.join(evidence), 'reason_sequence':seq_txt[:500], 'all_usn_reasons':reason_join,
        }
        matrix.append(row)
        reasoning_rows.append({'target_name':g['name'], 'prediction':prediction, 'prediction_type':ptype, 'score':str(score), 'reasoning':'; '.join(evidence) + ' | USN reasons=' + reason_join[:900], 'key_relative':g['parent'], 'key_mft':g['frn'], 'key_prefetch':'Unavailable'})
        if prediction != 'Normal':
            for dt, reason in g['timeline'][:max_timeline_per_target]:
                timeline_rows.append({'Time': dt.isoformat(sep=' ') if dt else '', 'TargetName':g['name'], 'Event':reason, 'Prediction':prediction, 'Detail':'USN-only calibrated event'})
        if str(prediction).startswith('Suspicious'):
            suspicious_rows.append({'Category':category, 'TargetName':g['name'], 'Prediction':prediction, 'PredictionType':ptype, 'Score':str(score), 'Evidence':'; '.join(evidence), 'LSNTransitionCandidate':'Unavailable', 'LSNTransitionStrength':'0', 'LSNTransitionReasons':'USN-only mode; $LogFile unavailable', 'MFT_Record_LSN':'', 'LogFile_LSN_Values':'', 'LSNExactMatch':'No', 'LSNNearMatch':'No', 'LowLevelCandidate':'USN BasicInfoChange' if has_basic else ('Known Tool Execution' if known_tool_exec else ''), 'LowLevelStrength':str(score), 'LowLevelReasons':reason_join[:1000], 'LowLevelFutureTimestamp':'Unavailable', 'LowLevelFutureFields':'', 'LowLevelSIFNDelta':'Unavailable', 'LowLevelSIFNDeltaPairs':'', 'LowLevelSIFNDeltaNonAccess':'Unavailable', 'LowLevelSIFNAccessedOnly':'Unavailable', 'LowLevelFutureNonAccess':'Unavailable', 'LowLevelFutureAccessedOnly':'Unavailable', 'NearTimeUniformMACECore':'Unavailable', 'LowLevelMetadataOnlyGrammar':'Yes' if has_basic else 'No', 'MutationCore':'Yes' if prediction == 'Suspicious High' else 'No', 'NormalCreationGuard':'Yes' if normal_creation_burst else 'No', 'ScoringRuleVersion':'OATFD_v1_0_causal_timeline_guard_usn_only', 'LowLevelFractionPattern':'Unavailable', 'MFT_SI_Created':'', 'MFT_SI_Modified':'', 'MFT_SI_Accessed':'', 'MFT_SI_EntryModified':'', 'USN_Support':'Yes', 'LogFile_Support':'No', 'PrefetchBestCandidate':'', 'PrefetchCandidates':'', 'LNK_Windows_Hits':'0', 'LNK_Office_Hits':'0', 'ToolAttributionLevel':'tool_execution' if known_tool_exec else 'not_available', 'Caution':'USN-only/artifact-limited. External profile is NLT-comparable; controlled profile may promote strong metadata patterns to probable manipulation, but MFT/$LogFile is required for final confirmation.'})

    def write_csv2(path, data, fields):
        with path.open('w', encoding='utf-8-sig', newline='') as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
            w.writeheader(); w.writerows(data)
    matrix_fields = []
    for r in matrix:
        for k in r.keys():
            if k not in matrix_fields: matrix_fields.append(k)
    if not matrix_fields:
        matrix_fields = ['scenario_id','target_name','prediction','prediction_type','score','reasons']
    log('[USN-ONLY CAL] Menulis output CSV ...')

    # v1.0: write NLT-like behavior alerts in USN-only direct mode.
    behavior_fields = [
        'alert_type', 'source', 'severity', 'usn', 'time',
        'previous_usn', 'current_usn', 'previous_time', 'current_time', 'reversal_minutes',
        'file_name', 'full_path', 'reason',
        'previous_file', 'current_file', 'previous_path', 'current_path', 'previous_reason', 'current_reason',
        'category', 'primary_manipulation', 'note'
    ]
    system_fields = [
        'alert_type', 'source', 'severity', 'previous_usn', 'current_usn', 'previous_time', 'current_time',
        'reversal_minutes', 'previous_file', 'current_file', 'previous_path', 'current_path',
        'previous_reason', 'current_reason', 'category', 'primary_manipulation', 'note'
    ]
    deletion_fields = ['alert_type', 'source', 'severity', 'usn', 'time', 'file_name', 'full_path', 'reason', 'category', 'primary_manipulation', 'note']
    write_csv2(out/'behavior_alerts.csv', behavior_alerts, behavior_fields)
    write_csv2(out/'system_time_anomalies.csv', system_time_anomalies, system_fields)
    write_csv2(out/'document_deletion_alerts.csv', document_deletion_alerts, deletion_fields)

    for a in behavior_alerts:
        if a.get('alert_type') == 'System Time Reversal':
            timeline_rows.append({
                'Time': a.get('current_time', ''),
                'TargetName': 'SYSTEM_TIME',
                'Event': 'Behavior Alert - System Time Reversal',
                'Prediction': 'Behavior Alert',
                'Detail': f"{a.get('previous_time','')} -> {a.get('current_time','')} reversal_minutes={a.get('reversal_minutes','')} severity={a.get('severity','')}"
            })
        elif a.get('alert_type') == 'Document Deletion':
            timeline_rows.append({
                'Time': a.get('time', ''),
                'TargetName': a.get('file_name', ''),
                'Event': 'Behavior Alert - Document Deletion',
                'Prediction': 'Behavior Alert',
                'Detail': a.get('note', '')
            })

    write_csv2(out/'detection_matrix.csv', matrix, matrix_fields)
    write_csv2(out/'case_reasoning.csv', reasoning_rows, ['target_name','prediction','prediction_type','score','reasoning','key_relative','key_mft','key_prefetch'])
    suspicious_fields = ['Category','TargetName','Prediction','PredictionType','Score','Evidence','LSNTransitionCandidate','LSNTransitionStrength','LSNTransitionReasons','MFT_Record_LSN','LogFile_LSN_Values','LSNExactMatch','LSNNearMatch','LowLevelCandidate','LowLevelStrength','LowLevelReasons','LowLevelFutureTimestamp','LowLevelFutureFields','LowLevelSIFNDelta','LowLevelSIFNDeltaPairs','LowLevelSIFNDeltaNonAccess','LowLevelSIFNAccessedOnly','LowLevelFutureNonAccess','LowLevelFutureAccessedOnly','NearTimeUniformMACECore','LowLevelMetadataOnlyGrammar','MutationCore','NormalCreationGuard','ScoringRuleVersion','LowLevelFractionPattern','MFT_SI_Created','MFT_SI_Modified','MFT_SI_Accessed','MFT_SI_EntryModified','USN_Support','LogFile_Support','PrefetchBestCandidate','PrefetchCandidates','LNK_Windows_Hits','LNK_Office_Hits','ToolAttributionLevel','Caution']
    # suspicious_behavior_detection.csv will be rewritten below as strict high-confidence only.
    write_csv2(out/'suspicious_behavior_detection.csv', suspicious_rows, suspicious_fields)
    write_csv2(out/'timeline_events.csv', timeline_rows, ['Time','TargetName','Event','Prediction','Detail'])
    normal_count = sum(1 for r in matrix if r.get('prediction') == 'Normal')
    need_count = sum(1 for r in matrix if r.get('prediction') == 'Need Review')
    susp_count = sum(1 for r in matrix if str(r.get('prediction','')) == 'Suspicious High')

    # v1.0 user-facing exports: suspicious_behavior_detection.csv is intentionally strict
    # and may only contain one row for Jung Oh (comparable with NTFS Log Tracker). To avoid
    # the result looking empty, export candidate rows separately and mirror all outputs
    # to an obvious folder. This does not change the algorithm; it fixes reporting.
    matrix = _apply_strict_reporting_guards(matrix)
    # Rewrite matrix after applying reporting guards.
    write_csv2(out/'detection_matrix.csv', matrix, matrix_fields)
    high_conf_rows = [r for r in matrix if str(r.get('prediction','')) == 'Suspicious High']
    need_review_rows = [r for r in matrix if r.get('prediction') == 'Need Review']
    write_csv2(out/'high_confidence_suspicious.csv', high_conf_rows, matrix_fields)
    write_csv2(out/'need_review_candidates.csv', need_review_rows, matrix_fields)
    # Strict user-facing suspicious behavior = high-confidence only.
    suspicious_high = []
    for r in high_conf_rows:
        suspicious_high.append({
            'Category':'High Confidence Suspicious',
            'TargetName':r.get('target_name',''),
            'Prediction':r.get('prediction',''),
            'PredictionType':r.get('prediction_type',''),
            'Score':r.get('score',''),
            'Evidence':r.get('reasons',''),
            'LSNTransitionCandidate':'Unavailable',
            'LSNTransitionStrength':'0',
            'LSNTransitionReasons':'USN-only/artifact-limited mode or unavailable $LogFile',
            'MFT_Record_LSN':'',
            'LogFile_LSN_Values':'',
            'LSNExactMatch':'No',
            'LSNNearMatch':'No',
            'LowLevelCandidate':'Known Tool Execution' if r.get('known_tool_execution') == 'Yes' else 'USN candidate',
            'LowLevelStrength':r.get('score',''),
            'LowLevelReasons':r.get('all_usn_reasons', r.get('reason_sequence','')),
            'LowLevelFutureTimestamp':'Unavailable',
            'LowLevelFutureFields':'',
            'LowLevelSIFNDelta':'Unavailable',
            'LowLevelSIFNDeltaPairs':'',
            'LowLevelSIFNDeltaNonAccess':'Unavailable',
            'LowLevelSIFNAccessedOnly':'Unavailable',
            'LowLevelFutureNonAccess':'Unavailable',
            'LowLevelFutureAccessedOnly':'Unavailable',
            'NearTimeUniformMACECore':'Unavailable',
            'LowLevelMetadataOnlyGrammar':'Yes' if 'basicinfo' in str(r.get('all_usn_reasons','')).lower() else 'No',
            'MutationCore':'Yes',
            'NormalCreationGuard':'No',
            'ScoringRuleVersion':'OATFD_v1_0_causal_timeline_guard_usn_only',
            'LowLevelFractionPattern':'Unavailable',
            'MFT_SI_Created':'', 'MFT_SI_Modified':'', 'MFT_SI_Accessed':'', 'MFT_SI_EntryModified':'',
            'USN_Support':'Yes', 'LogFile_Support':'No', 'PrefetchBestCandidate':'', 'PrefetchCandidates':'',
            'LNK_Windows_Hits':'0', 'LNK_Office_Hits':'0', 'ToolAttributionLevel':'tool_execution' if r.get('known_tool_execution') == 'Yes' else 'artifact_limited',
            'Caution':'High-confidence only. Need Review candidates are exported separately.'
        })
    write_csv2(out/'suspicious_behavior_detection.csv', suspicious_high, suspicious_fields)

    unique_keys = {_logical_key(r) for r in matrix}
    unique_high_keys = {_logical_key(r) for r in high_conf_rows}
    unique_need_keys = {_logical_key(r) for r in need_review_rows}
    unique_summary_rows = [
        {'metric':'raw_rows_total','value':str(len(matrix))},
        {'metric':'raw_high_confidence_rows','value':str(len(high_conf_rows))},
        {'metric':'raw_need_review_rows','value':str(len(need_review_rows))},
        {'metric':'raw_normal_rows','value':str(sum(1 for r in matrix if r.get('prediction') == 'Normal'))},
        {'metric':'unique_logical_total','value':str(len(unique_keys))},
        {'metric':'unique_high_confidence_logical','value':str(len(unique_high_keys))},
        {'metric':'unique_need_review_logical','value':str(len(unique_need_keys))},
    ]
    write_csv2(out/'unique_detection_summary.csv', unique_summary_rows, ['metric','value'])

    comparison_rows = [
        {'field':'NTFS Log Tracker comparable suspicious behavior','value':'External benchmark: usually tool-execution only; compare high_confidence_suspicious.csv.'},
        {'field':'OATFD comparable high-confidence suspicious','value':str(susp_count)},
        {'field':'OATFD USN metadata-change candidates / Need Review','value':str(need_count)},
        {'field':'Interpretation','value':'USN-only: Need Review rows are candidates, not confirmed timestamp manipulation without MFT/$LogFile.'},
    ]
    write_csv2(out/'comparison_ready_summary.csv', comparison_rows, ['field','value'])

    summary = [
        {'field':'target_count','value':str(len(matrix))},
        {'field':'manipulation_count','value':str(susp_count)},
        {'field':'suspicious_count','value':str(susp_count)},
        {'field':'need_review_count','value':str(need_count)},
        {'field':'normal_count','value':str(normal_count)},
        {'field':'excluded_count','value':'0'},
        {'field':'behavior_alert_count','value':str(len(behavior_alerts))},
        {'field':'system_time_anomaly_count','value':str(len(system_time_anomalies))},
        {'field':'document_deletion_alert_count','value':str(len(document_deletion_alerts))},
        {'field':'artifact_mode','value':'Adaptive USN-only profile: ' + profile},
        {'field':'rule_version','value':'OATFD_v1_0_causal_timeline_guard_usn_only'},
        {'field':'raw_usn_rows','value':str(row_count)},
        {'field':'note','value':'Auto profile: strict/external defaults are used to avoid small-case bias. Use --usn-profile controlled plus OATFD_USN_CONTROLLED_HIGH=1 only for lab benchmarks. Open need_review_candidates.csv for candidates.'},
    ]
    write_csv2(out/'run_summary.csv', summary, ['field','value'])

    ready = case/'OUTPUT_USN_BENCHMARK'
    ensure(ready)
    for fn in ['run_summary.csv','comparison_ready_summary.csv','high_confidence_suspicious.csv','need_review_candidates.csv','suspicious_behavior_detection.csv','detection_matrix.csv','case_reasoning.csv','timeline_events.csv','behavior_alerts.csv','system_time_anomalies.csv','document_deletion_alerts.csv']:
        src = out/fn
        if src.exists():
            try:
                shutil.copy2(src, ready/fn)
            except Exception as e:
                log(f'[WARN] Gagal menyalin {fn} ke OUTPUT_USN_BENCHMARK: {e}')
    (ready/'README_HASIL_USN_BENCHMARK.txt').write_text(
        """OATFD v1.0 Causal-Timeline Guard / I30 Parser Compatibility Policy
1. high_confidence_suspicious.csv = hasil high-confidence sesuai profil bukti yang tersedia.
2. suspicious_behavior_detection.csv = sama, hanya high-confidence suspicious.
3. need_review_candidates.csv = kandidat metadata-change USN-only, bukan bukti final manipulasi timestamp.
4. detection_matrix.csv = seluruh target/group yang dianalisis.
5. run_summary.csv = ringkasan angka.
6. Universal mode: aplikasi tetap berjalan walau hanya tersedia satu artefak; missing artifact = unavailable evidence, bukan error.
7. behavior_alerts.csv, system_time_anomalies.csv, dan document_deletion_alerts.csv berisi alert perilaku non-primary dari USN-only mode.
""",
        encoding='utf-8'
    )
    log(f'[USN-ONLY DIRECT] Output dibuat: targets={len(matrix)}, suspicious={susp_count}, need_review={need_count}, normal={normal_count}, behavior_alerts={len(behavior_alerts)}, system_time={len(system_time_anomalies)}, deletion={len(document_deletion_alerts)}, raw_usn_rows={row_count}')
    log(f'[OUTPUT READY] Buka folder: {ready}')
    return True

def _clear_unselected_inputs(case: Path, mft_file="", usn_file="", prefetch_dir="", raw_logfile_file="", logfile_csv="", win_dir="", office_dir="", i30_csv=""):
    """Remove stale parsed CSV for artifacts not selected in this run.

    Safety fix v1.0:
    - If the user does not explicitly select any artifact in the GUI/CLI, do NOT
      delete existing INPUT_PYTHON CSV files. This protects the common workflow
      where parsed CSVs are already placed in INPUT_PYTHON and the user presses
      Detect + Timeline directly.
    - Cleanup is only applied when at least one artifact is explicitly selected;
      then unselected artifact CSVs may be removed to avoid mixing datasets.
    """
    selected_any = any([
        bool(mft_file), bool(usn_file), bool(prefetch_dir), bool(raw_logfile_file or logfile_csv), bool(win_dir), bool(office_dir), bool(i30_csv)
    ])
    if not selected_any:
        log("[SKIP CLEAN] No explicit artifact was selected; the CSV files already present in INPUT_PYTHON were preserved.")
        return

    mapping = [
        (bool(mft_file), "mft_parsed.csv"),
        (bool(usn_file), "usn_parsed.csv"),
        (bool(prefetch_dir), "prefetch_all_parsed.csv"),
        (bool(raw_logfile_file or logfile_csv), "logfile_parsed.csv"),
        (bool(win_dir), "lnk_windows_recent_parsed.csv"),
        (bool(office_dir), "lnk_office_recent_parsed.csv"),
        (bool(i30_csv), "i30_parsed.csv"),
    ]
    for selected, fn in mapping:
        if not selected:
            remove_if_exists(case/"INPUT_PYTHON"/fn)


def detect(case: Path, all_files=True, keyword="", mft_file="", usn_file="", prefetch_dir="", raw_logfile_file="", logfile_csv="", win_dir="", office_dir="", i30_csv="", force_usn_only=False, usn_profile="auto", clear_unselected_inputs=False):
    case_dirs(case)
    # v1.0: Target Path Keyword now controls scope explicitly.
    # Blank / * / ALL / FULL_SCOPE means true all-file detection over the loaded MFT/artifacts.
    # Use a keyword such as "Percobaan Ketujuh" only when you intentionally want to restrict scope.
    if (keyword or '').strip().lower() in {"*", "all", "all_files", "full_scope", "full-scope", "volume", "no_filter", "nofilter", "semua"}:
        log("[SCOPE] Full-scope/all-file mode active: Target Path Keyword disabled; all MFT targets in input will be analysed.")
        keyword = ""
    elif not (keyword or '').strip():
        log("[SCOPE] Target Path Keyword is empty: full-scope / all-file detection is active. No automatic case-folder-name filter is applied.")
    if clear_unselected_inputs and not force_usn_only:
        log("[MODE] Universal Artifact Mode: safe cleanup is active; old CSV files are removed only when an artifact has been explicitly selected.")
        _clear_unselected_inputs(case, mft_file, usn_file, prefetch_dir, raw_logfile_file, logfile_csv, win_dir, office_dir, i30_csv)

    # OATFD v1.0: FORCE/BENCHMARK USN-only mode for external benchmark datasets such as Jung Oh.
    # This mode ignores MFT/LogFile/Prefetch/LNK even when Auto Fill found stale or neighboring
    # artifacts in the selected folder. The goal is benchmarking a USN-only dataset fairly:
    # parse/import the selected raw/CSV USN, then immediately generate USN-only evidence outputs.
    if force_usn_only:
        log("[MODE] FORCE USN-only benchmark mode active: only $UsnJrnl_$J/USN CSV will be used; all other artifacts are ignored.")
        for fn in [
            "mft_parsed.csv", "prefetch_all_parsed.csv", "logfile_parsed.csv",
            "lnk_windows_recent_parsed.csv", "lnk_office_recent_parsed.csv", "i30_parsed.csv",
        ]:
            remove_if_exists(case/"INPUT_PYTHON"/fn)
        chosen_usn = usn_file
        if not chosen_usn:
            found = find_file(case, ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*", "usn_parsed.csv", "usn_parsed*.csv", "NLT_UsnJrnl*.csv", "*UsnJrnl*.csv", "*USN*.csv"])
            chosen_usn = str(found) if found else ""
        if not chosen_usn:
            log("[ERROR] FORCE USN-only failed: the $UsnJrnl_$J/.bin file or a USN CSV was not found in the case folder.")
            empty_usn(case)
            return usn_only_direct_detect(case, keyword, usn_profile=usn_profile)
        parse_usn(case, chosen_usn)
        rows = count_csv_rows(case/"INPUT_PYTHON"/"usn_parsed.csv")
        log(f"[MODE] FORCE USN-only: usn_parsed.csv is ready ({rows} rows). The full cross-artifact engine was skipped.")
        return usn_only_direct_detect(case, keyword, usn_profile=usn_profile)

    # OATFD v1.0: true Jung Oh raw-USN-only mode.
    # If only --usn-file is selected, remove stale parsed CSV from previous multi-artifact runs.
    only_usn_selected = bool(usn_file) and not any([mft_file, prefetch_dir, raw_logfile_file, logfile_csv, win_dir, office_dir, i30_csv])
    if only_usn_selected:
        log("[MODE] USN-only clean mode active: only $UsnJrnl_$J artifacts will be used; stale artifacts in INPUT_PYTHON are cleared.")
        for fn in [
            "mft_parsed.csv", "prefetch_all_parsed.csv", "logfile_parsed.csv",
            "lnk_windows_recent_parsed.csv", "lnk_office_recent_parsed.csv", "i30_parsed.csv",
        ]:
            remove_if_exists(case/"INPUT_PYTHON"/fn)

    # Detect can start directly from raw/CSV artifacts. If the user selects only $UsnJrnl_$J(.bin)
    # and clicks Detect + Timeline, parse/import it first.
    if usn_file:
        parse_usn(case, usn_file)
    else:
        existing_usn = find_file(case, ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*", "usn_parsed.csv", "usn_parsed*.csv", "NLT_UsnJrnl*.csv", "*UsnJrnl*.csv", "*USN*.csv"])
        if existing_usn and not (case/"INPUT_PYTHON"/"usn_parsed.csv").exists():
            parse_usn(case, str(existing_usn))
    if mft_file and not (case/"INPUT_PYTHON"/"mft_parsed.csv").exists():
        parse_mft(case, mft_file)
    if prefetch_dir and not (case/"INPUT_PYTHON"/"prefetch_all_parsed.csv").exists():
        parse_prefetch(case, prefetch_dir)

    # v1.0 no-freeze rule: if a parsed LogFile CSV is available, use it first and
    # DO NOT re-run raw LogFileParser during Detect + Timeline. Raw $LogFile parsing
    # can be slow/hang on some cases; it should be explicit via Parse raw $LogFile
    # or used only when no CSV is selected/found.
    if logfile_csv and not (case/"INPUT_PYTHON"/"logfile_parsed.csv").exists():
        log("[FAST] A $LogFile CSV was selected; raw $LogFile parsing was skipped during Detect + Timeline to avoid freezing.")
        import_logfile_csv(case, logfile_csv)
    elif raw_logfile_file and not (case/"INPUT_PYTHON"/"logfile_parsed.csv").exists():
        log("[RAW-LOGFILE] No $LogFile CSV is available; attempting raw $LogFile parsing with a no-freeze timeout.")
        parse_raw_logfile(case, raw_logfile_file)
    if i30_csv and not (case/"INPUT_PYTHON"/"i30_parsed.csv").exists():
        import_i30_csv(case, i30_csv)
    # v1.0: Detect + Timeline should recover existing primary artifact CSVs automatically.
    # This prevents accidental LNK-only output when the user selected Recent folders but did not
    # press Use Existing CSV or did not manually fill MFT/USN/LogFile fields.
    auto_import_existing_primary_artifacts(case)

    # Missing artifacts are unavailable evidence, not fatal errors.
    if not (case/"INPUT_PYTHON"/"mft_parsed.csv").exists(): empty_mft(case)
    if not (case/"INPUT_PYTHON"/"usn_parsed.csv").exists(): empty_usn(case)
    if not (case/"INPUT_PYTHON"/"prefetch_all_parsed.csv").exists(): empty_prefetch(case)
    if not (case/"INPUT_PYTHON"/"logfile_parsed.csv").exists(): empty_log(case)
    if not (case/"INPUT_PYTHON"/"i30_parsed.csv").exists(): empty_i30(case)
    available = [x for x in ["mft_parsed.csv", "usn_parsed.csv", "prefetch_all_parsed.csv", "logfile_parsed.csv", "lnk_windows_recent_parsed.csv", "lnk_office_recent_parsed.csv", "i30_parsed.csv"] if (case/"INPUT_PYTHON"/x).exists()]
    log("[INFO] Artifact-flexible detect. Available INPUT_PYTHON CSV: " + (", ".join(available) if available else "none"))

    # v1.0: for true USN-only cases (Jung Oh folders containing only $UsnJrnl_$J.bin),
    # generate outputs directly. This avoids the full cross-artifact matrix engine becoming slow
    # on large USN-only journals and guarantees visual_report can read the output.
    non_empty_inputs = []
    for fn in ["mft_parsed.csv", "usn_parsed.csv", "prefetch_all_parsed.csv", "logfile_parsed.csv", "lnk_windows_recent_parsed.csv", "lnk_office_recent_parsed.csv", "i30_parsed.csv"]:
        p = case/"INPUT_PYTHON"/fn
        if p.exists() and count_csv_rows(p) > 0:
            non_empty_inputs.append(fn)
    if non_empty_inputs == ["usn_parsed.csv"]:
        log("[MODE] USN-only evidence output is active: only usn_parsed.csv contains data; the full matrix engine was skipped.")
        return usn_only_direct_detect(case, keyword, usn_profile=usn_profile)

    # v1.0 no-freeze guard: if a very large raw USN was selected and the GUI did not
    # pass --force-usn-only (for example user pressed the old Detect button), do not let
    # the full cross-artifact engine run silently for a long time. Generate benchmark
    # USN-only output instead. For full multi-artifact analysis, uncheck Benchmark USN-only
    # and use a smaller target keyword, or run the full mode intentionally.
    usn_rows_current = count_csv_rows(case/"INPUT_PYTHON"/"usn_parsed.csv")
    if usn_file and usn_rows_current >= 100000:
        log(f"[MODE] Large-USN no-freeze guard is active ({usn_rows_current} rows). The full engine was skipped; the output was created in USN-only benchmark mode.")
        return usn_only_direct_detect(case, keyword, usn_profile=usn_profile)

    if not MINI_NLT.exists():
        log(f"[ERROR] mini_nlt_prototype.py is missing: {MINI_NLT}")
        return False
    cmd = [sys.executable, str(MINI_NLT), "--input", str(case/"INPUT_PYTHON"), "--detect-only"]
    if all_files:
        cmd.append("--all-files")
    if keyword:
        cmd += ["--target-path-keyword", keyword]
    cmd += ["--tool-roots", str(TOOLS_DIR)]
    rc = run(cmd)
    if rc != 0:
        log(f"[WARN] The full matrix engine failed (exit={rc}). The universal fallback will try to create a conservative output from the available artifacts.")
        return generic_artifact_fallback_detect(case, keyword)
    matrix_path = case/"OATFD_OUTPUT"/"detection_matrix.csv"
    matrix_rows = count_csv_rows(matrix_path)
    if matrix_rows == 0:
        log("[WARN] The full matrix engine finished, but detection_matrix.csv is empty. The universal no-empty fallback is active.")
        return generic_artifact_fallback_detect(case, keyword)

    # v1.0 guard: if the matrix consists only of Recent .lnk files, the run did not perform
    # true file-level detection. Try to auto-import primary artifacts and rerun once.
    if _matrix_is_lnk_only(matrix_path):
        log("[WARN] The output contains only LNK context rows. This is not a target-file evaluation. Attempting to auto-import MFT/USN/LogFile CSV files from the case folder and rerun the full engine.")
        imported = auto_import_existing_primary_artifacts(case)
        primary_counts = {fn: count_csv_rows(case/"INPUT_PYTHON"/fn) for fn in ["mft_parsed.csv", "usn_parsed.csv", "logfile_parsed.csv", "prefetch_all_parsed.csv"] if (case/"INPUT_PYTHON"/fn).exists()}
        if imported or any(v > 0 for v in primary_counts.values()):
            log("[RERUN] Primary artifact rows available: " + ", ".join(f"{k}={v}" for k,v in primary_counts.items()))
            rc2 = run(cmd)
            if rc2 == 0 and count_csv_rows(matrix_path) > 0 and not _matrix_is_lnk_only(matrix_path):
                matrix_rows = count_csv_rows(matrix_path)
                log(f"[OK] Rerun berhasil; output file-level rows={matrix_rows}")
            else:
                log("[WARN] The rerun is still LNK-only or empty. Diagnostic output will still be created; make sure the MFT/USN/LogFile CSV files are present in the case folder or select the artifact files manually.")
        else:
            log("[DIAG] No non-empty MFT/USN/LogFile/Prefetch CSV files were found. LNK-only results are valid only as a context check, not as target-file detection.")

    # If the full engine produced targets, make sure v1.0 reporting files are also present.
    postprocess_standard_reports(case)
    log(f"[OK] Full matrix engine output rows={count_csv_rows(matrix_path)}")
    return True

def status(case: Path, mft_file="", usn_file="", prefetch_dir="", raw_logfile_file="", logfile_csv="", win_dir="", office_dir="", i30_csv=""):
    case_dirs(case)
    pairs = [
        ("$MFT raw", Path(mft_file) if mft_file else find_file(case, ["$MFT", "MFT"])),
        ("$UsnJrnl_$J raw", Path(usn_file) if usn_file else find_file(case, ["$UsnJrnl_$J", "$UsnJrnl:$J", "$J", "$UsnJrnl_$J.bin", "$UsnJrnl-$J.bin", "$J.bin", "*UsnJrnl*.bin", "*USN*.bin", "*UsnJrnl*", "*USN*"])),
        ("Prefetch folder", Path(prefetch_dir) if prefetch_dir else find_dir(case, ["Prefetch"])),
        ("raw $LogFile", Path(raw_logfile_file) if raw_logfile_file else find_file(case, ["$LogFile", "LogFile"])),
        ("$LogFile CSV", Path(logfile_csv) if logfile_csv else find_file(case, ["LogFileJoined.csv", "LogFile.csv", "logfile_parsed.csv", "NLT_LogFile*.csv"])),
        ("LNK Windows folder", Path(win_dir) if win_dir else find_dir(case, ["LNK_WindowsRecent", "WindowsRecent"])),
        ("LNK Office folder", Path(office_dir) if office_dir else find_dir(case, ["LNK_OfficeRecent", "OfficeRecent"])),
        ("$I30 CSV", Path(i30_csv) if i30_csv else find_file(case, ["i30_parsed.csv", "i30_all_physical.csv", "i30_all*.csv", "i30_percobaan*.csv", "*i30*.csv", "*I30*.csv"])),
        ("mft_parsed.csv", case/"INPUT_PYTHON"/"mft_parsed.csv"),
        ("usn_parsed.csv", case/"INPUT_PYTHON"/"usn_parsed.csv"),
        ("prefetch_all_parsed.csv", case/"INPUT_PYTHON"/"prefetch_all_parsed.csv"),
        ("logfile_parsed.csv", case/"INPUT_PYTHON"/"logfile_parsed.csv"),
        ("i30_parsed.csv", case/"INPUT_PYTHON"/"i30_parsed.csv"),
        ("timeline_events.csv", case/"OATFD_OUTPUT"/"timeline_events.csv"),
        ("detection_matrix.csv", case/"OATFD_OUTPUT"/"detection_matrix.csv"),
    ]
    log("[STATUS]")
    for label, p in pairs:
        exists = bool(p and p.exists())
        log(f"{'[FOUND]' if exists else '[MISS]'} {label}: {p if p else ''}")

def parse_all(case, mft="", usn="", pf="", rawlog="", logcsv="", win="", office="", i30="", all_files=True, keyword=""):
    parse_mft(case, mft)
    parse_usn(case, usn)
    parse_prefetch(case, pf)
    parse_lnk(case, win, office)
    import_i30_csv(case, i30)
    if rawlog:
        parse_raw_logfile(case, rawlog)
    elif logcsv:
        import_logfile_csv(case, logcsv)
    else:
        # Prefer raw $LogFile if found, otherwise existing CSV, otherwise placeholder.
        if find_file(case, ["$LogFile", "LogFile"]):
            parse_raw_logfile(case, "")
        elif find_file(case, ["LogFileJoined.csv", "LogFile.csv", "logfile_parsed.csv", "NLT_LogFile*.csv"]):
            import_logfile_csv(case, "")
        else:
            empty_log(case)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--mft-file", default="")
    ap.add_argument("--usn-file", default="")
    ap.add_argument("--prefetch-dir", default="")
    ap.add_argument("--lnk-windows-dir", default="")
    ap.add_argument("--lnk-office-dir", default="")
    ap.add_argument("--raw-logfile-file", default="")
    ap.add_argument("--logfile-csv", default="")
    ap.add_argument("--i30-csv", default="")
    ap.add_argument("--target-path-keyword", default="")
    ap.add_argument("--all-files", action="store_true")
    ap.add_argument("--timezone", default="7.00")
    ap.add_argument("--mft-record-size", default="1024")
    ap.add_argument("--force-usn-only", action="store_true", help="Ignore all other artifacts and generate USN-only direct output; useful for explicit external USN-only benchmark datasets.")
    ap.add_argument("--clear-unselected-inputs", action="store_true", help="Universal mode: remove stale INPUT_PYTHON CSV for artifacts not selected in this run.")
    ap.add_argument("--usn-profile", choices=["auto", "external", "controlled"], default="auto", help="USN-only scoring profile: external=strict NLT-comparable, controlled=small lab dataset probable detection, auto=choose by size.")
    ap.add_argument("action", choices=["status", "parse-mft", "parse-usn", "parse-prefetch", "parse-lnk", "parse-raw-logfile", "import-logfile", "import-usn", "use-existing", "parse-all", "detect"])
    a = ap.parse_args()
    case = Path(a.case)
    if a.action == "status":
        status(case, a.mft_file, a.usn_file, a.prefetch_dir, a.raw_logfile_file, a.logfile_csv, a.lnk_windows_dir, a.lnk_office_dir, a.i30_csv); return 0
    if a.action == "parse-mft":
        return 0 if parse_mft(case, a.mft_file) else 1
    if a.action == "parse-usn":
        return 0 if parse_usn(case, a.usn_file) else 1
    if a.action == "parse-prefetch":
        return 0 if parse_prefetch(case, a.prefetch_dir) else 1
    if a.action == "parse-lnk":
        return 0 if parse_lnk(case, a.lnk_windows_dir, a.lnk_office_dir) else 1
    if a.action == "parse-raw-logfile":
        return 0 if parse_raw_logfile(case, a.raw_logfile_file, timezone=a.timezone, mft_record_size=a.mft_record_size) else 1
    if a.action == "import-logfile":
        return 0 if import_logfile_csv(case, a.logfile_csv) else 1
    if a.action == "import-usn":
        return 0 if import_usn_csv(case, a.usn_file) else 1
    if a.action == "use-existing":
        return 0 if use_existing(case) else 1
    if a.action == "parse-all":
        parse_all(case, a.mft_file, a.usn_file, a.prefetch_dir, a.raw_logfile_file, a.logfile_csv, a.lnk_windows_dir, a.lnk_office_dir, a.i30_csv, a.all_files, a.target_path_keyword); return 0
    if a.action == "detect":
        return 0 if detect(case, a.all_files, a.target_path_keyword, a.mft_file, a.usn_file, a.prefetch_dir, a.raw_logfile_file, a.logfile_csv, a.lnk_windows_dir, a.lnk_office_dir, a.i30_csv, a.force_usn_only, a.usn_profile, a.clear_unselected_inputs) else 1

if __name__ == "__main__":
    raise SystemExit(main())
