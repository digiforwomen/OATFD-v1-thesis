# -*- coding: utf-8 -*-
"""
mini_nlt_prototype.py

Mini NLT-like Prototype untuk penelitian deteksi indikasi manipulasi timestamp NTFS.

STATUS AKADEMIK:
- Ini BUKAN clone penuh NTFS Log Tracker 1.9.
- Ini adalah prototype "NLT-like" yang:
  1. mengumpulkan artefak,
  2. memanggil parser eksternal untuk artefak yang formatnya sudah stabil,
  3. melakukan parsing eksperimental $LogFile jika NLT CSV tidak tersedia,
  4. menghasilkan suspicious_behavior_detection.csv ala ringkasan NLT,
  5. menghasilkan detection_matrix.csv dan case_reasoning.csv.

Parser:
- $MFT        : MFTECmd.exe
- $UsnJrnl:$J: MFTECmd.exe
- Prefetch    : PECmd.exe
- LNK         : LECmd.exe
- $LogFile    : dua opsi:
                a) CSV NLT_LogFile_*.csv jika tersedia;
                b) experimental_logfile_carver internal jika NLT CSV tidak tersedia.

KLAIM YANG BENAR:
- Tool ini memberi indikasi dan reasoning lintas artefak.
- Tool ini bukan bukti absolut dan bukan parser Redo/Undo $LogFile setara NLT.

CONTOH PENGGUNAAN

1) Dari folder case yang sudah berisi artefak mentah:
python mini_nlt_prototype.py --case "Z:\\Thesis\\Case_E01" --all

Struktur artefak yang dicari:
<case>\\$MFT
<case>\\$UsnJrnl_$J
<case>\\$LogFile
<case>\\Prefetch\\*.pf
<case>\\LNK_WindowsRecent\\*.lnk
<case>\\LNK_OfficeRecent\\*.lnk

2) Jika artefak mentah ada di RAW_ARTIFACTS:
python mini_nlt_prototype.py --case "Z:\\Thesis\\Case_E01" --raw-dir "Z:\\Thesis\\Case_E01\\RAW_ARTIFACTS" --all

3) Jika sudah punya INPUT_PYTHON:
python mini_nlt_prototype.py --input "Z:\\Thesis\\Case_E01\\INPUT_PYTHON" --detect-only --all-files

Output:
<case>\\OATFD_OUTPUT\\
- detection_matrix.csv
- case_reasoning.csv
- suspicious_behavior_detection.csv
- timeline_events.csv
- run_summary.csv
- non_primary_artifact_anomalies.csv
- high_risk_non_primary_artifacts.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Iterable, Tuple

try:
    csv.field_size_limit(2**31 - 1)
except OverflowError:
    csv.field_size_limit(10**8)


# ============================================================
# General utilities
# ============================================================

WINDOWS_EPOCH = datetime(1601, 1, 1)

OATFD_VERSION = "OATFD v1.0 Causal-Timeline Guard Thesis Edition"
SCORING_RULE_VERSION = "OATFD_v1_0_causal_timeline_guard"

# OATFD v1.0 configuration:
# - realcase is the default; benchmark label tokens are disabled unless explicitly enabled.
# - timezone offsets are configurable for datasets that mix UTC/local output.
BENCHMARK_MODE = os.environ.get("OATFD_BENCHMARK_MODE", "0").strip().lower() in {"1", "true", "yes", "on"}
# v1.0 bias-hardening defaults:
# - Dataset/support filename tokens are disabled by default to prevent lab/path-token leakage.
# - Program files (.exe/.dll/.ps1/...) are not automatically treated as non-primary unless
#   they are clearly OS/application-context artifacts.
# - Timezone equivalence defaults to UTC-only; add offsets explicitly with OATFD_TZ_OFFSETS if needed.
# - Experiment support files can be de-primary-role'd only by an explicit manifest.
DATASET_SUPPORT_TOKENS = os.environ.get("OATFD_DATASET_SUPPORT_TOKENS", "0").strip().lower() in {"1", "true", "yes", "on"}
PROGRAM_ROLE_GATE_STRICT = os.environ.get("OATFD_PROGRAM_ROLE_GATE_STRICT", "0").strip().lower() in {"1", "true", "yes", "on"}
SUPPORT_MANIFEST_PATH = os.environ.get("OATFD_SUPPORT_MANIFEST", "").strip()
SUPPORT_MANIFEST_INLINE = os.environ.get("OATFD_SUPPORT_MANIFEST_INLINE", "").strip()
_SUPPORT_MANIFEST_CACHE = None

def _support_manifest_names() -> set:
    """Explicit evaluation-role manifest for ground-truth/support files.

    This is not a detection feature. It only prevents pre-declared experiment
    support files from being evaluated as primary target files.
    """
    global _SUPPORT_MANIFEST_CACHE
    if _SUPPORT_MANIFEST_CACHE is not None:
        return _SUPPORT_MANIFEST_CACHE
    names = set()
    if SUPPORT_MANIFEST_INLINE:
        for item in SUPPORT_MANIFEST_INLINE.split(','):
            base = Path(item.strip().replace('\\', '/')).name.lower()
            if base:
                names.add(base)
    if SUPPORT_MANIFEST_PATH:
        mp = Path(SUPPORT_MANIFEST_PATH)
        if mp.exists():
            try:
                with mp.open('r', encoding='utf-8-sig', errors='replace', newline='') as f:
                    rdr = csv.reader(f)
                    for row in rdr:
                        if not row:
                            continue
                        first = row[0].strip()
                        if not first or first.startswith('#'):
                            continue
                        if first.lower() in {'filename','file','name','target_name'}:
                            continue
                        base = Path(first.replace('\\', '/')).name.lower()
                        if base:
                            names.add(base)
            except Exception:
                pass
    _SUPPORT_MANIFEST_CACHE = names
    return names

def _configured_tz_offsets():
    raw = os.environ.get("OATFD_TZ_OFFSETS", "0")
    vals = []
    for x in raw.split(','):
        try:
            vals.append(float(x.strip()))
        except Exception:
            pass
    return tuple(vals or (0,))

def _configured_causality_tz_offsets():
    """Timezone offsets for operation-causality proximity checks.

    This is used only to compare event times across artifacts that may be
    exported in UTC or local time.  It is not a ground-truth rule and does not
    label files as normal/manipulated.  Override with
    OATFD_CAUSALITY_TZ_OFFSETS, e.g. 0,7,-7.
    """
    raw = os.environ.get("OATFD_CAUSALITY_TZ_OFFSETS", os.environ.get("OATFD_TZ_OFFSETS", "0,7,-7"))
    vals = []
    for x in raw.split(','):
        try:
            vals.append(float(x.strip()))
        except Exception:
            pass
    return tuple(vals or (0,))

def say(msg: str) -> None:
    print(msg, flush=True)

def s(x) -> str:
    if x is None:
        return ""
    t = str(x).strip()
    return "" if t.lower() in {"nan", "nat", "none", "null"} else t

def lower(x) -> str:
    return s(x).lower()

def compact_reason(x) -> str:
    return re.sub(r"[^a-z0-9]+", "", lower(x))

def reason_has(reason_text, *tokens) -> bool:
    raw = lower(reason_text)
    compact = compact_reason(reason_text)
    for tok in tokens:
        t = tok.lower()
        if t in raw or re.sub(r"[^a-z0-9]+", "", t) in compact:
            return True
    return False

def parse_int(x, default=0) -> int:
    try:
        t = s(x)
        if not t:
            return default
        return int(float(t))
    except Exception:
        return default

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _load_support_manifest(input_dir: Path) -> set:
    """Load pre-declared experiment/support filenames or paths.

    This is an evaluation role manifest, not a timestamp-manipulation feature.
    It prevents ground-truth/log/support files from being treated as primary targets
    without relying on hidden dataset-name tokens.
    """
    import csv as _csv
    candidates = []
    env_path = os.environ.get("OATFD_SUPPORT_MANIFEST", "").strip()
    if env_path:
        candidates.append(Path(env_path))
    if input_dir:
        candidates.extend([input_dir / "evaluation_support_manifest.csv", input_dir / "oatfd_support_manifest.csv"])
    vals = set()
    for p in candidates:
        try:
            if not p or not p.exists():
                continue
            raw = p.read_text(encoding="utf-8-sig", errors="replace").splitlines()
            if not raw:
                continue
            try:
                rdr = _csv.DictReader(raw)
                if rdr.fieldnames:
                    for row in rdr:
                        for key in ["filename", "file_name", "target_name", "name", "path", "relative_path"]:
                            val = str(row.get(key, "")).strip().strip('"') if key in row else ""
                            if val:
                                vals.add(val.lower())
                                vals.add(Path(val.replace("\\", "/")).name.lower())
                    continue
            except Exception:
                pass
            for line in raw:
                line = line.strip().strip('"')
                if not line or line.startswith("#") or line.lower() in {"filename", "file_name", "target_name", "path"}:
                    continue
                parts = [x.strip().strip('"') for x in line.split(",") if x.strip()]
                for val in (parts[:1] or [line]):
                    vals.add(val.lower())
                    vals.add(Path(val.replace("\\", "/")).name.lower())
        except Exception:
            continue
    return vals

def parse_dt(x) -> Optional[datetime]:
    """Parse common timestamp strings.

    v1.0: preserve timezone semantics. Strings with Z or +/-HH:MM are converted
    to UTC and returned as naive UTC datetimes so the rest of the historical code
    can compare them safely. Naive strings remain naive.
    """
    t = s(x).strip()
    if not t:
        return None
    # Normalize ISO variants while preserving Z as UTC.
    iso = t.replace("/", "-") if re.match(r"^\d{4}/\d{2}/\d{2}", t) else t
    iso = iso.replace("T", " ")
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    # Trim fractional seconds to Python microseconds, preserving timezone suffix.
    m_iso = re.match(r"^(\d{4}-\d{2}-\d{2})[ ](\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:?\d{2})?$", iso)
    if m_iso:
        frac = m_iso.group(3) or ""
        tz = m_iso.group(4) or ""
        if frac:
            frac = "." + frac[1:7].ljust(6, "0")
        if tz and re.match(r"[+-]\d{4}$", tz):
            tz = tz[:3] + ":" + tz[3:]
        try:
            dt = datetime.fromisoformat(f"{m_iso.group(1)} {m_iso.group(2)}{frac}{tz}")
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except Exception:
            pass

    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?", t)
    if m:
        frac = m.group(3) or ""
        if frac:
            frac = "." + frac[1:7].ljust(6, "0")
        try:
            return datetime.fromisoformat(f"{m.group(1)} {m.group(2)}{frac}")
        except Exception:
            pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y:%m:%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(t, fmt)
        except Exception:
            pass
    return None

def fmt_dt(dt: Optional[datetime]) -> str:
    return dt.isoformat(sep=" ") if isinstance(dt, datetime) else ""

def filetime_to_dt(value: int) -> Optional[datetime]:
    if value <= 0:
        return None
    try:
        return WINDOWS_EPOCH + timedelta(microseconds=value / 10)
    except Exception:
        return None

def delta_days(anchor: Optional[datetime], dt: Optional[datetime]) -> Optional[float]:
    return None if not anchor or not dt else (anchor - dt).total_seconds() / 86400.0

def fmt_days(x: Optional[float]) -> str:
    return "" if x is None else f"{x:.2f}"


def extract_first_value(row: Dict[str, str], candidates: List[str], contains_all: List[str]=None) -> str:
    """Ambil nilai pertama dari kolom kandidat, dengan fallback pencarian nama kolom."""
    for c in candidates:
        if c in row and s(row.get(c)):
            return s(row.get(c))
    contains_all = [x.lower() for x in (contains_all or [])]
    if contains_all:
        for k, v in row.items():
            lk = lower(k).replace(" ", "").replace("_", "")
            if all(x in lk for x in contains_all) and s(v):
                return s(v)
    return ""

def normalize_lsn_text(x: object) -> str:
    t = s(x).strip()
    if not t:
        return ""
    # Ambil token numerik/hex pertama yang masuk akal.
    m = re.search(r"(0x[0-9a-fA-F]+|[0-9a-fA-F]{4,}|\\d+)", t)
    return m.group(1) if m else t

def lsn_to_int(x: object):
    t = normalize_lsn_text(x)
    if not t:
        return None
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        # Jika ada huruf A-F, anggap hex.
        if re.search(r"[a-fA-F]", t):
            return int(t, 16)
        return int(t, 10)
    except Exception:
        return None


def row_text(row: Dict[str, str]) -> str:
    return " ".join(s(v) for v in row.values())

def join_unique(vals: Iterable, max_items=8) -> str:
    out = []
    seen = set()
    for v in vals:
        t = s(v)
        if t and t not in seen:
            seen.add(t)
            out.append(t)
            if len(out) >= max_items:
                break
    return " | ".join(out)

def last_component(p: str) -> str:
    t = s(p).replace("/", "\\").strip("\\")
    return t.split("\\")[-1] if t else ""

def read_csv_auto(path: Optional[Path]) -> List[Dict[str, str]]:
    if path is None or not path.exists():
        return []

    encs = ["utf-8-sig", "utf-16", "utf-16le", "latin1"]
    seps = [",", "\t", ";"]
    last = None

    for enc in encs:
        for sep in seps:
            try:
                with path.open("r", encoding=enc, newline="") as f:
                    sample = f.read(12000)
                    f.seek(0)
                    if sep != "," and sep not in sample:
                        continue
                    rdr = csv.DictReader(f, delimiter=sep)
                    if not rdr.fieldnames or len(rdr.fieldnames) <= 1:
                        continue
                    rows = []
                    for row in rdr:
                        rows.append({
                            str(k).strip().replace("\ufeff", ""): ("" if v is None else str(v).strip())
                            for k, v in row.items()
                            if k is not None
                        })
                    return rows
            except Exception as e:
                last = e

    raise RuntimeError(f"Gagal membaca CSV {path}: {last}")


def keyword_aliases(keyword: str) -> List[str]:
    """Return robust path-keyword aliases for case-folder naming differences.

    Real artifacts may contain a shorter logical path than the GUI case folder.
    Example: GUI case folder = "Percobaan Thesis Ketujuh" while NTFS artifact path
    = "\\Thesis Experiment 2026\\Percobaan Ketujuh\\...".
    v1.0 therefore tests several aliases instead of a single literal keyword.
    """
    raw = s(keyword)
    # v1.0: explicit all-scope keywords disable target filtering.
    # Use blank, *, ALL, ALL_FILES, FULL_SCOPE, VOLUME, NO_FILTER, or SEMUA to scan every MFT file in the selected inputs.
    if raw.lower() in {"*", "all", "all_files", "full_scope", "full-scope", "volume", "no_filter", "nofilter", "semua"}:
        return []
    if not raw:
        return []
    vals = []
    def add(x):
        x = re.sub(r"\s+", " ", s(x)).strip()
        if len(x) >= 3 and x.lower() not in [v.lower() for v in vals]:
            vals.append(x)
    add(raw)
    # Remove common container words that may appear in a Windows folder name but not in artifact paths.
    cleaned = raw
    for word in ["Thesis", "Experiment", "Eksperimen", "Percobaan Thesis", "Percobaan Eksperimen"]:
        cleaned = re.sub(rf"\b{re.escape(word)}\b", " ", cleaned, flags=re.IGNORECASE)
    add(cleaned)
    # If the text contains 'Percobaan' plus an ordinal, add 'Percobaan <ordinal>'.
    tokens = re.findall(r"[A-Za-z0-9_]+", raw)
    ordinals = {"pertama","kedua","ketiga","keempat","kelima","keenam","enam","ketujuh","tujuh","kedelapan","delapan","kesembilan","sembilan","kesepuluh","sepuluh"}
    low_tokens = [t.lower() for t in tokens]
    for i,t in enumerate(low_tokens):
        if t == "percobaan":
            for u in low_tokens[i+1:]:
                if u in ordinals or u.startswith("ke"):
                    add("Percobaan " + u.title())
                    break
    # Add last two/three words as a fallback, but avoid overly generic single terms.
    if len(tokens) >= 2:
        add(" ".join(tokens[-2:]))
    if len(tokens) >= 3:
        add(" ".join(tokens[-3:]))
    return vals

def keyword_matches(keyword: str, *texts: object) -> bool:
    aliases = keyword_aliases(keyword)
    if not aliases:
        return True
    blob = " ".join(s(x) for x in texts if s(x)).lower().replace("/", "\\")
    # Literal alias match.
    if any(a.lower().replace("/", "\\") in blob for a in aliases):
        return True
    # Token fallback: require all meaningful tokens except generic container words.
    generic = {"thesis", "experiment", "eksperimen", "data", "case", "folder"}
    for a in aliases:
        toks = [t.lower() for t in re.findall(r"[A-Za-z0-9_]+", a) if t.lower() not in generic]
        if toks and len(toks) <= 4 and all(t in blob for t in toks):
            return True
    return False

def write_csv(path: Path, rows: List[Dict], fields: List[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

def parse_roots(text: str) -> List[Path]:
    return [Path(x.strip().strip('"')) for x in text.split(",") if x.strip()]

def find_first(roots: Iterable[Path], filename: str) -> Optional[Path]:
    for root in roots:
        if not root.exists():
            continue
        direct = root / filename
        if direct.exists():
            return direct
        try:
            for p in root.rglob(filename):
                if p.is_file():
                    return p
        except Exception:
            continue
    return None

def find_latest(root: Path, pattern: str, exclude_contains: str = "") -> Optional[Path]:
    if not root.exists():
        return None
    items = []
    for p in root.rglob(pattern):
        if p.is_file() and (not exclude_contains or exclude_contains.lower() not in p.name.lower()):
            items.append(p)
    if not items:
        return None
    return sorted(items, key=lambda x: x.stat().st_mtime, reverse=True)[0]

def run_cmd(args: List[str], dry_run=False) -> int:
    say("")
    say("[CMD] " + " ".join(f'"{x}"' if " " in x else x for x in args))
    if dry_run:
        say("[DRY-RUN] command tidak dijalankan.")
        return 0
    try:
        p = subprocess.run(args, shell=False)
        return p.returncode
    except Exception as e:
        say(f"[ERROR] command gagal: {e}")
        return 1

def copy_if_exists(src: Path, dst: Path) -> bool:
    if not src.exists():
        say(f"[SKIP] Tidak ada: {src}")
        return False
    ensure_dir(dst.parent)
    shutil.copy2(src, dst)
    say(f"[COPY] {src} -> {dst}")
    return True


# ============================================================
# Parse stage: external parsers + experimental LogFile
# ============================================================

def parse_mft(raw_dir: Path, input_dir: Path, parsed_dir: Path, mftecmd: Path, dry_run=False) -> bool:
    raw = raw_dir / "$MFT"
    out_dir = parsed_dir / "MFT"
    ensure_dir(out_dir)
    if not raw.exists():
        say(f"[MISS] $MFT tidak ditemukan: {raw}")
        return False
    rc = run_cmd([str(mftecmd), "-f", str(raw), "--csv", str(out_dir), "--csvf", "mft_parsed.csv"], dry_run)
    if rc != 0:
        return False
    return copy_if_exists(out_dir / "mft_parsed.csv", input_dir / "mft_parsed.csv")

def parse_usn(raw_dir: Path, input_dir: Path, parsed_dir: Path, mftecmd: Path, dry_run=False) -> bool:
    candidates = [
        raw_dir / "$UsnJrnl_$J",
        raw_dir / "$Extend" / "$UsnJrnl:$J",
        raw_dir / "$Extend" / "$UsnJrnl_$J",
    ]
    raw = next((p for p in candidates if p.exists()), None)
    out_dir = parsed_dir / "USN"
    ensure_dir(out_dir)

    if raw is None:
        say("[MISS] $UsnJrnl_$J tidak ditemukan.")
        return False

    rc = run_cmd([str(mftecmd), "-f", str(raw), "--csv", str(out_dir), "--csvf", "usn_parsed.csv"], dry_run)
    if rc != 0:
        return False
    return copy_if_exists(out_dir / "usn_parsed.csv", input_dir / "usn_parsed.csv")

def parse_prefetch(raw_dir: Path, input_dir: Path, parsed_dir: Path, pecmd: Path, dry_run=False) -> bool:
    candidates = [raw_dir / "Prefetch", raw_dir / "Prefetch_raw", raw_dir / "Windows" / "Prefetch"]
    pf_dir = next((p for p in candidates if p.exists() and p.is_dir()), None)
    out_dir = parsed_dir / "Prefetch"
    ensure_dir(out_dir)

    if pf_dir is None:
        say("[MISS] Folder Prefetch tidak ditemukan.")
        return False

    rc = run_cmd([str(pecmd), "-d", str(pf_dir), "--csv", str(out_dir), "--csvf", "prefetch_all_parsed.csv"], dry_run)
    if rc != 0:
        return False
    return copy_if_exists(out_dir / "prefetch_all_parsed.csv", input_dir / "prefetch_all_parsed.csv")

def parse_lnk(raw_dir: Path, input_dir: Path, parsed_dir: Path, lecmd: Optional[Path], dry_run=False) -> None:
    if lecmd is None:
        say("[OPT] LECmd.exe tidak ditemukan; LNK dilewati.")
        return

    out_dir = parsed_dir / "LNK"
    ensure_dir(out_dir)

    jobs = [
        (raw_dir / "LNK_WindowsRecent", "lnk_windows_recent_parsed.csv"),
        (raw_dir / "LNK_OfficeRecent", "lnk_office_recent_parsed.csv"),
    ]

    for src_dir, csv_name in jobs:
        if not src_dir.exists():
            say(f"[OPT] Folder LNK tidak ada: {src_dir}")
            continue
        rc = run_cmd([str(lecmd), "-d", str(src_dir), "--csv", str(out_dir), "--csvf", csv_name], dry_run)
        if rc == 0:
            copy_if_exists(out_dir / csv_name, input_dir / csv_name)

def experimental_logfile_carve(logfile: Path, mft_csv: Path, output: Path, target_keyword="", window=4096, max_hits_per_name=50, tz_offset=7) -> bool:
    if not logfile.exists():
        say(f"[MISS] raw $LogFile tidak ditemukan: {logfile}")
        return False
    if not mft_csv.exists():
        say(f"[MISS] mft_parsed.csv belum ada, tidak bisa experimental carve $LogFile.")
        return False

    say("[LOGCARVE] Membaca raw $LogFile secara eksperimental...")
    data = logfile.read_bytes()
    mft_rows = read_csv_auto(mft_csv)

    names = []
    seen = set()
    for r in mft_rows:
        if lower(r.get("InUse")) == "false":
            continue
        if lower(r.get("IsDirectory")) == "true":
            continue
        if lower(r.get("IsAds")) == "true":
            continue
        fn = s(r.get("FileName"))
        parent = s(r.get("ParentPath"))
        if not fn or fn.startswith("$"):
            continue
        if "$recycle.bin" in parent.lower():
            continue
        if target_keyword and target_keyword.lower() not in parent.lower():
            continue
        if fn.lower() not in seen:
            seen.add(fn.lower())
            names.append(fn)

    date_min = datetime(2000, 1, 1)
    date_max = datetime(2035, 1, 1)
    rows = []
    total_hit = 0

    for name in names:
        needles = [name.encode("utf-16le", errors="ignore")]
        if all(ord(c) < 128 for c in name):
            needles.append(name.encode("ascii", errors="ignore"))

        offsets = []
        for needle in needles:
            if not needle:
                continue
            pos = 0
            count = 0
            while count < max_hits_per_name:
                i = data.find(needle, pos)
                if i < 0:
                    break
                offsets.append(i)
                count += 1
                pos = i + 1

        offsets = sorted(set(offsets))[:max_hits_per_name]
        total_hit += len(offsets)

        for name_off in offsets:
            start = max(0, name_off - window)
            end = min(len(data), name_off + window)
            candidates = []
            seen_dt = set()

            for off in range(start, max(start, end - 8)):
                try:
                    val = struct.unpack_from("<Q", data, off)[0]
                except Exception:
                    continue
                dt_utc = filetime_to_dt(val)
                if not dt_utc or not (date_min <= dt_utc <= date_max):
                    continue
                key = dt_utc.isoformat(sep=" ")
                if key in seen_dt:
                    continue
                seen_dt.add(key)
                candidates.append((abs(off - name_off), off, dt_utc))

            candidates.sort(key=lambda x: x[0])
            if not candidates:
                rows.append({
                    "EventTime(UTC+7)": "",
                    "Event": "ExperimentalLogFileContext",
                    "Detail": f"target={name}; filename found but no nearby FILETIME candidate",
                    "Source": "OATFD internal logfile carver",
                    "TargetName": name,
                    "Confidence": "Low",
                })
                continue

            for dist, ft_off, dt_utc in candidates[:10]:
                local = dt_utc + timedelta(hours=tz_offset)
                rows.append({
                    "EventTime(UTC+7)": local.isoformat(sep=" "),
                    "Event": "ExperimentalLogFileContext",
                    "Detail": f"target={name}; candidate_time_utc={dt_utc.isoformat(sep=' ')}; byte_distance={dist}; name_offset={name_off}; filetime_offset={ft_off}",
                    "Source": "OATFD internal logfile carver",
                    "TargetName": name,
                    "Confidence": "Medium" if dist <= 512 else "Low",
                })

    write_csv(output, rows, ["EventTime(UTC+7)", "Event", "Detail", "Source", "TargetName", "Confidence"])
    say(f"[LOGCARVE] Selesai. Name hits={total_hit}, rows={len(rows)}, output={output}")
    return True

def copy_or_build_logfile_csv(case: Path, raw_dir: Path, input_dir: Path, target_keyword="") -> None:
    # 1) Prioritize real NLT export.
    nlt = find_latest(case, "NLT_LogFile*.csv", exclude_contains="Search")
    if nlt:
        copy_if_exists(nlt, input_dir / "logfile_parsed.csv")
        return

    # 2) Experimental fallback.
    raw_log = raw_dir / "$LogFile"
    if raw_log.exists() and (input_dir / "mft_parsed.csv").exists():
        experimental_logfile_carve(raw_log, input_dir / "mft_parsed.csv", input_dir / "logfile_parsed.csv", target_keyword=target_keyword)
        return

    # 3) Placeholder.
    say("[WARN] $LogFile tidak dapat diparse; membuat placeholder kosong.")
    write_csv(input_dir / "logfile_parsed.csv", [], ["EventTime(UTC+7)", "Event", "Detail", "Source"])


# ============================================================
# Detection stage
# ============================================================

def find_file(input_dir: Path, name: str, fallback: str = "") -> Optional[Path]:
    """Find input CSV robustly.

    v1.0: The user may keep parsed files with suffixes such as
    mft_parsed(7).csv, usn_parsed(6).csv, logfile_parsed(4).csv.
    Earlier versions only looked for exact names and therefore silently
    lost USN/$LogFile evidence. This function tries exact name, explicit
    fallback, and safe stem wildcard.
    """
    p = input_dir / name
    stem = Path(name).stem
    # v1.0: for $I30 prefer target-level INDXRipper exports (e.g. i30_all.csv)
    # over weak LogFile-carver files named i30_parsed.csv. Therefore do not return
    # the exact i30_parsed.csv before candidate prioritization.
    if p.exists() and stem != "i30_parsed":
        return p

    patterns = []
    if fallback:
        patterns.append(fallback)
    suffix = Path(name).suffix or ".csv"
    patterns.append(f"{stem}*{suffix}")

    # Some normalized artifacts are exported with capitalized / NLT names.
    if stem == "mft_parsed":
        patterns += ["MFT*.csv", "*mft*parsed*.csv"]
    elif stem == "usn_parsed":
        patterns += ["USN*.csv", "*usn*parsed*.csv", "NLT_UsnJrnl*.csv"]
    elif stem == "logfile_parsed":
        patterns += ["LogFile*.csv", "*logfile*parsed*.csv", "NLT_LogFile*.csv"]
    elif stem == "prefetch_all_parsed":
        patterns += ["Prefetch*.csv", "*prefetch*parsed*.csv"]
    elif stem == "lnk_windows_recent_parsed":
        patterns += ["*windows*recent*parsed*.csv", "lnk_windows*.csv"]
    elif stem == "lnk_office_recent_parsed":
        patterns += ["*office*recent*parsed*.csv", "lnk_office*.csv"]
    elif stem == "i30_parsed":
        patterns += ["i30*.csv", "*i30*.csv", "*I30*.csv", "INDX*.csv", "*indx*.csv"]

    seen = set()
    candidates = []
    for pat in patterns:
        for x in input_dir.glob(pat):
            if x.name in seen:
                continue
            # avoid derived outputs as inputs
            low = x.name.lower()
            if any(bad in low for bad in ["detection_matrix", "case_reasoning", "timeline_events", "visual_summary", "suspicious_behavior", "need_review", "high_confidence", "run_summary", "search"]):
                continue
            seen.add(x.name)
            candidates.append(x)
    if candidates:
        if stem == "i30_parsed":
            def _i30_priority(x: Path):
                low = x.name.lower()
                pri = 0
                if low == "i30_all.csv" or low.startswith("indx") or "indxripper" in low:
                    pri = 3
                elif "i30_parsed" in low:
                    pri = 1
                return (pri, x.stat().st_mtime)
            candidates.sort(key=_i30_priority, reverse=True)
        else:
            candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return candidates[0]
    return None

def load_inputs(input_dir: Path) -> Dict[str, List[Dict[str, str]]]:
    paths = {
        "mft": find_file(input_dir, "mft_parsed.csv"),
        "usn": find_file(input_dir, "usn_parsed.csv"),
        "log": find_file(input_dir, "logfile_parsed.csv", "NLT_LogFile*.csv"),
        "pf": find_file(input_dir, "prefetch_all_parsed.csv"),
        "lnk_w": find_file(input_dir, "lnk_windows_recent_parsed.csv"),
        "lnk_o": find_file(input_dir, "lnk_office_recent_parsed.csv"),
        # Prefer target-level INDXRipper-style I30 over weak LogFile-carver style rows.
        "i30": find_file(input_dir, "i30_all.csv", "i30*.csv") or find_file(input_dir, "i30_parsed.csv", "i30*.csv"),
    }

    # OATFD v1.0: tidak ada artefak yang wajib.
    # Aplikasi tetap berjalan jika hanya tersedia $MFT, hanya $UsnJrnl, hanya $LogFile,
    # hanya Prefetch/LNK, atau kombinasi parsial lain. Artefak yang hilang/kosong diperlakukan
    # sebagai evidence unavailable, bukan error.
    loaded = {
        "mft": read_csv_auto(paths["mft"]) if paths["mft"] else [],
        "usn": read_csv_auto(paths["usn"]) if paths["usn"] else [],
        "log": read_csv_auto(paths["log"]) if paths["log"] else [],
        "pf": read_csv_auto(paths["pf"]) if paths["pf"] else [],
        "lnk_w": read_csv_auto(paths["lnk_w"]) if paths["lnk_w"] else [],
        "lnk_o": read_csv_auto(paths["lnk_o"]) if paths["lnk_o"] else [],
        "i30": read_i30_csv_auto(paths["i30"]) if paths["i30"] else [],
    }
    missing = [k for k in ["mft", "usn", "log", "pf", "lnk_w", "lnk_o", "i30"] if paths[k] is None or len(loaded[k]) == 0]
    loaded["_input_paths"] = {k: str(v) if v else "" for k, v in paths.items()}
    loaded["_missing_artifacts"] = missing
    return loaded



def read_i30_csv_auto(path: Optional[Path]) -> List[Dict[str, str]]:
    """Read INDXRipper / normalized $I30 CSV robustly.

    INDXRipper builds used in this project may output either:
    - headerless rows: Index Record,"./path",parent_ref,parent_seq,"file",attrs,child_ref,child_seq,size,alloc,C,M,A,E
    - normalized/headered rows created by the researcher.

    The engine normalizes both forms into stable i30_* columns.
    """
    if path is None or not path.exists():
        return []

    default_headers = [
        "record_type", "parent_path", "parent_mft_ref", "parent_sequence", "file_name", "attributes",
        "child_mft_ref", "child_sequence", "logical_size", "allocated_size",
        "i30_created_utc", "i30_modified_utc", "i30_accessed_utc", "i30_changed_utc"
    ]

    def norm_row(row: Dict[str, str]) -> Dict[str, str]:
        lower_map = {str(k).strip().lower().replace(" ", "_"): k for k in row.keys()}
        def pick(*names):
            for name in names:
                if name in row and s(row.get(name)):
                    return s(row.get(name))
                lk = name.lower().replace(" ", "_")
                if lk in lower_map and s(row.get(lower_map[lk])):
                    return s(row.get(lower_map[lk]))
            return ""
        d = {
            "record_type": pick("record_type", "type", "RecordType"),
            "parent_path": pick("parent_path", "path", "directory", "source_folder", "ParentPath"),
            "parent_mft_ref": pick("parent_mft_ref", "parent_ref", "ParentMftRef", "ParentFileReferenceNumber", "ParentFileNumber"),
            "parent_sequence": pick("parent_sequence", "parent_seq", "ParentSequence", "ParentSequenceNumber"),
            "file_name": pick("file_name", "entry_name", "child_name", "name", "FileName", "Filename", "TargetName"),
            "attributes": pick("attributes", "file_attributes", "FileAttributes", "Flags"),
            "child_mft_ref": pick("child_mft_ref", "mft_reference", "mft_ref", "MFTReference", "FileReferenceNumber", "FileNumber"),
            "child_sequence": pick("child_sequence", "sequence_number", "sequence", "Seq", "SequenceNumber"),
            "logical_size": pick("logical_size", "size", "FileSize", "LogicalSize", "Size"),
            "allocated_size": pick("allocated_size", "allocated", "AllocatedSize"),
            "i30_created_utc": pick("i30_created_utc", "i30_created", "created", "Created", "CreationTime", "CreatedTime"),
            "i30_modified_utc": pick("i30_modified_utc", "i30_modified", "modified", "Modified", "ModificationTime", "LastModified", "ModifiedTime"),
            "i30_accessed_utc": pick("i30_accessed_utc", "i30_accessed", "accessed", "Accessed", "AccessTime", "LastAccessed", "AccessedTime"),
            "i30_changed_utc": pick("i30_changed_utc", "i30_changed", "changed", "record_changed", "mft_changed", "EntryModified", "ChangedTime"),
        }
        # Target-level $I30 requires a child filename plus child file reference and sequence.
        # LogFile-carver/index-context formats that only expose parent references are kept
        # as weak context and are not allowed to create high-confidence $I30 evidence.
        d["i30_source_mode"] = "target_level_i30" if (d.get("file_name") and d.get("child_mft_ref") and d.get("child_sequence")) else "weak_context_i30"
        return d

    def finalize_i30_rows(rows):
        out = []
        for rr in rows:
            target_level = bool(s(rr.get("file_name")) and s(rr.get("child_mft_ref")) and s(rr.get("child_sequence")))
            rr["i30_parser_mode"] = "target_level" if target_level else "weak_context"
            rr["i30_target_level"] = "Yes" if target_level else "No"
            out.append(rr)
        return out

    # Detect headerless INDXRipper output.
    first_nonempty = ""
    for enc in ["utf-8-sig", "utf-16", "latin1"]:
        try:
            with path.open("r", encoding=enc, errors="replace", newline="") as f:
                for line in f:
                    if line.strip():
                        first_nonempty = line.strip()
                        break
            if first_nonempty:
                break
        except Exception:
            continue

    if first_nonempty.startswith('Index Record,') or first_nonempty.startswith('"Index Record",'):
        rows = []
        import csv as _csv
        for enc in ["utf-8-sig", "utf-16", "latin1"]:
            try:
                with path.open("r", encoding=enc, errors="replace", newline="") as f:
                    rdr = _csv.reader(f)
                    for vals in rdr:
                        if len(vals) < 14:
                            continue
                        d = dict(zip(default_headers, vals[:14]))
                        rows.append(norm_row(d))
                return finalize_i30_rows(rows)
            except Exception:
                rows = []
        return rows

    try:
        return finalize_i30_rows([norm_row(r) for r in read_csv_auto(path)])
    except Exception:
        return []


def _min_delta_minutes_tzsafe(a: Optional[datetime], b: Optional[datetime], offsets=None) -> Optional[float]:
    """Minimum absolute delta in minutes while allowing configured UTC/local shifts."""
    if not isinstance(a, datetime) or not isinstance(b, datetime):
        return None
    vals = []
    for h in (offsets if offsets is not None else _configured_tz_offsets()):
        vals.append(abs((a - (b + timedelta(hours=float(h)))).total_seconds()) / 60.0)
    return min(vals) if vals else None


def i30_features(i30_rows: List[Dict[str, str]], target: str, folder: str = "", mf: Dict[str, object] = None, anchor: Optional[datetime] = None, threshold_days: int = 180) -> Dict[str, object]:
    """Build $I30 directory-index features for a target file.

    $I30 is used as secondary evidence:
    - strengthens normal write/tunneling guard;
    - substitutes weak/missing $FN comparison with reliability control;
    - never becomes high-confidence proof alone.
    """
    mf = mf or {}
    base = {
        "i30_found": "No", "i30_parent_path": "", "i30_record_type": "", "i30_attributes": "",
        "i30_child_mft_ref": "", "i30_child_sequence": "", "i30_logical_size": "", "i30_allocated_size": "",
        "i30_created": "", "i30_modified": "", "i30_accessed": "", "i30_changed": "",
        "i30_reliability": "0.00", "i30_link_type": "none", "i30_source_mode": "none", "i30_match_count": "0",
        "i30_anchor_delta_min": "", "i30_anchor_contradiction": "No", "i30_anchor_contradiction_score": "0.00",
        "i30_mft_c_delta_min": "", "i30_mft_m_delta_min": "", "i30_mft_e_delta_min": "",
        "i30_uniform_mace_far": "No", "i30_cma_e_split": "No", "i30_cluster_shift": "No",
        "i30_normal_write_support": "No", "i30_sequence_reuse_signal": "No", "i30_tunneling_guard_hint": "No",
        "i30_parser_mode": "", "i30_target_level": "No", "i30_current_file_match": "No",
        "i30_cma_moved_from_anchor": "No", "i30_e_only_metadata_change": "No", "i30_stale_entry": "No",
        "i30_reason": ""
    }
    if not i30_rows or not target:
        return base

    target_l = target.lower()
    folder_cands = _path_match_candidates(folder)
    entry = s(mf.get("mft_entry"))
    seq = s(mf.get("mft_sequence"))

    cands = []
    for r in i30_rows:
        fn = s(r.get("file_name"))
        if not fn:
            continue
        txt_norm = _row_text_norm(r)
        name_match = (fn.lower() == target_l) or (target_l in txt_norm)
        if not name_match:
            continue
        parent = s(r.get("parent_path"))
        parent_norm = _norm_for_path_match(parent)
        path_match = bool(folder_cands and any(c in parent_norm or c in txt_norm for c in folder_cands))
        ref_match = bool(entry and s(r.get("child_mft_ref")) == entry)
        seq_match = bool(seq and s(r.get("child_sequence")) == seq)
        # If folder is known, require path or ref match. Name-only rows are too risky.
        if folder_cands and not (path_match or ref_match):
            continue
        complete_times = sum(1 for k in ["i30_created_utc", "i30_modified_utc", "i30_accessed_utc", "i30_changed_utc"] if parse_dt(r.get(k)))
        # v1.0: deterministic $I30 reliability.
        # Name match is already required. Exact child MFT reference is strongest;
        # parent-path + sequence is enough for a medium/high confidence directory-index match.
        link_parts = []
        if ref_match and seq_match:
            reliability = 1.00; link_parts = ["mft_ref", "sequence"]
        elif ref_match:
            reliability = 0.90; link_parts = ["mft_ref"]
        elif path_match and seq_match:
            reliability = 0.75; link_parts = ["parent_path", "sequence"]
        elif path_match:
            reliability = 0.60; link_parts = ["parent_path"]
        else:
            reliability = 0.30; link_parts = ["name_only"]
        source_mode = s(r.get("i30_source_mode")) or "weak_context_i30"
        stale_i30_row = (parse_int(r.get("child_mft_ref"), -1) == 0 or parse_int(r.get("child_sequence"), -1) == 0)
        if source_mode != "target_level_i30":
            reliability = min(reliability, 0.30)
            link_parts.append("context_only")
        if stale_i30_row:
            reliability = min(reliability, 0.05)
            link_parts.append("stale")
        if complete_times >= 3 and reliability < 1.0 and not stale_i30_row and source_mode == "target_level_i30":
            reliability = min(1.0, reliability + 0.05)
            link_parts.append("timestamps")
        cands.append((reliability, seq_match, ref_match, path_match, r, "+".join(link_parts)))

    if not cands:
        return base
    cands.sort(key=lambda x: (x[0], x[1], x[2], x[3]), reverse=True)
    rel, seq_match, ref_match, path_match, r, link_type = cands[0]
    i30_parser_mode = s(r.get("i30_parser_mode")) or "weak_context"
    i30_target_level = (s(r.get("i30_target_level")) == "Yes")
    child_ref_i = parse_int(r.get("child_mft_ref"), 0)
    child_seq_i = parse_int(r.get("child_sequence"), 0)
    i30_stale_entry = bool(child_ref_i <= 0 or child_seq_i <= 0)
    i30_current_file_match = bool(ref_match and (seq_match or not seq))
    if (not i30_target_level) or i30_stale_entry:
        rel = min(rel, 0.30)
        link_type = (link_type + "+weak_context") if link_type else "weak_context"

    ic = parse_dt(r.get("i30_created_utc"))
    im = parse_dt(r.get("i30_modified_utc"))
    ia = parse_dt(r.get("i30_accessed_utc"))
    ie = parse_dt(r.get("i30_changed_utc"))
    times = [x for x in [ic, im, ia, ie] if x]

    def dm(a, b):
        v = _min_delta_minutes_tzsafe(a, b)
        return "" if v is None else f"{v:.2f}"

    si_c = parse_dt(mf.get("mft_si_created"))
    si_m = parse_dt(mf.get("mft_si_modified"))
    si_a = parse_dt(mf.get("mft_si_accessed"))
    si_e = parse_dt(mf.get("mft_si_record_changed"))
    anchor_delta = _min_delta_minutes_tzsafe(ic, anchor) if (ic and anchor) else None
    mft_c_delta = _min_delta_minutes_tzsafe(ic, si_c) if ic and si_c else None
    mft_m_delta = _min_delta_minutes_tzsafe(im, si_m) if im and si_m else None
    mft_a_delta = _min_delta_minutes_tzsafe(ia, si_a) if ia and si_a else None
    mft_e_delta = _min_delta_minutes_tzsafe(ie, si_e) if ie and si_e else None

    # Uniform/cluster indicators.
    uniform_mace = False
    if len(times) == 4:
        uniform_mace = (max(times) - min(times)).total_seconds() <= 2
    cma_uniform = False
    if ic and im and ia:
        cma_uniform = max(abs((im - ic).total_seconds()), abs((ia - ic).total_seconds())) <= 2

    def _anchor_delta(x):
        return _min_delta_minutes_tzsafe(x, anchor) if (x and anchor) else None

    cma_deltas_to_anchor = [_anchor_delta(x) for x in [ic, im, ia]]
    cma_close_to_anchor = bool(cma_uniform and all(d is not None and d <= 5.0 for d in cma_deltas_to_anchor))
    cma_moved_from_anchor = bool(cma_uniform and all(d is not None and d > 5.0 for d in cma_deltas_to_anchor))
    e_anchor_delta = _anchor_delta(ie)
    e_near_anchor = bool(e_anchor_delta is not None and e_anchor_delta <= 5.0)
    raw_cma_e_split = bool(cma_uniform and ie and abs((ie - ic).total_seconds()) >= 30 * 60)
    cma_e_split = bool(raw_cma_e_split and cma_moved_from_anchor and e_near_anchor and rel >= 0.75 and i30_target_level and not i30_stale_entry)
    i30_e_only_metadata_change = bool(raw_cma_e_split and cma_close_to_anchor and (e_anchor_delta is not None and e_anchor_delta > 5.0))

    def _contra_score(delta_min):
        if delta_min is None:
            return 0.0
        if delta_min <= 5:
            return 0.0
        if delta_min <= 60:
            return 0.30
        if delta_min <= 1440:
            return 0.60
        if delta_min <= 259200:  # 180 days
            return 0.80
        return 1.00

    i30_anchor_contradiction_score = _contra_score(anchor_delta)
    far_from_anchor = bool(anchor_delta is not None and anchor_delta >= threshold_days * 1440)
    medium_anchor_contra = bool(anchor_delta is not None and i30_anchor_contradiction_score >= 0.60)

    # Normal write support: created time is coherent with creation anchor, while
    # M/A/E may legitimately move later to the final write/close time. This is the
    # TN lock helper for files such as Cleo 15-17.
    normal_write_support = False
    if ic and im and ie and rel >= 0.50:
        order_ok = im >= ic and ie >= ic
        write_gap_min = abs((ie - ic).total_seconds()) / 60.0
        # v1.0: $I30 normal write support is tiered and intentionally narrow.
        # Strong TN support only for create->write/save windows up to 120 minutes.
        create_ok = True if anchor_delta is None else anchor_delta <= 5
        normal_write_support = bool(order_ok and write_gap_min <= 120 and create_ok and not cma_e_split) or i30_e_only_metadata_change

    i30_anchor_contradiction = bool((i30_anchor_contradiction_score >= 0.60) and rel >= 0.75 and i30_target_level and cma_moved_from_anchor and not normal_write_support and not i30_stale_entry)
    i30_uniform_mace_far = bool(uniform_mace and (far_from_anchor or medium_anchor_contra) and rel >= 0.75 and i30_target_level and not normal_write_support and not i30_stale_entry)
    i30_cluster_shift = bool((i30_uniform_mace_far or cma_e_split or i30_anchor_contradiction) and rel >= 0.75 and i30_target_level and not normal_write_support and not i30_stale_entry)

    child_seq = parse_int(r.get("child_sequence"), 0)
    sequence_reuse_signal = child_seq > 1
    # v1.0: sequence>1 is weak reuse evidence only. It is NOT a tunneling
    # guard by itself; USN Delete/Create or Rename evidence must corroborate it.
    tunneling_hint = False

    reasons = []
    if i30_anchor_contradiction:
        reasons.append("$I30 timestamp contradicts create/change anchor")
    if i30_uniform_mace_far:
        reasons.append("$I30 MACE uniform far from anchor")
    if cma_e_split:
        reasons.append("$I30 suspicious C/M/A moved from anchor while E stayed near anchor")
    if i30_e_only_metadata_change:
        reasons.append("$I30 E/ChangedTime moved while C/M/A stayed near anchor; metadata/attribute/rename context")
    if normal_write_support:
        reasons.append("$I30 supports normal create/write chronology")
    if i30_stale_entry:
        reasons.append("$I30 stale/invalid child reference; context only")
    if sequence_reuse_signal:
        reasons.append("$I30 child sequence > 1, possible delete-recreate/reuse context")

    base.update({
        "i30_found": "Yes",
        "i30_parent_path": s(r.get("parent_path")),
        "i30_record_type": s(r.get("record_type")),
        "i30_attributes": s(r.get("attributes")),
        "i30_child_mft_ref": s(r.get("child_mft_ref")),
        "i30_child_sequence": s(r.get("child_sequence")),
        "i30_logical_size": s(r.get("logical_size")),
        "i30_allocated_size": s(r.get("allocated_size")),
        "i30_created": s(r.get("i30_created_utc")),
        "i30_modified": s(r.get("i30_modified_utc")),
        "i30_accessed": s(r.get("i30_accessed_utc")),
        "i30_changed": s(r.get("i30_changed_utc")),
        "i30_reliability": f"{min(rel, 1.0):.2f}",
        "i30_link_type": link_type,
        "i30_source_mode": s(r.get("i30_source_mode")) or "weak_context_i30",
        "i30_match_count": str(len(cands)),
        "i30_anchor_delta_min": "" if anchor_delta is None else f"{anchor_delta:.2f}",
        "i30_anchor_contradiction": "Yes" if i30_anchor_contradiction else "No",
        "i30_anchor_contradiction_score": f"{i30_anchor_contradiction_score:.2f}",
        "i30_mft_c_delta_min": "" if mft_c_delta is None else f"{mft_c_delta:.2f}",
        "i30_mft_m_delta_min": "" if mft_m_delta is None else f"{mft_m_delta:.2f}",
        "i30_mft_a_delta_min": "" if mft_a_delta is None else f"{mft_a_delta:.2f}",
        "i30_mft_e_delta_min": "" if mft_e_delta is None else f"{mft_e_delta:.2f}",
        "i30_uniform_mace_far": "Yes" if i30_uniform_mace_far else "No",
        "i30_cma_e_split": "Yes" if cma_e_split else "No",
        "i30_cluster_shift": "Yes" if i30_cluster_shift else "No",
        "i30_normal_write_support": "Yes" if normal_write_support else "No",
        "i30_sequence_reuse_signal": "Yes" if sequence_reuse_signal else "No",
        "i30_tunneling_guard_hint": "Yes" if tunneling_hint else "No",
        "i30_parser_mode": i30_parser_mode,
        "i30_target_level": "Yes" if i30_target_level else "No",
        "i30_current_file_match": "Yes" if i30_current_file_match else "No",
        "i30_cma_moved_from_anchor": "Yes" if cma_moved_from_anchor else "No",
        "i30_e_only_metadata_change": "Yes" if i30_e_only_metadata_change else "No",
        "i30_stale_entry": "Yes" if i30_stale_entry else "No",
        "i30_reason": "; ".join(reasons),
    })
    return base

def _path_from_generic_row(r: Dict[str, str]) -> str:
    """Best-effort path extractor for partial-artifact mode."""
    for key in ["FullPath", "Path", "FilePath", "TargetPath", "LocalPath", "SourceFile", "SourceFilename", "ParentPath"]:
        val = s(r.get(key))
        if val:
            return val
    return ""


def _name_from_generic_row(r: Dict[str, str]) -> str:
    for key in ["FileName", "Name", "TargetName", "TargetFileName", "ExecutableName", "SourceFile", "SourceFilename", "Path", "FullPath", "LocalPath"]:
        val = s(r.get(key))
        if val:
            # Prefetch names often look like APP.EXE-HASH.pf; keep a reasonable filename.
            base = Path(val.replace("\\", "/")).name
            if base:
                return base
            return val
    return ""


def _add_target(rows, seen, fn, parent="", ext="", source="partial", extra: Dict[str, object] = None):
    fn = s(fn)
    parent = s(parent)
    extra = extra or {}
    if not fn:
        return
    # Only skip directory markers, not files. REALCASE v1.0 does not exclude control/support files; context guard is applied later.
    if fn in {".", ".."}:
        return
    if not ext and "." in fn:
        ext = fn.rsplit(".", 1)[-1].lower()

    # v1.0: MFT-derived targets use NTFS record identity as unique key.
    logical_id = s(extra.get("logical_id"))
    key = ("mft_id", logical_id) if logical_id else (parent.lower(), fn.lower(), source)
    if key in seen:
        return
    seen.add(key)
    row = {
        "scenario_id": f"AUTO{len(rows)+1:04d}",
        "file_name": fn.rsplit(".", 1)[0] if "." in fn else fn,
        "target_name": fn,
        "folder": last_component(parent),
        "relative_path": f"{parent}\\{fn}" if parent and fn.lower() not in parent.lower().split("\\")[-1:] else (parent or fn),
        "extension": ext,
        "target_source_artifact": source,
    }
    row.update(extra)
    rows.append(row)

def infer_targets(mft: List[Dict[str, str]], exts: List[str], keyword: str, all_files=False) -> List[Dict[str, str]]:
    extset = {e.lower().lstrip(".") for e in exts}
    rows = []
    seen = set()

    for r in mft:
        # Directories and ADS are structural containers; files only are targets.
        if lower(r.get("IsDirectory")) == "true":
            continue
        if lower(r.get("IsAds")) == "true":
            continue
        fn = s(r.get("FileName"))
        parent = s(r.get("ParentPath"))
        if not fn:
            continue
        if keyword and not keyword_matches(keyword, parent, fn):
            continue
        ext = lower(r.get("Extension")).lstrip(".")
        if not ext and "." in fn:
            ext = fn.rsplit(".", 1)[-1].lower()
        # In non-all-files mode, keep extension filter. In all-files mode, include everything.
        if not all_files and extset and ext not in extset:
            continue
        entry = s(r.get("EntryNumber"))
        seq = extract_first_value(r, ["SequenceNumber", "Sequence", "Seq"], ["sequence"])
        logical_id = f"case_volume_1:{entry}:{seq}" if entry and seq else ""
        _add_target(rows, seen, fn, parent, ext, "MFT", {
            "mft_entry_hint": entry,
            "mft_sequence_hint": seq,
            "mft_lsn_hint": extract_first_value(r, ["LogfileSequenceNumber", "Logfile Sequence Number", "LogFile Sequence Number", "LogFileSequenceNumber", "LSN"], ["logfile", "sequence"]),
            "logical_id": logical_id,
        })

    rows.sort(key=lambda x: (x["relative_path"].lower(), x["target_name"].lower()))
    return rows


def infer_targets_from_available(data: Dict[str, List[Dict[str, str]]], exts: List[str], keyword: str, all_files=False) -> List[Dict[str, str]]:
    """Build target list even when $MFT is absent.

    Priority:
      1) MFT records when available.
      2) USN rows by Name/ParentPath.
      3) LogFile rows by best-effort filename/path columns.
      4) LNK target rows.
      5) Prefetch executable names as context targets.
    """
    rows = infer_targets(data.get("mft", []), exts, keyword, all_files)
    seen = {(r.get("folder", "").lower(), r.get("target_name", "").lower(), r.get("target_source_artifact", "MFT")) for r in rows}
    extset = {e.lower().lstrip(".") for e in exts}

    def allowed(fn, parent):
        if keyword and not keyword_matches(keyword, parent, fn):
            return False
        ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
        return all_files or not extset or ext in extset

    # v1.0: when MFT is available, MFT is the authoritative target inventory.
    # USN and LogFile rows are evidence to be attached to MFT targets, not additional
    # primary targets. This prevents directory/root rows such as "Percobaan Ketujuh"
    # from being promoted as suspicious targets just because a journal record exists.
    # If MFT is absent or filtered to zero rows, fall back to USN/LogFile targets.
    use_artifact_fallback_targets = (len(rows) == 0)

    if use_artifact_fallback_targets:
        for r in data.get("usn", []):
            fn = s(r.get("Name")) or s(r.get("FileName")) or s(r.get("File/Directory Name"))
            fullp = s(r.get("FullPath")) or s(r.get("Path")) or s(r.get("FilePath"))
            parent = s(r.get("ParentPath"))
            if not parent and fullp:
                fp_norm = fullp.replace("/", "\\")
                if fn and fp_norm.lower().endswith("\\" + fn.lower()):
                    parent = fp_norm[:-(len(fn)+1)]
                else:
                    parent = fp_norm
            # Prefer file-like USN fallback targets; extensionless directory labels are context only.
            ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
            if fn and ext and allowed(fn, parent):
                _add_target(rows, seen, fn, parent, ext, "USN")

        for r in data.get("log", []):
            p = _path_from_generic_row(r)
            fn = _name_from_generic_row(r)
            parent = str(Path(p.replace("\\", "/")).parent).replace("/", "\\") if p and "/" in p.replace("\\", "/") else ""
            ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
            if fn and ext and allowed(fn, parent):
                _add_target(rows, seen, fn, parent, ext, "LogFile")

    # v1.0: LNK files are context evidence, not primary file-level targets, whenever
    # a primary artifact exists. Earlier versions could produce a dashboard containing
    # only *.lnk rows when the user selected Recent folders but did not import MFT/USN/LogFile.
    # This made the output look "empty" for the real case. Therefore, LNK becomes a
    # target source only in a true LNK-only run where no MFT/USN/LogFile/Prefetch data exists.
    primary_context_available = any(len(data.get(k, [])) > 0 for k in ["mft", "usn", "log", "pf"])
    if not primary_context_available:
        for source_key, source_name in [("lnk_w", "LNK-WindowsRecent"), ("lnk_o", "LNK-OfficeRecent")]:
            for r in data.get(source_key, []):
                p = _path_from_generic_row(r)
                fn = _name_from_generic_row(r)
                parent = str(Path(p.replace("\\", "/")).parent).replace("/", "\\") if p and "/" in p.replace("\\", "/") else ""
                if fn and allowed(fn, parent):
                    _add_target(rows, seen, fn, parent, "", source_name)

    # Prefetch-only mode: executable is context target; still output Normal/Need Review instead of failing.
    for r in data.get("pf", []):
        fn = s(r.get("ExecutableName")) or _name_from_generic_row(r)
        if fn and allowed(fn, "Prefetch"):
            _add_target(rows, seen, fn, "Prefetch", "exe" if "." not in fn else "", "Prefetch")

    rows.sort(key=lambda x: (x["relative_path"].lower(), x["target_name"].lower(), x.get("target_source_artifact", "")))
    return rows

def select_mft(mft: List[Dict[str, str]], target: str, folder="") -> Optional[Dict[str, str]]:
    c = [r for r in mft if lower(r.get("FileName")) == target.lower() and lower(r.get("IsAds")) != "true" and lower(r.get("IsDirectory")) != "true"]
    if not c:
        return None
    c = [r for r in c if lower(r.get("InUse")) == "true"] or c
    c = [r for r in c if "$recycle.bin" not in lower(r.get("ParentPath"))] or c
    if folder:
        c = [r for r in c if folder.lower() in lower(r.get("ParentPath"))] or c
    c.sort(key=lambda r: parse_int(r.get("EntryNumber")), reverse=True)
    return c[0]


def select_mft_for_target(mft: List[Dict[str, str]], t: Dict[str, str]) -> Optional[Dict[str, str]]:
    """v1.0: prefer exact MFT identity carried by target row."""
    entry = parse_int(t.get("mft_entry_hint"), -1)
    seq = parse_int(t.get("mft_sequence_hint"), -1)
    if entry >= 0 and seq >= 0:
        for r in mft:
            if parse_int(r.get("EntryNumber"), -2) == entry and parse_int(r.get("SequenceNumber"), -3) == seq:
                return r
        for r in mft:
            if parse_int(r.get("EntryNumber"), -2) == entry:
                return r
    return select_mft(mft, s(t.get("target_name")), s(t.get("folder")))

def mft_features(r: Optional[Dict[str, str]]) -> Dict[str, object]:
    if not r:
        base = {k: "" for k in [
            "mft_entry", "mft_sequence", "mft_lsn", "mft_parent_path", "mft_si_created", "mft_si_modified", "mft_si_accessed",
            "mft_si_record_changed", "mft_fn_created", "mft_fn_modified", "mft_fn_accessed", "mft_fn_record_changed"
        ]}
        base.update({"mft_found": "No", "mft_si_fn_mismatch": "No", "mft_usec_zeros": "No"})
        return base

    mismatch = lower(r.get("SI<FN")) == "true"
    pairs = [
        ("Created0x10", "Created0x30"),
        ("LastModified0x10", "LastModified0x30"),
        ("LastAccess0x10", "LastAccess0x30"),
        ("LastRecordChange0x10", "LastRecordChange0x30"),
    ]
    for a, b in pairs:
        if s(r.get(a)) and s(r.get(b)) and s(r.get(a)) != s(r.get(b)):
            mismatch = True

    return {
        "mft_found": "Yes",
        "mft_entry": r.get("EntryNumber", ""),
        "mft_sequence": extract_first_value(r, ["SequenceNumber", "Sequence", "Seq"], ["sequence"]),
        "mft_lsn": extract_first_value(r, ["LogfileSequenceNumber", "Logfile Sequence Number", "LogFile Sequence Number", "LogFileSequenceNumber", "LSN"], ["logfile", "sequence"]),
        "mft_parent_path": r.get("ParentPath", ""),
        "mft_si_created": r.get("Created0x10", ""),
        "mft_si_modified": r.get("LastModified0x10", ""),
        "mft_si_accessed": r.get("LastAccess0x10", ""),
        "mft_si_record_changed": r.get("LastRecordChange0x10", ""),
        "mft_fn_created": r.get("Created0x30", ""),
        "mft_fn_modified": r.get("LastModified0x30", ""),
        "mft_fn_accessed": r.get("LastAccess0x30", ""),
        "mft_fn_record_changed": r.get("LastRecordChange0x30", ""),
        "mft_si_fn_mismatch": "Yes" if mismatch else "No",
        "mft_usec_zeros": "Yes" if lower(r.get("uSecZeros")) == "true" else "No",
    }

def _norm_for_path_match(x: object) -> str:
    t = lower(x).replace("/", "\\")
    t = t.replace('"', '').strip()
    while "\\\\" in t:
        t = t.replace("\\\\", "\\")
    if t.startswith(".\\"):
        t = t[2:]
    return t.strip("\\")

def _path_match_candidates(folder: str) -> List[str]:
    f = _norm_for_path_match(folder)
    if not f:
        return []
    parts = [x for x in f.split("\\") if x and x != "."]
    cands = []
    if f:
        cands.append(f)
    # Last components are robust across drive-letter / mounted-folder differences.
    for n in (5, 4, 3, 2, 1):
        if len(parts) >= n:
            cands.append("\\".join(parts[-n:]))
    # Deduplicate while preserving order and avoid one-character junk.
    out = []
    for c in cands:
        c = c.strip("\\")
        if len(c) >= 3 and c not in out:
            out.append(c)
    return out

def _row_text_norm(r: Dict[str, str]) -> str:
    return _norm_for_path_match(row_text(r))

def _filter_rows_by_target_and_folder(rows: List[Dict[str, str]], target: str, folder: str, row_name_func) -> List[Dict[str, str]]:
    # v1.0: strict path-aware matching.  Earlier versions still fell back to
    # name-only matching when an artifact row did not expose a usable path.  That
    # contaminated repeated controlled-test file names across folders such as
    # Uji 15.docx in 00_SOURCE_ORIGINAL, S01, S02, S04, and S08.
    #
    # Principle: if the target has a known folder, USN/$LogFile evidence must either
    # match that folder/path (or MFT reference when available in a future build), or
    # it is treated as unavailable evidence for that specific logical file.  Missing
    # path evidence is safer than merging unrelated folders.
    base = [r for r in rows if lower(row_name_func(r)) == target.lower() or target.lower() in _row_text_norm(r)]
    if not base:
        return []
    cands = _path_match_candidates(folder)
    if cands:
        path_filtered = []
        for r in base:
            txt = _row_text_norm(r)
            if any(c in txt for c in cands):
                path_filtered.append(r)
        if path_filtered:
            return path_filtered
        # Strict rule: when folder is known but no path candidate matches, do not
        # fall back to name-only matches.  This prevents false delayed-BasicInfo
        # anchors from other copies of the same filename.
        return []
    return base

def usn_features(usn: List[Dict[str, str]], target: str, folder: str = "", entry_number: object = "", sequence_number: object = "") -> Dict[str, object]:
    # Accept MFTECmd and NTFS Log Tracker columns.
    def row_name(r):
        return s(r.get("Name")) or s(r.get("FileName")) or s(r.get("File/Directory Name"))
    def row_reason(r):
        return s(r.get("UpdateReasons")) or s(r.get("EventInfo")) or s(r.get("Reason")) or s(r.get("Event"))
    def row_time(r):
        return s(r.get("UpdateTimestamp")) or s(r.get("TimeStamp(UTC+7)")) or s(r.get("Timestamp(UTC+7)")) or s(r.get("TimeStamp")) or s(r.get("Timestamp")) or s(r.get("Time"))

    # v1.0 MFT-centered evidence linking. USN ParentPath may be blank; attach by EntryNumber + SequenceNumber.
    rows = []
    entry_i = parse_int(entry_number, -1)
    seq_i = parse_int(sequence_number, -1)
    if entry_i >= 0 and seq_i >= 0:
        rows = [r for r in usn if parse_int(r.get("EntryNumber"), -2) == entry_i and parse_int(r.get("SequenceNumber"), -3) == seq_i]
    if not rows and entry_i >= 0:
        rows = [r for r in usn if parse_int(r.get("EntryNumber"), -2) == entry_i]
    if not rows:
        rows = _filter_rows_by_target_and_folder(usn, target, folder, row_name)
    reasons = [row_reason(r) for r in rows]
    txt = "|".join(reasons).lower()
    compact_txt = compact_reason("|".join(reasons))

    def has(reason, *tokens):
        return reason_has(reason, *tokens)

    times = []
    create_times = []
    data_times = []
    basic_times = []
    close_times = []
    rename_times = []
    move_times = []
    delete_times = []
    basic_isolated = False
    ordered = []

    for r in rows:
        dt = parse_dt(row_time(r))
        reason = row_reason(r)
        if not dt:
            continue
        times.append(dt)
        labels = []
        if has(reason, "filecreate", "filecreated", "file_created", "file creation"):
            create_times.append(dt); labels.append("create")
        if has(reason, "dataextend", "dataoverwrite", "datatruncation", "dataextended", "dataoverwritten", "datatruncated", "data_added", "data overwritten", "data_overwritten", "data_truncated", "dataadded"):
            data_times.append(dt); labels.append("data")
        if has(reason, "basicinfochange", "basicinfochanged", "basic_info_changed", "basic info changed"):
            basic_times.append(dt); labels.append("basic")
            if not any(has(reason, tok) for tok in ["filecreate", "filecreated", "dataextend", "dataoverwrite", "datatruncation", "dataadded", "dataoverwritten", "datatruncated", "rename", "filemove", "filemoved"]):
                basic_isolated = True
        if has(reason, "close", "fileclosed", "file_closed"):
            close_times.append(dt); labels.append("close")
        if has(reason, "rename", "renamed"):
            rename_times.append(dt); labels.append("rename")
        if has(reason, "filemove", "filemoved", "file_move", "move"):
            move_times.append(dt); labels.append("move")
        if has(reason, "delete", "filedeleted", "file_deleted"):
            delete_times.append(dt); labels.append("delete")
        if labels:
            ordered.append((dt, labels, reason))

    arrival = []
    for r in rows:
        reason = row_reason(r)
        if any(has(reason, tok) for tok in ["filecreate", "filecreated", "dataextend", "dataoverwrite", "datatruncation", "dataadded", "dataoverwritten", "datatruncated", "close", "fileclosed", "basicinfochange", "basicinfochanged"]):
            dt = parse_dt(row_time(r))
            if dt:
                arrival.append(dt)

    first_create = min(create_times) if create_times else None
    first_basic = min(basic_times) if basic_times else None
    last_basic = max(basic_times) if basic_times else None

    delayed_basic = False
    delayed_gap = None
    if first_create and first_basic:
        delayed_gap = (first_basic - first_create).total_seconds()
        delayed_basic = delayed_gap > 60 and basic_isolated

    ordered.sort(key=lambda x: x[0])
    seq = []
    for _, labels, _ in ordered:
        for lab in labels:
            if not seq or seq[-1] != lab:
                seq.append(lab)
    seq_text = ">".join(seq)
    basic_move_basic = False
    for i, lab in enumerate(seq):
        if lab == "basic":
            for j in range(i+1, len(seq)):
                if seq[j] in {"move", "rename"}:
                    if "basic" in seq[j+1:]:
                        basic_move_basic = True
                    break
    multiple_isolated_basic = len(basic_times) >= 2 and basic_isolated and not data_times

    return {
        "usn_event_count": len(rows),
        "usn_first_time": fmt_dt(min(times) if times else None),
        "usn_last_time": fmt_dt(max(times) if times else None),
        "usn_arrival_candidate": fmt_dt(min(arrival) if arrival else (min(times) if times else None)),
        "usn_filecreate_first_time": fmt_dt(first_create),
        "usn_basicinfo_first_time": fmt_dt(first_basic),
        "usn_basicinfo_last_time": fmt_dt(last_basic),
        "usn_delayed_basicinfo_change": "Yes" if delayed_basic else "No",
        "usn_delayed_basicinfo_gap_sec": f"{delayed_gap:.2f}" if delayed_gap is not None else "",
        "usn_basicinfo_isolated": "Yes" if basic_isolated else "No",
        "usn_has_filecreate": "Yes" if create_times else "No",
        "usn_has_delete": "Yes" if delete_times else "No",
        "usn_has_basic_info_change": "Yes" if basic_times else "No",
        "usn_has_security_change": "Yes" if ("securitychange" in compact_txt or "securitychanged" in compact_txt) else "No",
        "usn_has_rename": "Yes" if (rename_times or move_times) else "No",
        "usn_has_data_change": "Yes" if data_times else "No",
        "usn_basic_move_basic_pattern": "Yes" if basic_move_basic else "No",
        "usn_multiple_isolated_basicinfo": "Yes" if multiple_isolated_basic else "No",
        "usn_sequence_compact": seq_text,
        "usn_reasons": join_unique(reasons, 20),
        "_usn_anchor": last_basic if basic_times else (max(times) if times else None),
    }

def log_features(log: List[Dict[str, str]], target: str, folder: str = "", entry_number: object = "", mft_lsn: object = "") -> Dict[str, object]:
    def log_row_name(r):
        return s(r.get("File/Directory Name")) or s(r.get("FileName")) or s(r.get("Name"))
    # v1.0 MFT-centered evidence linking. LogFile rows may lack path/name but keep Log_MFTReference.
    rows = []
    entry_i = parse_int(entry_number, -1)
    if entry_i >= 0:
        rows = [r for r in log if parse_int(r.get("Log_MFTReference") or r.get("lf_MFTReference") or r.get("MFTReference"), -2) == entry_i]
    if not rows:
        rows = _filter_rows_by_target_and_folder(log, target, folder, log_row_name)
    events = [r.get("Event", "") for r in rows]
    details = [r.get("Detail", "") for r in rows]
    txt = " ".join(events + details + [row_text(r) for r in rows]).lower()

    times = []
    for r in rows:
        dt = parse_dt(r.get("EventTime(UTC+7)")) or parse_dt(r.get("EventTime")) or parse_dt(r.get("Time")) or parse_dt(r.get("EventTimeUTC"))
        if dt:
            # 1601 and 0000-derived values are sentinel/noise, not event time anchors.
            if dt.year > 1980:
                times.append(dt)

    has_ts_update = (
        ("timestamp" in txt)
        or ("updating modified time" in txt)
        or ("updating mftmodified time" in txt)
        or ("si_ctime" in txt)
        or ("si_mtime" in txt)
        or ("si_atime" in txt)
        or ("si_rtime" in txt)
    )

    standard_info = (
        "$standard_information" in txt
        or "standard_information" in txt
        or "standardinformation" in txt
        or "currentattribute=$standard_information" in txt
    )

    update_resident = (
        "updateresidentvalue" in txt
        or "update resident value" in txt
        or "log_redooperation=updateresidentvalue" in txt
        or "lf_redooperation=updateresidentvalue" in txt
    )

    undo_redo_hint = ("undo" in txt and "redo" in txt) or ("log_redooperation" in txt) or ("log_undooperation" in txt)

    # Parse SI timestamp values from $LogFile detail. Values 0000 and 1601 are sentinel/incomplete and must not
    # become direct manipulation evidence.
    si_valid = []
    si_sentinel = []
    si_core_valid = []
    for r in rows:
        detail = row_text(r)
        for m in re.finditer(r"lf_SI_([CMAR])Time\s*=\s*([^|]+)", detail, re.I):
            label = m.group(1).upper()
            val = m.group(2).strip()
            dt = parse_dt(val)
            if dt and dt.year > 1980:
                si_valid.append(f"{label}:{fmt_dt(dt)}")
                if label in {"C", "M", "A"}:
                    si_core_valid.append(dt)
            else:
                si_sentinel.append(f"{label}:{val}")

    valid_si_count = len(si_core_valid)
    sentinel_only = bool(si_sentinel) and valid_si_count == 0
    valid_si_transition = standard_info and update_resident and valid_si_count >= 2

    lsn_vals = []
    prev_lsn_vals = []
    mft_refs = []
    attrs = []
    ops = []

    for r in rows:
        for key in ["Log_LSN", "lf_LSN", "lf_CurrentLsn", "lf_CurrentLSN", "LSN", "CurrentLsn", "CurrentLSN"]:
            if s(r.get(key)):
                lsn_vals.append(normalize_lsn_text(r.get(key)))
        for key in ["Log_PreviousLSN", "lf_PreviousLsn", "PreviousLsn", "PreviousLSN"]:
            if s(r.get(key)):
                prev_lsn_vals.append(normalize_lsn_text(r.get(key)))
        for key in ["Log_MFTReference", "lf_MFTReference", "lf_RealMFTReference", "MFTReference", "RealMFTReference", "FileReference"]:
            if s(r.get(key)):
                mft_refs.append(s(r.get(key)))
        for key in ["Log_CurrentAttribute", "lf_CurrentAttribute", "CurrentAttribute", "Attribute", "AttributeName"]:
            if s(r.get(key)):
                attrs.append(s(r.get(key)))
        for key in ["Log_RedoOperation", "Log_UndoOperation", "lf_RedoOperation", "lf_UndoOperation", "RedoOperation", "UndoOperation"]:
            if s(r.get(key)):
                ops.append(s(r.get(key)))

        detail = row_text(r)
        for pat in [
            r"(?:Log_LSN|lf_LSN|lf_CurrentLsn|LSN|CurrentLsn)\s*=\s*([0-9a-fA-Fx]+)",
            r"(?:Log_PreviousLSN|lf_PreviousLsn|PreviousLsn)\s*=\s*([0-9a-fA-Fx]+)",
        ]:
            for m in re.finditer(pat, detail, re.I):
                lsn_vals.append(normalize_lsn_text(m.group(1)))

    lsn_vals = [x for x in lsn_vals if x]
    prev_lsn_vals = [x for x in prev_lsn_vals if x]

    # Time reversal is only direct if explicit phrase exists or a valid SI transition is present.
    # Generic UpdateResidentValue with 0000/1601 is just transaction context.
    has_time_reversal_direct = ("time reversal" in txt) or valid_si_transition

    return {
        "logfile_event_count": len(rows),
        "logfile_has_time_reversal": "Yes" if has_time_reversal_direct else "No",
        "logfile_has_timestamp_update": "Yes" if has_ts_update else "No",
        "logfile_has_valid_si_timestamp": "Yes" if valid_si_count >= 1 else "No",
        "logfile_valid_si_timestamp_transition": "Yes" if valid_si_transition else "No",
        "logfile_valid_si_timestamp_count": valid_si_count,
        "logfile_only_sentinel_si_timestamps": "Yes" if sentinel_only else "No",
        "logfile_valid_si_values": join_unique(si_valid, 12),
        "logfile_has_rename": "Yes" if "renaming file" in txt else "No",
        "logfile_events": join_unique(events, 20),
        "logfile_first_time": fmt_dt(min(times) if times else None),
        "logfile_last_time": fmt_dt(max(times) if times else None),
        "logfile_lsn_values": join_unique(lsn_vals, 20),
        "logfile_previous_lsn_values": join_unique(prev_lsn_vals, 20),
        "logfile_mft_references": join_unique(mft_refs, 20),
        "logfile_current_attributes": join_unique(attrs, 20),
        "logfile_operations": join_unique(ops, 20),
        "logfile_standard_information_update": "Yes" if standard_info else "No",
        "logfile_update_resident_value": "Yes" if update_resident else "No",
        "logfile_undo_redo_hint": "Yes" if undo_redo_hint else "No",
        "_log_anchor": max(times) if times else None,
    }

def relative_features(mf: Dict[str, object], anchor: Optional[datetime], threshold: int) -> Dict[str, object]:
    c = parse_dt(mf.get("mft_si_created"))
    m = parse_dt(mf.get("mft_si_modified"))
    a = parse_dt(mf.get("mft_si_accessed"))
    e = parse_dt(mf.get("mft_si_record_changed"))

    dc, dm, da, de = [delta_days(anchor, x) for x in [c, m, a, e]]

    def back(d): return d is not None and d > threshold
    def near(d): return d is not None and abs(d) <= 2

    cma = sum([back(dc), back(dm), back(da)])
    mace = sum([back(dc), back(dm), back(da), back(de)])
    e_near = near(de)

    times = [x for x in [c, m, a, e] if x]
    spread = (max(times) - min(times)).total_seconds() / 86400.0 if len(times) >= 2 else 0.0

    full_cli = mace >= 3 and back(de)
    gui_api = cma >= 2 and (e_near or not back(de))
    non_uniform = cma >= 2 and spread > threshold
    rel = cma >= 2 or mace >= 2

    return {
        "anchor_time": fmt_dt(anchor),
        "relative_threshold_days": threshold,
        "delta_c_days": fmt_days(dc),
        "delta_m_days": fmt_days(dm),
        "delta_a_days": fmt_days(da),
        "delta_e_days": fmt_days(de),
        "mft_cma_backdated_count": cma,
        "mft_mace_backdated_count": mace,
        "mft_relative_backdated": "Yes" if rel else "No",
        "mft_full_cli_timestomp_pattern": "Yes" if full_cli else "No",
        "mft_gui_api_setter_pattern": "Yes" if gui_api else "No",
        "mft_non_uniform_timestamp_anomaly": "Yes" if non_uniform else "No",
        "timestamp_spread_days": f"{spread:.2f}",
        "mft_entry_changed_near_anchor": "Yes" if e_near else "No",
    }

def prefetch_events(pf: List[Dict[str, str]]) -> List[Dict[str, object]]:
    cols = ["LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3", "PreviousRun4", "PreviousRun5", "PreviousRun6"]
    out = []
    for r in pf:
        exe = s(r.get("ExecutableName")) or (Path(s(r.get("SourceFilename"))).name.split("-")[0] if s(r.get("SourceFilename")) else "")
        for col in cols:
            dt = parse_dt(r.get(col))
            if dt:
                out.append({
                    "executable": exe,
                    "run_time": dt,
                    "run_count": parse_int(r.get("RunCount")),
                    "source_file": s(r.get("SourceFilename")),
                })
    return out

TIMESTAMP_TOOL_KEYS = ("NTIMESTOMP", "TIMESTOMP", "SETMACE", "NEWFILETIME", "SETFILETIME", "BULKFILECHANGER")
TIMESTAMP_TOOL_EXACT = {"TOUCH.EXE"}
ATTRIBUTE_TOOL_KEYS = ("ATTRIB.EXE", "ICACLS.EXE", "TAKEOWN.EXE")

def looks_like_attribute_tool(text: object) -> bool:
    raw = s(text).upper().replace("\\", "/")
    if not raw:
        return False
    base = re.split(r"[/]", raw)[-1]
    base = re.sub(r"-[A-F0-9]{6,}\.PF$", ".EXE", base)
    return base in ATTRIBUTE_TOOL_KEYS or any(k in raw for k in ATTRIBUTE_TOOL_KEYS)

def looks_like_timestamp_tool(text: object) -> bool:
    """Safer tool-name recognition.

    Known distinctive tool names may match substrings (e.g. Prefetch name with hash),
    but generic TOUCH only matches exact executable basename TOUCH.EXE.
    """
    raw = s(text).upper().replace("\\", "/")
    if not raw:
        return False
    base = re.split(r"[/]", raw)[-1]
    base = re.sub(r"-[A-F0-9]{6,}\.PF$", ".EXE", base)
    if base in TIMESTAMP_TOOL_EXACT:
        return True
    return any(k in raw for k in TIMESTAMP_TOOL_KEYS)

COMMON = {
    "EXPLORER.EXE", "RUNTIMEBROKER.EXE", "SVCHOST.EXE", "DLLHOST.EXE", "CONHOST.EXE",
    "NOTEPAD.EXE", "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE",
    "CMD.EXE", "POWERSHELL.EXE", "WINDOWSTERMINAL.EXE", "FSUTIL.EXE",
    "FTK IMAGER.EXE", "AUTOPSY64.EXE", "PYTHON.EXE", "PY.EXE",
    "PECMD.EXE", "LECMD.EXE", "MFTECMD.EXE",
    # generic/system/application context executables; they may be displayed but
    # should not outrank a known timestamp tool for BestCandidate.
    "STOREDESKTOPEXTENSION.EXE", "SETUPDIAG.EXE", "MSEDGEWEBVIEW2.EXE",
    "DISMHOST.EXE", "CLEANMGR.EXE", "FILECOAUTH.EXE", "OFFICESVCMGR.EXE",
    "WINDOWSUPDATEBOX.EXE",
}

def prefetch_features(events: List[Dict[str, object]], anchors: List[Tuple[str, datetime]], has_anomaly: bool, window: int) -> Dict[str, object]:
    valid = []
    seen = set()
    for label, dt in anchors:
        if isinstance(dt, datetime):
            key = (label, dt.isoformat(sep=" "))
            if key not in seen:
                seen.add(key)
                valid.append((label, dt))

    anchor_text = " | ".join([f"{label}={dt.isoformat(sep=' ')}" for label, dt in valid])

    if not valid or not has_anomaly:
        return {
            "prefetch_anchor_time": anchor_text,
            "prefetch_candidate_count": 0,
            "prefetch_candidates": "",
            "prefetch_best_candidate": "",
            "prefetch_best_delta_min": "",
            "prefetch_best_anchor": "",
            "prefetch_has_low_run_candidate": "No",
            "prefetch_masquerade_hint": "No",
        }

    cand = []
    for ev in events:
        exe = s(ev["executable"])
        up = exe.upper()
        if not exe:
            continue
        is_timestamp_tool = looks_like_timestamp_tool(up)
        if up in COMMON and not is_timestamp_tool:
            continue
        run_time = ev["run_time"]
        run_count = parse_int(ev["run_count"])
        if not isinstance(run_time, datetime):
            continue
        # Low run-count is useful for unknown executables. Known timestamp tools
        # remain relevant even if run count is higher because repeated tool use is
        # expected in controlled and real cases.
        if is_timestamp_tool:
            if not (0 < run_count <= 80):
                continue
        else:
            if not (0 < run_count <= 8):
                continue

        best = None
        for label, anchor_dt in valid:
            delta = abs((run_time - anchor_dt).total_seconds()) / 60
            if delta <= window:
                item = (delta, run_count, label, ev)
                if best is None or item[0] < best[0]:
                    best = item
        if best:
            cand.append(best)

    dedup = {}
    for delta, run_count, label, ev in cand:
        key = (s(ev["executable"]), ev["run_time"].isoformat(sep=" "))
        if key not in dedup or delta < dedup[key][0]:
            dedup[key] = (delta, run_count, label, ev)

    cand = list(dedup.values())

    def is_tool_item(x):
        exe = s(x[3]["executable"]).upper()
        return looks_like_timestamp_tool(exe)

    def is_attribute_item(x):
        exe = s(x[3]["executable"]).upper()
        return looks_like_attribute_tool(exe)

    # v1.0: attribute/metadata tools (e.g. ATTRIB.EXE) exactly at the
    # BasicInfoChange/metadata anchor must outrank a timestomping tool that is
    # merely in the broad window. This prevents attrib +H/-H or +R/-R normal
    # activity from being narrated as tool-correlated timestomping.
    def prefetch_rank(x):
        delta = x[0]
        if is_attribute_item(x) and delta <= 2.0:
            return (0, delta, x[1])
        if is_tool_item(x):
            return (1, delta, x[1])
        if is_attribute_item(x):
            return (2, delta, x[1])
        return (3, delta, x[1])

    cand.sort(key=prefetch_rank)
    attr_chosen = [x for x in cand if is_attribute_item(x) and x[0] <= 2.0][:2]
    known_chosen = [x for x in cand if is_tool_item(x)][:4]
    other_chosen = [x for x in cand if (not is_tool_item(x) and not (is_attribute_item(x) and x[0] <= 2.0))][:4]
    chosen = (attr_chosen + known_chosen + other_chosen)[:8]
    best = chosen[0] if chosen else None

    generic = ["SVCHOST", "UPDATE", "HELPER", "SERVICE", "HOST", "SYSTEM", "ANTIVIRUS"]
    masq = False
    if best:
        b = s(best[3]["executable"]).upper()
        masq = any(g in b for g in generic) and b not in COMMON

    def fmt_item(x):
        delta, run_count, label, ev = x
        return f"{ev['executable']}@{ev['run_time']} Δ={delta:.1f}m anchor={label} RunCount={run_count}"

    return {
        "prefetch_anchor_time": anchor_text,
        "prefetch_candidate_count": len(cand),
        "prefetch_candidates": " | ".join(fmt_item(x) for x in chosen),
        "prefetch_best_candidate": s(best[3]["executable"]) if best else "",
        "prefetch_best_delta_min": f"{best[0]:.2f}" if best else "",
        "prefetch_best_anchor": s(best[2]) if best else "",
        "prefetch_has_low_run_candidate": "Yes" if cand else "No",
        "prefetch_masquerade_hint": "Yes" if masq else "No",
    }

def lnk_features(rows: List[Dict[str, str]], target: str) -> Dict[str, object]:
    hits = [r for r in rows if target.lower() in lower(row_text(r))]
    return {
        "lnk_hit_count": len(hits),
        "lnk_sources": join_unique([r.get("SourceFile", "") for r in hits], 5),
    }



def lsn_transition_features(mf: Dict[str, object], lf: Dict[str, object]) -> Dict[str, object]:
    """
    LSN-linked transition scoring.

    Bukan sekadar memakai LSN sebagai nomor transaksi.
    Ide utamanya:
    - ambil MFT record header LSN
    - cari LSN terkait pada $LogFile CSV
    - jika cocok dan transaksi menyentuh $STANDARD_INFORMATION / UpdateResidentValue,
      maka current MFT state punya keterkaitan kausal dengan transaksi metadata.
    """
    mft_lsn = normalize_lsn_text(mf.get("mft_lsn"))
    mft_lsn_int = lsn_to_int(mft_lsn)

    log_lsn_text = s(lf.get("logfile_lsn_values"))
    log_lsn_values = [normalize_lsn_text(x.strip()) for x in re.split(r"\s*\|\s*", log_lsn_text) if x.strip()]
    log_lsn_ints = [lsn_to_int(x) for x in log_lsn_values]
    log_lsn_ints = [x for x in log_lsn_ints if x is not None]

    exact = False
    near = False
    if mft_lsn:
        exact = any(x == mft_lsn for x in log_lsn_values)
    if mft_lsn_int is not None and log_lsn_ints:
        exact = exact or any(x == mft_lsn_int for x in log_lsn_ints)
        # $MFT header LSN kadang menunjuk transaksi terakhir record, sedangkan CSV bisa berisi record sekitar.
        # Near match bukan bukti final, tetapi indikasi bahwa transaksi berada dalam cluster urutan dekat.
        near = any(abs(x - mft_lsn_int) <= 8 for x in log_lsn_ints)

    std = lf.get("logfile_standard_information_update") == "Yes"
    upd = lf.get("logfile_update_resident_value") == "Yes"
    undo_redo = lf.get("logfile_undo_redo_hint") == "Yes"
    ts = lf.get("logfile_has_timestamp_update") == "Yes" or lf.get("logfile_has_time_reversal") == "Yes"

    strength = 0
    reasons = []
    if exact and std and (upd or ts or undo_redo):
        strength += 8
        reasons.append("MFT record header LSN EXACT match dengan $LogFile metadata/timestamp transaction")
    elif near and std and (upd or ts or undo_redo):
        strength += 6
        reasons.append("MFT record header LSN NEAR match dengan transaksi $LogFile metadata/timestamp")
    elif std and (upd or ts or undo_redo):
        # Konteks penting, tetapi tidak cukup untuk menaikkan file normal menjadi suspicious.
        # $STANDARD_INFORMATION update bisa terjadi pada operasi normal create/open/save.
        strength += 2
        reasons.append("$LogFile menunjukkan $STANDARD_INFORMATION update, tetapi tanpa LSN exact/near match")
    elif ts:
        strength += 1
        reasons.append("$LogFile menunjukkan timestamp update tanpa LSN match")

    # LSN-linked candidate harus ketat: exact/near match wajib.
    if not (exact or near):
        strength = min(strength, 3)

    return {
        "lsn_mft_record_lsn": mft_lsn,
        "lsn_logfile_values": log_lsn_text,
        "lsn_exact_match": "Yes" if exact else "No",
        "lsn_near_match": "Yes" if near else "No",
        "lsn_standard_information_update": "Yes" if std else "No",
        "lsn_update_resident_value": "Yes" if upd else "No",
        "lsn_undo_redo_hint": "Yes" if undo_redo else "No",
        "lsn_transition_candidate": "Yes" if strength >= 4 else "No",
        "lsn_transition_strength": strength,
        "lsn_transition_reasons": "; ".join(reasons),
    }


def lowlevel_features(mf: Dict[str, object], uf: Dict[str, object], lf: Dict[str, object], rf: Dict[str, object], lsnf: Dict[str, object]=None) -> Dict[str, object]:
    """
    Low-level timestamp mutation detector.

    Tujuan:
    - mendeteksi manipulasi timestamp kecil/near-time yang tidak melewati threshold backdating 180 hari.
    - memakai jejak low-level: LogFile timestamp update, USN BasicInfoChange, SI/FN delta, future timestamp,
      dan pola sub-second/FILETIME yang mencurigakan.

    Catatan:
    - Ini belum menggantikan decoding Redo/Undo mentah dari $LogFile.
    - Ini adalah layer low-level heuristic berbasis output LogFileParser/MFTECmd/USN yang tersedia.
    """
    lsnf = lsnf or {}
    anchor = parse_dt(rf.get("anchor_time"))
    si_fields = [
        ("C", mf.get("mft_si_created")),
        ("M", mf.get("mft_si_modified")),
        ("A", mf.get("mft_si_accessed")),
        ("E", mf.get("mft_si_record_changed")),
    ]
    fn_fields = [
        ("C", mf.get("mft_fn_created")),
        ("M", mf.get("mft_fn_modified")),
        ("A", mf.get("mft_fn_accessed")),
        ("E", mf.get("mft_fn_record_changed")),
    ]

    # 100-ns / sub-second pattern.
    # Banyak tool timestomping memakai waktu "bulat" atau pola artifisial seperti .1234567.
    suspicious_fraction = 0
    zero_fraction = 0
    rounded_second = 0
    fractions = []

    for label, val in si_fields:
        text = s(val)
        m = re.search(r"\.(\d{1,7})", text)
        if m:
            frac = m.group(1).ljust(7, "0")[:7]
            fractions.append(f"{label}:{frac}")
            if frac == "0000000":
                zero_fraction += 1
                suspicious_fraction += 1
            if frac == "1234567":
                suspicious_fraction += 1
        else:
            # Tidak ada pecahan detik sama sekali: anggap rounded-to-second.
            if parse_dt(text):
                rounded_second += 1

    # Future timestamp: timestamp file lebih baru daripada anchor investigatif.
    future_fields = []
    if isinstance(anchor, datetime):
        tolerance = timedelta(minutes=5)
        for label, val in si_fields:
            dt = parse_dt(val)
            if dt and dt > anchor + tolerance:
                future_fields.append(f"{label}:{fmt_dt(dt)}")

    # SI/FN field-level delta.
    # Ini berbeda dari sekadar SI/FN mismatch. Kita ukur beda menit pada field yang sama.
    max_delta_min = 0.0
    delta_pairs = []
    for (label1, si_val), (label2, fn_val) in zip(si_fields, fn_fields):
        if label1 != label2:
            continue
        si_dt = parse_dt(si_val)
        fn_dt = parse_dt(fn_val)
        if si_dt and fn_dt:
            delta = abs((si_dt - fn_dt).total_seconds()) / 60.0
            max_delta_min = max(max_delta_min, delta)
            if delta >= 4:
                delta_pairs.append(f"{label1}:{delta:.1f}m")

    # Metadata/transaction evidence from low-level artifacts.
    logfile_update = lf.get("logfile_has_timestamp_update") == "Yes" or lf.get("logfile_has_time_reversal") == "Yes"
    usn_basic = uf.get("usn_has_basic_info_change") == "Yes"
    usn_data = uf.get("usn_has_data_change") == "Yes"

    # Time spread in SI timestamps. Near-time manipulation can still produce odd internal spread.
    try:
        spread_days = float(s(rf.get("timestamp_spread_days")) or "0")
    except Exception:
        spread_days = 0.0

    # Candidate logic:
    # 1. Future timestamp is strong.
    # 2. SI/FN field delta + LogFile/USN metadata evidence is strong.
    # 3. Suspicious sub-second pattern + LogFile/USN evidence is strong.
    # 4. Rounded seconds + SI/FN delta is moderate.
    # 5. Spread > 30 minutes + metadata evidence is moderate.
    reasons = []
    strength = 0

    # Future/accessed-only guard: Accessed-only future is weak context, not mutation strength.
    future_non_access = [x for x in future_fields if not x.startswith("A:")]
    if future_non_access and (logfile_update or usn_basic):
        strength += 5
        reasons.append("future timestamp non-Access terhadap anchor")
    elif future_fields:
        reasons.append("future Accessed-only terhadap anchor (weak context)")

    delta_non_access = [x for x in delta_pairs if not x.startswith("A:")]
    if delta_non_access and (logfile_update or usn_basic):
        strength += 4
        reasons.append("SI/FN field-level delta non-Access >=4 menit + metadata/journal support")
    elif delta_non_access:
        # v1.0: A strong SI/FN non-access delta remains meaningful even when
        # USN/LogFile path matching is unavailable. It should not be mislabeled
        # as Accessed-only. The final decision layer still prevents this from
        # becoming Suspicious High inside normal/context folders.
        strength += 3
        reasons.append("SI/FN field-level delta non-Access >=4 menit tanpa journal support")
    elif delta_pairs:
        reasons.append("SI/FN delta Accessed-only >=5 menit (weak context)")

    if suspicious_fraction >= 2 and (usn_basic or (logfile_update and delta_pairs)):
        strength += 4
        reasons.append("pola sub-second artifisial/100ns pada timestamp SI")

    if rounded_second >= 2 and delta_pairs and (logfile_update or usn_basic):
        strength += 3
        reasons.append("timestamp rounded-to-second + SI/FN delta")

    if spread_days >= (30.0 / 1440.0) and (usn_basic or delta_pairs) and not rf.get("mft_relative_backdated") == "Yes":
        strength += 2
        reasons.append("spread timestamp internal >30 menit dengan metadata-change evidence")

    # Metadata-only grammar: BasicInfoChange tanpa data change lebih kuat.
    if usn_basic and not usn_data and logfile_update:
        strength += 2
        reasons.append("metadata-only grammar: USN BasicInfoChange tanpa data write besar + LogFile update")

    # LSN-linked transaction is NOT a mutation-core by itself.
    # A normal create/save operation can also have MFT header LSN + $LogFile metadata update.
    # Therefore LSN is evaluated later in score(), together with mutation_core.
    lsn_linked_seen = lsnf.get("lsn_transition_candidate") == "Yes"
    if lsn_linked_seen and lsnf.get("lsn_transition_reasons") and strength > 0:
        reasons.append("LSN context available, evaluated separately: " + s(lsnf.get("lsn_transition_reasons")))

    candidate = strength >= 4

    return {
        "lowlevel_mode": "Enabled",
        "lowlevel_timestamp_mutation_candidate": "Yes" if candidate else "No",
        "lowlevel_strength": strength,
        "lowlevel_reasons": "; ".join(reasons),
        "lowlevel_suspicious_fraction_count": suspicious_fraction,
        "lowlevel_zero_fraction_count": zero_fraction,
        "lowlevel_rounded_second_count": rounded_second,
        "lowlevel_fraction_pattern": " | ".join(fractions),
        "lowlevel_future_timestamp": "Yes" if future_fields else "No",
        "lowlevel_future_fields": " | ".join(future_fields),
        "lowlevel_si_fn_delta_large": "Yes" if delta_pairs else "No",
        "lowlevel_si_fn_delta_pairs": " | ".join(delta_pairs),
        "lowlevel_max_si_fn_delta_min": f"{max_delta_min:.2f}",
        "lowlevel_metadata_only_grammar": "Yes" if (usn_basic and not usn_data and logfile_update) else "No",
    }


def score(row: Dict[str, object]) -> Dict[str, object]:
    """
    OATFD v1.0 / Evidence-Capped Plausibility Scoring (ECP).

    Formula ilmiah:
    - Manipulasi tidak diputuskan dari LSN/$LogFile/BasicInfoChange mentah.
    - Aplikasi membangun create_anchor dari USN FileCreate/arrival.
    - TP kuat dicari dari:
      1) delayed isolated BasicInfoChange + timestamp anomaly,
      2) event-anchored timestamp inconsistency; uniform MACE is only an anomaly indicator,
      3) valid $LogFile SI timestamp transition yang bukan 0000/1601,
      4) known timestomping tool + timestamp anomaly.
    - TN dicari dari pola operasi normal yang konsisten dengan anchor dan tidak memiliki direct TP rule.
    """

    def is_yes(v) -> bool:
        return str(v).strip().lower() in ("yes", "true", "1", "y", "ya")

    def fnum(v, default=0.0) -> float:
        try:
            if v is None or str(v).strip() == "" or str(v).lower() == "nan":
                return default
            return float(str(v).strip())
        except Exception:
            return default

    def contains_any(txt: object, keys) -> bool:
        t = s(txt).upper()
        return any(k.upper() in t for k in keys)

    def delta_pair_kinds(text_obj: object) -> set:
        t = s(text_obj).upper().replace(" ", "")
        kinds = set()
        for part in t.split("|"):
            if ":" in part:
                k = part.split(":", 1)[0].strip()
                if k:
                    kinds.add(k)
        return kinds

    def field_kinds(text_obj: object) -> set:
        return delta_pair_kinds(text_obj)

    def support_control_reason() -> str:
        # REALCASE v1.0: tidak ada label Excluded.
        # Fungsi ini sengaja tetap mengembalikan string kosong agar file support/temp
        # tidak dikeluarkan dari analisis. Guard kontekstual diterapkan di bawah,
        # setelah bukti USN/$LogFile/MFT dibaca.
        return ""

    support_reason = support_control_reason()
    if support_reason:
        row.update({
            "score": 0,
            "prediction": "Excluded",
            "prediction_type": "excluded_support_control_file",
            "mutation_core": "No",
            "normal_creation_guard": "No",
            "operation_type": "SUPPORT_CONTROL",
            "operation_normality_score": 0,
            "direct_manipulation_score": 0,
            "artifact_confidence_score": 0,
            "decision_margin": 0,
            "expected_pattern_match": "Not evaluated",
            "direct_manipulation_evidence": "No",
            "anchor_consistency": "Not evaluated",
            "delayed_basicinfo": "No",
            "uniform_mace_far_from_anchor": "No",
            "valid_logfile_transition": "No",
            "operation_reasoning": support_reason,
            "scoring_rule_version": SCORING_RULE_VERSION,
        "filename_bias_used": "ContextGuardOnly",
        "folder_label_used": "ContextGuardOnly",
        "dataset_label_bias_used": "False",
        "ground_truth_used_for_detection": "False",
        "all_file_detection_mode": "True",
        "evidence_basis": best_direct if str(prediction).startswith("Suspicious") else (best_operation if prediction == "Normal" else "ambiguous_evidence"),
            "reasons": "File kontrol/support/output aplikasi dikeluarkan dari target deteksi; bukan objek evaluasi timestamp.",
        })
        return row

    ext = s(row.get("extension")).lower().lstrip(".")
    usn_text = s(row.get("usn_reasons")).lower()
    low_text = s(row.get("lowlevel_reasons")).lower()
    pf_best = s(row.get("prefetch_best_candidate"))

    has_filecreate = is_yes(row.get("usn_has_filecreate")) or "filecreate" in usn_text or "file create" in usn_text
    has_delete = is_yes(row.get("usn_has_delete")) or "delete" in usn_text
    has_data = is_yes(row.get("usn_has_data_change")) or any(k in usn_text for k in ["dataextend", "dataoverwrite", "datatruncation"])
    has_close = "close" in usn_text or "fileclosed" in usn_text or "file_closed" in usn_text
    has_basic = is_yes(row.get("usn_has_basic_info_change")) or "basicinfochange" in usn_text or "basic_info_changed" in usn_text
    has_rename = is_yes(row.get("usn_has_rename")) or is_yes(row.get("logfile_has_rename")) or "rename" in usn_text
    has_security = is_yes(row.get("usn_has_security_change")) or "securitychange" in usn_text
    usn_basic_move_basic_pattern = is_yes(row.get("usn_basic_move_basic_pattern"))
    usn_multiple_isolated_basicinfo = is_yes(row.get("usn_multiple_isolated_basicinfo"))
    usn_only_suspicious_pattern = usn_basic_move_basic_pattern or usn_multiple_isolated_basicinfo

    lsn_linked = is_yes(row.get("lsn_exact_match")) or is_yes(row.get("lsn_near_match")) or is_yes(row.get("lsn_transition_candidate"))
    log_update = is_yes(row.get("logfile_standard_information_update")) or is_yes(row.get("logfile_has_timestamp_update")) or is_yes(row.get("lsn_standard_information_update"))
    valid_logfile_transition = is_yes(row.get("logfile_valid_si_timestamp_transition"))
    sentinel_log_only = is_yes(row.get("logfile_only_sentinel_si_timestamps"))
    log_time_reversal = is_yes(row.get("logfile_has_time_reversal")) and not sentinel_log_only

    low = is_yes(row.get("lowlevel_timestamp_mutation_candidate"))
    low_strength = fnum(row.get("lowlevel_strength"))
    delta_kinds = delta_pair_kinds(row.get("lowlevel_si_fn_delta_pairs"))
    future_kinds = field_kinds(row.get("lowlevel_future_fields"))
    si_fn_delta_non_access = bool(delta_kinds - {"A", "ACCESS", "ACCESSED"})
    si_fn_delta_access_only = bool(delta_kinds) and not si_fn_delta_non_access
    future_non_access = bool(future_kinds - {"A", "ACCESS", "ACCESSED"})
    future_access_only = bool(future_kinds) and not future_non_access

    rel_backdated = is_yes(row.get("mft_relative_backdated"))
    cli_pattern = is_yes(row.get("mft_full_cli_timestomp_pattern"))
    gui_pattern = is_yes(row.get("mft_gui_api_setter_pattern"))
    subsec_suspicious = fnum(row.get("lowlevel_suspicious_fraction_count")) >= 2 or fnum(row.get("lowlevel_zero_fraction_count")) >= 2

    si_vals = [
        parse_dt(row.get("mft_si_created")), parse_dt(row.get("mft_si_modified")),
        parse_dt(row.get("mft_si_accessed")), parse_dt(row.get("mft_si_record_changed")),
    ]
    fn_vals = [
        parse_dt(row.get("mft_fn_created")), parse_dt(row.get("mft_fn_modified")),
        parse_dt(row.get("mft_fn_accessed")), parse_dt(row.get("mft_fn_record_changed")),
    ]
    created, modified, accessed, entry_changed = si_vals
    fn_created, fn_modified, fn_accessed, fn_entry_changed = fn_vals

    create_anchor = (
        parse_dt(row.get("usn_filecreate_first_time"))
        or parse_dt(row.get("usn_arrival_candidate"))
        or parse_dt(row.get("usn_first_time"))
    )
    basic_first = parse_dt(row.get("usn_basicinfo_first_time"))
    basic_last = parse_dt(row.get("usn_basicinfo_last_time"))
    anchor = basic_last or parse_dt(row.get("anchor_time")) or parse_dt(row.get("usn_last_time")) or parse_dt(row.get("logfile_last_time"))

    known_tool = looks_like_timestamp_tool(pf_best + " " + s(row.get("prefetch_candidates")))
    attribute_tool_context = looks_like_attribute_tool(pf_best + " " + s(row.get("prefetch_candidates")))
    generic_exec = contains_any(pf_best, ["ANTIVIRUS", "SETUPDIAG", "SPEECHUXWIZ", "DISMHOST", "CLEANMGR", "EXPLORER", "SVCHOST", "WINWORD", "EXCEL", "POWERPNT", "MSACCESS", "WIDGETSERVICE"])

    i30_found = is_yes(row.get("i30_found"))
    i30_reliability = fnum(row.get("i30_reliability"), 0.0)
    i30_anchor_contradiction = is_yes(row.get("i30_anchor_contradiction")) and i30_reliability >= 0.50
    i30_uniform_mace_far = is_yes(row.get("i30_uniform_mace_far")) and i30_reliability >= 0.50
    i30_cma_e_split = is_yes(row.get("i30_cma_e_split")) and i30_reliability >= 0.50
    i30_cluster_shift = is_yes(row.get("i30_cluster_shift")) and i30_reliability >= 0.50
    i30_normal_write_support = is_yes(row.get("i30_normal_write_support")) and i30_reliability >= 0.50
    i30_sequence_reuse_signal = is_yes(row.get("i30_sequence_reuse_signal")) and i30_reliability >= 0.50
    i30_target_level = is_yes(row.get("i30_target_level"))
    i30_current_file_match = is_yes(row.get("i30_current_file_match"))
    i30_cma_moved_from_anchor = is_yes(row.get("i30_cma_moved_from_anchor"))
    i30_e_only_metadata_change = is_yes(row.get("i30_e_only_metadata_change"))
    i30_stale_entry = is_yes(row.get("i30_stale_entry"))
    if i30_stale_entry or not i30_target_level:
        i30_anchor_contradiction = False
        i30_uniform_mace_far = False
        i30_cma_e_split = False
        i30_cluster_shift = False
    i30_tunneling_raw_hint = is_yes(row.get("i30_tunneling_guard_hint")) and i30_reliability >= 0.50
    # v1.0: child_sequence/reuse is weak until corroborated by USN/log delete-create or rename.
    i30_tunneling_guard_hint = bool(i30_tunneling_raw_hint and (has_delete or has_rename) and has_filecreate and not delayed_basic)

    def classify_support_or_temp_file() -> str:
        """Context guard: keep the file in the scan, but avoid treating support/report/temp
        files as timestamp manipulation when the only signal is a weak timestamp-vector pattern.
        This is not an Excluded rule. It is a normal-context explanation.
        """
        name = s(row.get("target_name") or row.get("file_name")).strip().lower()
        rel = s(row.get("relative_path")).replace("/", "\\").lower()
        parent = s(row.get("mft_parent_path") or row.get("folder")).replace("/", "\\").lower()
        full_context = "\\" + rel + "\\" + parent + "\\" + name
        ext_here = s(row.get("extension")).lower().lstrip(".")
        manifest_names = SUPPORT_MANIFEST_NAMES if isinstance(SUPPORT_MANIFEST_NAMES, set) else set()
        rel_norm_for_manifest = rel.replace("\\", "/").strip("/")
        if name in manifest_names or rel_norm_for_manifest in manifest_names:
            return "experiment_support_report_file"

        # v1.0 target-role guard. Full-scope mode must read every file, but not every
        # file is an eligible primary timestamp-manipulation target. System metadata,
        # recycle-bin objects, forensic containers, support/report files, scripts,
        # executables, and DLLs are retained as context but cannot become high-confidence
        # timestamp manipulation merely from LogFile/LSN/metadata activity.
        system_metadata_exact = {
            "$objid", "$i30", "indexervolumeguid", "wpsettings.dat",
            "desktop.ini", "thumbs.db", "file system slack", "backup boot sector",
        }
        system_metadata_prefixes = (
            "$txflog", "$mft", "$logfile", "$bitmap", "$usnjrnl", "$secure",
            "$boot", "$volume", "$attrdef", "$objid", "$quota", "$reparse",
            "$badclus", "$upcase", "$extend", "$i30", "$index",
        )
        system_metadata_dirs = (
            "\\system volume information", "\\$extend", "\\$extend\\$rmmetadata",
            "\\programdata\\microsoft\\search",
        )
        if (
            name in system_metadata_exact
            or name.startswith(system_metadata_prefixes)
            or any(tok in full_context for tok in system_metadata_dirs)
            or "\\$extend\\$rmmetadata" in full_context
            or ext_here in {"blf"}
        ):
            return "system_metadata_artifact"
        if "$recycle.bin" in full_context or name.startswith(("$r", "$i")):
            return "recycle_bin_context_file"
        if ext_here in {"e01", "aff", "raw", "dd", "vhd", "vhdx"} or name.startswith(("ambil prefetch", "ambil prefecth")):
            return "forensic_image_container"
        if ext_here in {"pf", "lnk"} or "\\prefetch" in full_context or "lnk_windowsrecent" in full_context or "lnk_officerecent" in full_context:
            return "os_context_artifact"
        if ext_here in {"exe", "dll", "cmd", "bat", "ps1", "msi", "sys"}:
            # v1.0: do NOT automatically demote user-level executables/scripts.
            # Real malware and timestomped payloads are often .exe/.dll/.ps1. Treat only
            # clear OS/application locations as tool/program context unless strict legacy
            # program role gating is explicitly enabled.
            program_context_dirs = (
                "\\windows\\", "\\program files", "\\program files (x86)",
                "\\programdata\\", "\\appdata\\local\\microsoft", "\\appdata\\roaming\\microsoft",
            )
            if PROGRAM_ROLE_GATE_STRICT or any(tok in full_context for tok in program_context_dirs):
                return "tool_program_artifact"
            # user/workdir program files remain primary candidates; Prefetch/LNK rows were
            # already caught above as os_context_artifact.
        if DATASET_SUPPORT_TOKENS and (name.startswith(("00_log_", "00_daftar_", "run_", "visual_", "detection_", "case_reasoning", "timeline_", "suspicious_behavior_", "unique_detection_", "comparison_ready_", "all_file_classification", "before_manipulation", "hasil_timestamp", "action_log", "file_times_snapshot", "ground_truth")) or "timestomping_perfile" in name):
            return "experiment_support_report_file"
        if name.startswith("readme") or name.endswith((".md", ".log", ".ini")):
            return "documentation_support_file"

        # v1.0 directory/root-case guard. Directory labels and case-root shortcuts are
        # not file-level timestamp manipulation targets. They stay in the matrix only
        # as Normal context, never as high-confidence suspicious.
        target_source = s(row.get("target_source_artifact")).lower()
        ext_here = s(row.get("extension")).lower().lstrip(".")
        mft_found_here = s(row.get("mft_found")).lower() == "yes" or bool(s(row.get("mft_entry")))
        if (not ext_here) and (target_source in {"usn", "logfile", "lnk-windowsrecent", "lnk-officerecent"} or not mft_found_here):
            return "directory_or_case_root_context"

        # v1.0 no-label-leakage policy:
        # Folder/file tokens such as "normal", "aktifitas normal", or S01/S02
        # scenario names are NOT used as negative evidence during detection.
        # Normality must come from artifact grammar only, not dataset labels.

        exact_support_names = {
            "00_log_timestomping_perfile.csv",
            "00_log_timestomping_perfile.xlsx",
            "00_daftar_file_mace.xlsx",
            "run_summary.csv",
            "detection_matrix.csv",
            "case_reasoning.csv",
            "timeline_events.csv",
            "visual_summary_table.csv",
            "suspicious_behavior_detection.csv",
            "action_log.csv",
            "file_times_snapshot.csv",
            "ground_truth.csv",
        }
        report_prefixes = (
            "visual_dashboard",
            "nlt_suspicious_behavior_detection",
            "nlt_usnjrnl",
            "nlt_logfile",
            "action_log",
            "file_times_snapshot",
            "ground_truth",
            "run_summary",
            "detection_matrix",
            "case_reasoning",
            "timeline_events",
            "visual_summary_table",
            "suspicious_behavior_detection",
        )
        support_dirs = (
            "\\output_python",
            "\\validation_example",
            "\\raw_artifacts",
            "\\input_python",
        )

        if name.startswith("~$"):
            return "office_temporary_lock_file"
        # Office/Excel temporary working files are normal application artifacts unless
        # corroborated by strong non-name-based timestomping evidence. They must not
        # become high-confidence manipulation from BasicInfoChange alone.
        if (name.startswith(("~wrd", "~wrl")) and name.endswith(".tmp")) or (name.startswith("~") and name.endswith(".tmp")):
            return "office_temporary_work_file"
        if name in {"new microsoft excel worksheet.xlsx", "new microsoft word document.docx"}:
            return "office_generated_placeholder_file"
        # v1.0: archive outputs and recycle-bin entries are context artifacts, not direct
        # timestamp manipulation, unless there is independent strong timestomp evidence.
        # v1.0: controlled-normal folder names are intentionally ignored during
        # detection to prevent folder/name label leakage.
        if ext == "zip" or "normal_archive" in name or "archive_from" in name or "archive" in name:
            return "archive_output_context_file"
        if "$recycle.bin" in parent or "$recycle.bin" in rel or name.startswith(("$r", "$i")):
            return "recycle_bin_context_file"
        if DATASET_SUPPORT_TOKENS and name in exact_support_names:
            return "experiment_support_report_file"
        if DATASET_SUPPORT_TOKENS and any(name.startswith(pfx) for pfx in report_prefixes):
            return "generated_report_file"
        if DATASET_SUPPORT_TOKENS and any(token in rel or token in parent for token in support_dirs) and name.startswith(("00_", "run_", "visual_")):
            return "case_output_support_context"
        return ""

    support_temp_reason = classify_support_or_temp_file()
    support_or_temp_file = bool(support_temp_reason)
    controlled_normal_context = False  # v1.0: no folder/name normal-label context is used for detection.
    office_temp_file = support_temp_reason == "office_temporary_lock_file"
    hard_context_artifact = support_temp_reason in {
        "system_metadata_artifact",
        "recycle_bin_context_file",
        "forensic_image_container",
        "os_context_artifact",
        "tool_program_artifact",
        "experiment_support_report_file",
        "generated_report_file",
        "case_output_support_context",
        "documentation_support_file",
        "directory_or_case_root_context",
    }

    def target_role_label(reason: str) -> str:
        mapping = {
            "system_metadata_artifact": "System Metadata",
            "recycle_bin_context_file": "Recycle Bin Artifact",
            "forensic_image_container": "Forensic Container",
            "os_context_artifact": "OS Context Artifact",
            "tool_program_artifact": "Tool/Program Artifact",
            "experiment_support_report_file": "Experiment Support/Report File",
            "generated_report_file": "Experiment Support/Report File",
            "case_output_support_context": "Experiment Support/Report File",
            "documentation_support_file": "Documentation/Support File",
            "directory_or_case_root_context": "Directory/Case Root Context",
            "office_temporary_lock_file": "Context-Guarded File",
            "office_temporary_work_file": "Context-Guarded File",
            "office_generated_placeholder_file": "Context-Guarded File",
            "archive_output_context_file": "Context-Guarded File",
        }
        return mapping.get(reason, "Primary File Target" if not reason else "Context-Guarded File")

    # v1.0: target role is not a permanent exclusion.  Non-primary artifacts such as
    # scripts, executables, DLLs, documentation, recycle-bin files, and support logs may
    # still be suspicious in real cases, but they require stronger corroboration and must
    # be reported as role-aware anomaly classes rather than ordinary user-document hits.
    nonprimary_high_eligible_roles = {
        "tool_program_artifact",
        "documentation_support_file",
        "experiment_support_report_file",
        "generated_report_file",
        "case_output_support_context",
        "recycle_bin_context_file",
    }
    nonprimary_review_only_roles = {
        "system_metadata_artifact",
        "forensic_image_container",
        "os_context_artifact",
        "directory_or_case_root_context",
    }

    # ---- Anchor-vector features ----
    delayed_basic_gap = fnum(row.get("usn_delayed_basicinfo_gap_sec"), -1)
    delayed_basic = is_yes(row.get("usn_delayed_basicinfo_change")) or (has_basic and has_filecreate and delayed_basic_gap > 60)

    uniform_mace = False
    uniform_mace_far = False
    mace_anchor_gap_min = None
    if all(si_vals):
        spread = (max(si_vals) - min(si_vals)).total_seconds()
        uniform_mace = spread <= 1.0
        if create_anchor:
            mace_anchor_gap_min = min(abs((v - create_anchor).total_seconds()) for v in si_vals) / 60.0
            uniform_mace_far = uniform_mace and mace_anchor_gap_min > 5.0

    # EntryChanged can be near operation while C/M/A are backdated. Treat C/M/A uniform far as strong too.
    cma_uniform_far = False
    if all(si_vals[:3]) and create_anchor:
        cma_spread = (max(si_vals[:3]) - min(si_vals[:3])).total_seconds()
        cma_gap = min(abs((v - create_anchor).total_seconds()) for v in si_vals[:3]) / 60.0
        cma_uniform_far = cma_spread <= 1.0 and cma_gap > 5.0

    # v1.0: timestamp-copy / partial timestomp guard plus archive/recycle guards and low-level USN correction.
    # Accessed may be refreshed by normal access, so a suspicious C/M/E or C/M
    # cluster must not be suppressed as "access-only normal".
    def _cluster_spread_sec(vals):
        vals = [v for v in vals if isinstance(v, datetime)]
        if len(vals) < 2:
            return None
        return (max(vals) - min(vals)).total_seconds()

    def _far_from_anchor(vals, min_minutes=5.0):
        vals = [v for v in vals if isinstance(v, datetime)]
        if not vals:
            return False
        ref = create_anchor if isinstance(create_anchor, datetime) else (anchor if isinstance(anchor, datetime) else None)
        if isinstance(ref, datetime):
            return min(abs((v - ref).total_seconds()) for v in vals) / 60.0 > min_minutes
        if isinstance(accessed, datetime):
            return min(abs((v - accessed).total_seconds()) for v in vals) / 60.0 > min_minutes
        return False

    non_access_vals = [created, modified, entry_changed]
    cme_uniform_far = False
    cm_uniform_far = False
    cme_spread = _cluster_spread_sec(non_access_vals)
    if cme_spread is not None and len([v for v in non_access_vals if isinstance(v, datetime)]) == 3:
        cme_uniform_far = cme_spread <= 1.0 and _far_from_anchor(non_access_vals, 5.0)
    if isinstance(created, datetime) and isinstance(modified, datetime):
        cm_spread = abs((created - modified).total_seconds())
        cm_uniform_far = cm_spread <= 1.0 and _far_from_anchor([created, modified], 5.0)

    non_access_cluster_far = (cme_uniform_far or cm_uniform_far)

    # Accessed-only changes are generally weak/normal unless combined with direct evidence.
    access_only = (si_fn_delta_access_only or future_access_only) and not si_fn_delta_non_access and not future_non_access

    # v1.0 Attribute-AE Metadata Change Guard:
    # Delayed BasicInfoChange can be normal when caused by attrib/security/metadata
    # changes.  v1.0 handled E/ChangedTime-only deltas.  v1.0 extends this
    # to A+E-only deltas (Accessed + EntryModified/ChangedTime) while C/M remain
    # stable.  This protects normal attrib +H/-H and similar metadata/access-only
    # activity without whitelisting filenames or ground-truth labels.
    lowlevel_delta_pairs_raw = s(row.get("lowlevel_si_fn_delta_pairs"))
    _delta_pair_labels = []
    for _part in lowlevel_delta_pairs_raw.replace(",", "|").split("|"):
        _part = _part.strip()
        if ":" in _part:
            _delta_pair_labels.append(_part.split(":", 1)[0].strip().upper())

    _A_LABELS = {"A", "ACCESS", "ACCESSED", "ACCESSTIME", "LASTACCESS", "LASTACCESSTIME"}
    _E_LABELS = {"E", "ENTRY", "ENTRYMODIFIED", "CHANGED", "CHANGETIME", "ENTRYCHANGED", "RECORDCHANGED"}
    _C_LABELS = {"C", "CREATED", "CREATION", "CREATIONTIME"}
    _M_LABELS = {"M", "MODIFIED", "MODIFICATION", "MODIFICATIONTIME", "LASTWRITE", "LASTWRITETIME"}
    _AE_LABELS = _A_LABELS | _E_LABELS
    _CM_LABELS = _C_LABELS | _M_LABELS

    _delta_label_set = set(_delta_pair_labels)
    entry_only_nonaccess_delta = bool(
        si_fn_delta_non_access
        and _delta_label_set
        and _delta_label_set.issubset(_E_LABELS)
    )
    access_entry_only_delta = bool(
        si_fn_delta_non_access
        and _delta_label_set
        and _delta_label_set.issubset(_AE_LABELS)
        and bool(_delta_label_set & _E_LABELS)
        and not bool(_delta_label_set & _CM_LABELS)
    )

    # Future fields on A/E are also metadata/access context; future C/M remains suspicious.
    _future_label_set = set(future_kinds)
    future_non_access_strong = bool(future_non_access and bool(_future_label_set - _AE_LABELS))

    metadata_only_i30_guard = bool(i30_e_only_metadata_change and not i30_cma_moved_from_anchor)
    attribute_metadata_change_guard = bool(
        has_basic
        and (entry_only_nonaccess_delta or access_entry_only_delta or metadata_only_i30_guard)
        and not (uniform_mace_far or cma_uniform_far or non_access_cluster_far)
        and not (rel_backdated or cli_pattern or gui_pattern or future_non_access_strong or subsec_suspicious)
        and not (i30_anchor_contradiction or i30_uniform_mace_far or i30_cma_e_split or i30_cluster_shift)
    )

    # Once the attribute/access metadata guard is active, downstream scoring should not
    # continue treating A/E-only deltas as non-access timestamp mutation evidence.
    if attribute_metadata_change_guard:
        future_non_access = False

    si_fn_delta_non_access_scoring = bool(si_fn_delta_non_access and not attribute_metadata_change_guard)

    # Copy/archive signature: Created newer than Modified can be normal. It does not explain uniform full MACE far.
    copy_like_timestamp = False
    if created and modified:
        copy_like_timestamp = (created - modified).total_seconds() / 60.0 >= 1.0

    # ---- Operation normality scoring ----
    op_scores = {}
    op_reasons = []

    create_score = 0
    if has_filecreate:
        create_score += 3
        op_reasons.append("USN FileCreate indicates create/copy operation")
    if has_filecreate and (has_data or has_close):
        create_score += 3
        op_reasons.append("FileCreate + Data/Close is normal create/copy grammar")
    if create_anchor and created and abs((created - create_anchor).total_seconds()) <= 300 and not delayed_basic:
        create_score += 3
        op_reasons.append("SI.Created is near create anchor")
    if lsn_linked and log_update and has_filecreate and not valid_logfile_transition:
        create_score += 1
        op_reasons.append("LSN/$LogFile linkage is transaction context only")
    op_scores["CREATE_OR_COPY"] = create_score

    copy_score = 0
    if has_filecreate and (has_data or has_close) and copy_like_timestamp:
        copy_score += 6
        op_reasons.append("Created newer than Modified with FileCreate/Data/Close fits copy/archive extraction")
    if ext == "zip":
        copy_score += 6
        op_reasons.append("Archive file itself is normal archive output")
    op_scores["COPY_OR_ARCHIVE_EXTRACT"] = copy_score

    update_score = 0
    if has_data and has_close and not has_filecreate and not delayed_basic:
        update_score += 5
        op_reasons.append("DataWrite/DataExtend + Close fits normal update/save")
    if ext in {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pub", "accdb"} and (has_data or has_close) and not delayed_basic:
        update_score += 2
        op_reasons.append("Office-like document activity fits normal application save when no delayed BasicInfoChange")
    op_scores["UPDATE_SAVE"] = update_score

    rename_score = 0
    if has_rename and not delayed_basic:
        rename_score += 5
        op_reasons.append("Rename/Move can explain SI/FN differences")
    op_scores["RENAME_MOVE"] = rename_score

    attr_score = 0
    if has_basic and (attribute_metadata_change_guard or (not delayed_basic and not (si_fn_delta_non_access_scoring or future_non_access or uniform_mace_far or cma_uniform_far))):
        attr_score += 5
        op_reasons.append("BasicInfoChange inside normal burst without timestamp-vector anomaly")
    if has_security and not known_tool:
        attr_score += 2
        op_reasons.append("SecurityChange is normal metadata context")
    op_scores["ATTRIBUTE_METADATA_CHANGE"] = attr_score

    delete_recreate_score = 0
    if has_delete and has_filecreate and not delayed_basic:
        delete_recreate_score += 6
        op_reasons.append("Delete + FileCreate fits delete-recreate/tunneling candidate")
    op_scores["DELETE_RECREATE_TUNNELING"] = delete_recreate_score

    access_score = 0
    if access_only:
        access_score += 6
        op_reasons.append("Accessed-only anomaly is weak/normal when direct TP rules are absent")
    op_scores["ACCESS_ONLY_ACTIVITY"] = access_score

    best_operation = max(op_scores, key=op_scores.get)
    operation_normality_score = op_scores[best_operation]

    # ---- Direct manipulation evidence ----
    direct_scores = {}
    direct_reasons = []

    # v1.0: MACE seragam bukan bukti final. Ia hanya indikator anomali.
    # Bukti final harus berbasis inkonsistensi timestamp terhadap event aktual atau korelasi artefak.
    timestamp_vector_anomaly = si_fn_delta_non_access_scoring or future_non_access or rel_backdated or cli_pattern or gui_pattern
    uniform_indicator = uniform_mace_far or cma_uniform_far or non_access_cluster_far
    timestamp_anomaly = timestamp_vector_anomaly or uniform_indicator
    access_only_effective = access_only and not non_access_cluster_far

    normal_office_temp_grammar = (
        office_temp_file
        and has_filecreate
        and (has_data or has_close or has_basic or has_delete)
        and not delayed_basic
        and not known_tool
    )

    # Support/report/temp files may still be suspicious if there is strong direct evidence,
    # but not when the only signal is uniform MACE / weak timestamp-vector context.
    strong_override_for_support = (
        (not controlled_normal_context)
        and (not hard_context_artifact)
        and (
            (known_tool and (timestamp_vector_anomaly or delayed_basic or subsec_suspicious))
            or (delayed_basic and (si_fn_delta_non_access_scoring or future_non_access or subsec_suspicious or valid_logfile_transition))
            or (valid_logfile_transition and (known_tool or delayed_basic) and timestamp_vector_anomaly)
        )
    )

    basic_direct = 0
    if delayed_basic and (timestamp_vector_anomaly or uniform_indicator) and (not support_or_temp_file or strong_override_for_support):
        basic_direct += 10
        direct_reasons.append("Delayed isolated BasicInfoChange after create anchor + timestamp/event inconsistency")
    elif delayed_basic and subsec_suspicious and (not support_or_temp_file or strong_override_for_support):
        basic_direct += 8
        direct_reasons.append("Delayed isolated BasicInfoChange + artificial sub-second pattern")
    elif delayed_basic and support_or_temp_file:
        direct_reasons.append(f"Delayed BasicInfoChange on support/temp file suppressed unless strong direct evidence exists ({support_temp_reason})")
    direct_scores["DELAYED_BASICINFO_TIMESTAMP_EDIT"] = basic_direct

    uniform_direct = 0
    uniform_has_corroboration = (
        valid_logfile_transition
        or delayed_basic
        or si_fn_delta_non_access_scoring
        or future_non_access
        or rel_backdated
        or cli_pattern
        or gui_pattern
        or subsec_suspicious
        or known_tool
    )
    if uniform_mace_far and uniform_has_corroboration and not support_or_temp_file:
        uniform_direct += 9
        direct_reasons.append("Uniform SI MACE far from create anchor with corroborating event/artifact evidence")
    elif cma_uniform_far and not support_or_temp_file and (delayed_basic or valid_logfile_transition or known_tool or rel_backdated or cli_pattern or gui_pattern or subsec_suspicious):
        uniform_direct += 8
        direct_reasons.append("Uniform SI C/M/A far from create anchor with corroborating event/artifact evidence")
    elif uniform_indicator and support_or_temp_file and strong_override_for_support:
        uniform_direct += 7
        direct_reasons.append("Support/temp file has uniform timestamp-vector plus strong direct override evidence")
    elif uniform_indicator:
        direct_reasons.append("Uniform timestamp-vector treated as anomaly indicator only; not direct manipulation evidence")
    direct_scores["UNIFORM_MACE_FAR_FROM_ANCHOR"] = uniform_direct

    nonaccess_direct = 0
    nonaccess_has_corroboration = (
        has_basic
        or delayed_basic
        or valid_logfile_transition
        or known_tool
        or subsec_suspicious
        or si_fn_delta_non_access_scoring
        or future_non_access
        or rel_backdated
        or cli_pattern
        or gui_pattern
    )
    if non_access_cluster_far and nonaccess_has_corroboration and not support_or_temp_file:
        nonaccess_direct += 8
        if known_tool or valid_logfile_transition or delayed_basic:
            nonaccess_direct += 1
        direct_reasons.append("Non-access timestamp cluster copied/backdated while Accessed may be refreshed by normal use")
    elif non_access_cluster_far and support_or_temp_file and strong_override_for_support:
        nonaccess_direct += 7
        direct_reasons.append("Support/temp file has non-access timestamp cluster plus strong direct override evidence")
    elif non_access_cluster_far:
        direct_reasons.append("Non-access timestamp cluster retained as anomaly indicator; needs corroboration")
    direct_scores["NON_ACCESS_TIMESTAMP_COPY_CLUSTER"] = nonaccess_direct

    log_direct = 0
    # v1.0: A valid $LogFile SI transition is NOT direct manipulation evidence by itself.
    # Normal create/copy operations also generate $STANDARD_INFORMATION LogFile transitions.
    # Therefore, $LogFile is promoted to direct evidence only when it is corroborated by
    # independent timestamp-mutation evidence (delayed BasicInfoChange, SI/FN non-access
    # delta, future/backdated vector, CLI/GUI timestamp pattern, or sub-second anomaly).
    # A nearby known tool alone is treated as context/review evidence, not high-confidence proof.
    independent_timestamp_mutation_signal = (
        delayed_basic
        or si_fn_delta_non_access_scoring
        or future_non_access
        or rel_backdated
        or cli_pattern
        or gui_pattern
        or subsec_suspicious
        or non_access_cluster_far
    )
    logfile_has_direct_corroboration = (
        delayed_basic
        or si_fn_delta_non_access_scoring
        or future_non_access
        or rel_backdated
        or cli_pattern
        or gui_pattern
        or subsec_suspicious
        or (uniform_mace_far and not support_or_temp_file and independent_timestamp_mutation_signal)
        or (cma_uniform_far and not support_or_temp_file and independent_timestamp_mutation_signal)
        or (known_tool and independent_timestamp_mutation_signal)
    )
    if valid_logfile_transition and logfile_has_direct_corroboration and (not support_or_temp_file or strong_override_for_support):
        log_direct += 9
        direct_reasons.append("Valid $LogFile $STANDARD_INFORMATION timestamp transition corroborated by independent timestamp-mutation evidence")
    elif valid_logfile_transition and support_or_temp_file:
        direct_reasons.append(f"Valid $LogFile SI transition on support/temp file treated as context ({support_temp_reason})")
    elif sentinel_log_only:
        direct_reasons.append("$LogFile SI values are sentinel/1601/0000; ignored as direct manipulation evidence")
    direct_scores["VALID_LOGFILE_TIMESTAMP_TRANSITION"] = log_direct

    tool_direct = 0
    if known_tool and timestamp_anomaly:
        tool_direct += 9
        direct_reasons.append("Known timestamp tool near anchor + timestamp anomaly")
    elif known_tool:
        tool_direct += 4
        direct_reasons.append("Known timestamp tool candidate without sufficient file-level anomaly")
    elif generic_exec:
        direct_reasons.append("Generic/system/antivirus-looking executable is context only")
    direct_scores["TOOL_CORRELATED_TIMESTOMP"] = tool_direct

    # v1.0: True Negative Lock for ordinary two-phase create/write/save.
    # A normal user/application workflow can create a file at t0 and write/save it at t1.
    # In that pattern $FN often remains at create-time while $SI and $I30 M/A/E move to write-time.
    # This must suppress SI/FN delta evidence even when a timestamp tool exists somewhere in Prefetch.
    write_anchor = parse_dt(row.get("usn_last_time")) or parse_dt(row.get("logfile_last_time")) or entry_changed or modified
    def _close_to(a, b, minutes=5.0):
        d = _min_delta_minutes_tzsafe(a, b)
        return d is not None and d <= minutes
    i30_mft_m_close = fnum(row.get("i30_mft_m_delta_min"), 999999) <= 5.0
    i30_mft_e_close = fnum(row.get("i30_mft_e_delta_min"), 999999) <= 5.0
    i30_mft_a_close = fnum(row.get("i30_mft_a_delta_min"), 999999) <= 5.0 if "i30_mft_a_delta_min" in row else True
    si_write_explained = bool(
        (modified and write_anchor and _close_to(modified, write_anchor, 5.0))
        and (entry_changed and write_anchor and _close_to(entry_changed, write_anchor, 5.0))
    )
    i30_write_explained = bool(
        (not i30_found)
        or (i30_found and i30_reliability >= 0.50 and i30_mft_m_close and i30_mft_e_close and i30_mft_a_close)
        or i30_normal_write_support
    )
    normal_write_sequence_guard = bool(
        has_filecreate
        and (has_data or has_close)
        and not has_basic
        and not delayed_basic
        and created and create_anchor and _close_to(created, create_anchor, 5.0)
        and si_write_explained
        and i30_write_explained
        and not (rel_backdated or cli_pattern or gui_pattern or future_non_access or subsec_suspicious)
        and not (i30_anchor_contradiction or i30_uniform_mace_far or i30_cma_e_split or i30_cluster_shift)
    )

    # v1.0: Low-level MFT/SI-FN evidence can be decisive even when USN BasicInfoChange
    # occurs in a rename/create burst and delayed_basic is not set. This fixes partial
    # timestomp / timestamp-copy cases such as ACCDB/PUB/DOCX targets where the file has
    # strong SI/FN non-access delta, artificial sub-second pattern, or old/new timestamp
    # vector mismatch, but USN alone looks like ordinary rename/save grammar.
    lowlevel_direct = 0
    lowlevel_candidate = is_yes(row.get("lowlevel_timestamp_mutation_candidate")) or fnum(row.get("lowlevel_strength"), 0) >= 8
    lowlevel_strength_val = fnum(row.get("lowlevel_strength"), 0)
    lowlevel_has_nonaccess_delta = is_yes(row.get("lowlevel_si_fn_delta_non_access")) or si_fn_delta_non_access
    usn_metadata_pattern = has_basic or usn_only_suspicious_pattern or is_yes(row.get("usn_basicinfo_isolated")) or is_yes(row.get("usn_multiple_isolated_basicinfo")) or is_yes(row.get("usn_basic_move_basic_pattern"))
    mft_timestamp_pattern = rel_backdated or cli_pattern or gui_pattern or subsec_suspicious or lowlevel_has_nonaccess_delta
    if (not support_or_temp_file) and lowlevel_candidate and lowlevel_strength_val >= 8 and lowlevel_has_nonaccess_delta and (usn_metadata_pattern or mft_timestamp_pattern):
        lowlevel_direct += 8
        if rel_backdated or cli_pattern or gui_pattern or subsec_suspicious or is_yes(row.get("usn_multiple_isolated_basicinfo")) or is_yes(row.get("usn_basic_move_basic_pattern")):
            lowlevel_direct += 1
        direct_reasons.append("Low-level SI/FN non-access delta + metadata-change pattern indicates partial/timestamp-copy timestomp")
    elif support_or_temp_file and lowlevel_candidate:
        direct_reasons.append(f"Low-level anomaly on support/context file suppressed unless stronger evidence exists ({support_temp_reason})")
    direct_scores["LOWLEVEL_SI_FN_METADATA_TIMESTOMP"] = lowlevel_direct

    delta_direct = 0
    if si_fn_delta_non_access and not (i30_normal_write_support or normal_write_sequence_guard) and delayed_basic:
        delta_direct += 8
        direct_reasons.append("Non-Access SI/FN delta corroborated by delayed BasicInfoChange")
    elif si_fn_delta_non_access and not (i30_normal_write_support or normal_write_sequence_guard) and valid_logfile_transition:
        delta_direct += 7
        direct_reasons.append("Non-Access SI/FN delta corroborated by valid $LogFile SI transition")
    elif si_fn_delta_non_access and not (i30_normal_write_support or normal_write_sequence_guard) and known_tool:
        delta_direct += 6
        direct_reasons.append("Non-Access SI/FN delta corroborated by known tool")
    direct_scores["UNEXPLAINED_NON_ACCESS_SI_FN_DELTA"] = delta_direct

    # v1.0 Balanced MFT Strong-Anomaly Recovery.
    # Strict path matching in v1.0 correctly reduced false positives, but it also
    # suppressed manipulated files when USN/LogFile events could not be joined to
    # the target path. This block allows strong MFT-only SI/FN anomalies to become
    # evidence when the file is not in a normal/context/support folder.
    def _mft_delta_map():
        pairs = []
        for label, si_dt, fn_dt in [
            ("C", created, parse_dt(row.get("mft_fn_created"))),
            ("M", modified, parse_dt(row.get("mft_fn_modified"))),
            ("A", accessed, parse_dt(row.get("mft_fn_accessed"))),
            ("E", entry_changed, parse_dt(row.get("mft_fn_record_changed"))),
        ]:
            if si_dt and fn_dt:
                dmin = abs((si_dt - fn_dt).total_seconds()) / 60.0
                pairs.append((label, dmin, si_dt, fn_dt))
        return pairs

    def _is_timezone_equivalent_delta(dmin: float) -> bool:
        # v1.0: timezone-equivalent deltas are configurable rather than WIB-only.
        for h in _configured_tz_offsets():
            if abs(h) > 0 and abs(dmin - abs(float(h)) * 60.0) <= 10.0:
                return True
        return False

    mft_delta_pairs_detail = _mft_delta_map()
    non_access_mft_deltas = [(lab, dmin, si_dt, fn_dt) for lab, dmin, si_dt, fn_dt in mft_delta_pairs_detail if lab != "A" and dmin >= 4 and not _is_timezone_equivalent_delta(dmin)]
    access_mft_deltas = [(lab, dmin, si_dt, fn_dt) for lab, dmin, si_dt, fn_dt in mft_delta_pairs_detail if lab == "A" and dmin >= 4]
    max_non_access_mft_delta = max([d for _, d, _, _ in non_access_mft_deltas] or [0.0])

    # Detect common timestomp patterns from MFT alone:
    # 1) SI C/M/A/E all moved far away from FN C/M/A/E (tool-based SetMACE/timestomp).
    # 2) SI C/M/A backdated while SI-E remains near the real activity time.
    # 3) Two or more non-access SI/FN deltas not explainable by timezone or normal copy/archive folders.
    si_non_access = [created, modified, entry_changed]
    si_cma = [created, modified, accessed]
    fn_non_access = [parse_dt(row.get("mft_fn_created")), parse_dt(row.get("mft_fn_modified")), parse_dt(row.get("mft_fn_record_changed"))]
    si_cma_uniform = bool(created and modified and accessed and max(abs((x-created).total_seconds()) for x in [modified, accessed]) <= 2)
    si_all_uniform = bool(created and modified and accessed and entry_changed and max(abs((x-created).total_seconds()) for x in [modified, accessed, entry_changed]) <= 2)
    fn_all_available = all(parse_dt(row.get(k)) for k in ["mft_fn_created", "mft_fn_modified", "mft_fn_accessed", "mft_fn_record_changed"])
    mft_score = 0
    mft_reasons = []

    if not support_or_temp_file and not (i30_normal_write_support or normal_write_sequence_guard):
        if fn_all_available and si_all_uniform and max_non_access_mft_delta >= 24*60:
            mft_score = max(mft_score, 9)
            mft_reasons.append("MFT-only: SI C/M/A/E uniform differs from FN vector by >=1 day")
        elif fn_all_available and len(non_access_mft_deltas) >= 2 and max_non_access_mft_delta >= 24*60:
            mft_score = max(mft_score, 9)
            mft_reasons.append("MFT-only: multiple non-access SI/FN deltas >=1 day")
        elif created and modified and accessed and entry_changed:
            # C/M/A are old or shifted while E is materially different: common partial timestomp.
            cma_to_e_days = max(abs((x-entry_changed).total_seconds()) for x in [created, modified, accessed]) / 86400.0
            if si_cma_uniform and cma_to_e_days >= 1:
                mft_score = max(mft_score, 9 if cma_to_e_days >= 30 else 8)
                mft_reasons.append(f"MFT-only: SI C/M/A cluster differs from EntryChanged by {cma_to_e_days:.1f} days")
        if len(non_access_mft_deltas) >= 2 and max_non_access_mft_delta >= 4:
            # If the gap is small/near-time, treat as Need Review or lower High; if huge, High.
            mft_score = max(mft_score, 8 if max_non_access_mft_delta < 1440 else 9)
            labs = ",".join(f"{lab}:{dmin:.1f}m" for lab, dmin, _, _ in non_access_mft_deltas)
            mft_reasons.append(f"MFT-only: non-access SI/FN deltas >=4 minutes not explained by timezone ({labs})")

    if mft_score:
        direct_scores["MFT_STRONG_SI_FN_TIMESTAMP_VECTOR_ANOMALY"] = mft_score
        direct_reasons.extend(mft_reasons)
    else:
        direct_scores["MFT_STRONG_SI_FN_TIMESTAMP_VECTOR_ANOMALY"] = 0

    # v1.0 $I30 directory-index evidence.
    # $I30 is secondary/corroborative: it can recover SI+FN rewrites where FN is missing
    # and it can strengthen normal/tunneling guards, but it must not become a lone proof.
    i30_direct = 0
    if not support_or_temp_file and i30_found:
        # v1.0: $I30 remains corroborative.  Low-reliability or name/parent-only
        # $I30 evidence is capped to review level; high-confidence $I30 promotion requires
        # reliability >= 0.75 plus independent file-level mutation context.
        i30_independent_corroboration = (
            (delayed_basic and timestamp_anomaly)
            or si_fn_delta_non_access
            or future_non_access
            or rel_backdated
            or cli_pattern
            or gui_pattern
            or non_access_cluster_far
            or (valid_logfile_transition and logfile_has_direct_corroboration and timestamp_anomaly)
            or (known_tool and timestamp_anomaly)
        )
        if i30_reliability >= 0.75 and i30_uniform_mace_far and i30_independent_corroboration:
            i30_direct = 8
            direct_reasons.append("$I30: reliable uniform directory-index MACE far from anchor with independent file-level corroboration")
        elif i30_reliability >= 0.75 and i30_anchor_contradiction and i30_independent_corroboration:
            i30_direct = 7
            direct_reasons.append("$I30: reliable directory-index timestamp contradicts anchor with independent corroboration")
        elif i30_reliability >= 0.75 and i30_cma_e_split and i30_independent_corroboration:
            i30_direct = 6
            direct_reasons.append("$I30: reliable C/M/A cluster split from E with corroboration; review-level evidence")
        elif i30_anchor_contradiction or i30_cluster_shift or i30_uniform_mace_far or i30_cma_e_split:
            i30_direct = 5
            direct_reasons.append("$I30: directory-index timestamp anomaly without high-reliability independent corroboration; review-level only")
    direct_scores["I30_DIRECTORY_INDEX_TIMESTAMP_ANOMALY"] = i30_direct



    # v1.0 Batch/tool-correlated weak evidence recovery.
    # Some controlled and real-world timestomping attempts may leave weak or neutral
    # final MFT timestamps (e.g., no SI/FN delta and no BasicInfoChange) even though
    # the file is temporally close to a known timestamp manipulation tool execution.
    # This is not high-confidence proof. It becomes Suspicious Medium / Need Review
    # only when the file is not in a known normal/context folder and has a metadata
    # transaction footprint that can be associated to the MFT record.
    batch_direct = 0
    try:
        prefetch_delta = fnum(row.get("prefetch_best_delta_min"), 99999)
    except Exception:
        prefetch_delta = 99999
    has_metadata_transaction_context = (
        has_filecreate
        and (has_data or has_close)
        and fnum(row.get("logfile_event_count")) > 0
        and (is_yes(row.get("logfile_standard_information_update")) or is_yes(row.get("lsn_standard_information_update")) or fnum(row.get("logfile_event_count")) >= 6)
    )
    if (
        known_tool
        and not support_or_temp_file
        and not timestamp_anomaly
        and not delayed_basic
        and has_metadata_transaction_context
        and prefetch_delta <= 15
    ):
        batch_direct = 6
        direct_reasons.append(
            "Batch/tool-correlated weak candidate: known timestamp tool executed near file metadata transaction; "
            "no direct SI/FN or BasicInfoChange evidence, therefore retained as review-level evidence"
        )
    direct_scores["BATCH_TOOL_CORRELATED_WEAK_CANDIDATE"] = batch_direct

    # Artifact availability for partial-artifact / real-case mode.
    mft_available = (s(row.get("mft_found")) == "Yes" or bool(s(row.get("mft_entry"))))
    usn_available = (fnum(row.get("usn_event_count")) > 0 or bool(usn_text))
    log_available = (fnum(row.get("logfile_event_count")) > 0)
    artifact_limited = (int(mft_available) + int(usn_available) + int(log_available)) <= 1

    # Artifact-limited boosts: allow detection from one available artifact.
    if artifact_limited and delayed_basic and has_basic and (not support_or_temp_file or strong_override_for_support):
        direct_scores["DELAYED_BASICINFO_TIMESTAMP_EDIT"] = max(direct_scores.get("DELAYED_BASICINFO_TIMESTAMP_EDIT", 0), 7)
        direct_reasons.append("Artifact-limited detection: delayed isolated BasicInfoChange from USN-only/partial evidence")
    if artifact_limited and usn_only_suspicious_pattern and has_basic and (not support_or_temp_file or strong_override_for_support):
        direct_scores["DELAYED_BASICINFO_TIMESTAMP_EDIT"] = max(direct_scores.get("DELAYED_BASICINFO_TIMESTAMP_EDIT", 0), 6)
        direct_reasons.append("Artifact-limited detection: USN BasicInfoChange/Move/BasicInfoChange or repeated isolated BasicInfoChange pattern")
    if artifact_limited and valid_logfile_transition and (known_tool or delayed_basic or rel_backdated or cli_pattern or gui_pattern or subsec_suspicious) and (not support_or_temp_file or strong_override_for_support):
        direct_scores["VALID_LOGFILE_TIMESTAMP_TRANSITION"] = max(direct_scores.get("VALID_LOGFILE_TIMESTAMP_TRANSITION", 0), 7)
        direct_reasons.append("Artifact-limited detection: valid non-sentinel $LogFile SI transition with strong corroboration from LogFile-only/partial evidence")
    if artifact_limited and (rel_backdated or cli_pattern or gui_pattern or subsec_suspicious or non_access_cluster_far) and not access_only_effective and not support_or_temp_file:
        direct_scores["UNIFORM_MACE_FAR_FROM_ANCHOR"] = max(direct_scores.get("UNIFORM_MACE_FAR_FROM_ANCHOR", 0), 7)
        direct_reasons.append("Artifact-limited detection: strong MFT timestamp-vector anomaly from MFT-only/partial evidence")

    best_direct = max(direct_scores, key=direct_scores.get)
    direct_manipulation_score = direct_scores[best_direct]

    # ---- Artifact confidence ----
    artifact_confidence_score = 0
    if s(row.get("mft_found")) == "Yes" or s(row.get("mft_entry")):
        artifact_confidence_score += 1
    if fnum(row.get("usn_event_count")) > 0 or usn_text:
        artifact_confidence_score += 2
    if fnum(row.get("logfile_event_count")) > 0:
        artifact_confidence_score += 2
    if valid_logfile_transition:
        artifact_confidence_score += 2
    if lsn_linked:
        artifact_confidence_score += 1
    if fnum(row.get("prefetch_candidate_count")) > 0:
        artifact_confidence_score += 1
    if fnum(row.get("lnk_windows_hit_count")) > 0 or fnum(row.get("lnk_office_hit_count")) > 0:
        artifact_confidence_score += 1
    if i30_found:
        artifact_confidence_score += 1

    # ---- OATFD v1.0 TrueNegativeLock + $I30 support ----
    # Prinsip: Prefetch/tool dan $LogFile/LSN transaction adalah konteks.
    # High-confidence hanya boleh keluar jika ada mutation evidence pada level file.
    # FN kosong/missing tidak dihitung sebagai SI/FN mismatch.
    normal_create_burst = bool(has_filecreate and (has_data or has_close))
    compact_timestamp_vector = False
    try:
        spread_days_val = fnum(row.get("timestamp_spread_days"), 0.0)
        compact_timestamp_vector = spread_days_val <= (5.0 / 1440.0)  # <= 5 menit
    except Exception:
        compact_timestamp_vector = False

    # SI/FN non-access delta is strong only when not fully explained by normal create/copy grammar,
    # or when corroborated by a delayed BasicInfoChange / known tool / explicit timestamp-vector anomaly.
    strong_si_fn_nonaccess_delta = bool(
        si_fn_delta_non_access_scoring
        and not (i30_normal_write_support or normal_write_sequence_guard)
        and (
            delayed_basic
            or known_tool
            or rel_backdated
            or cli_pattern
            or gui_pattern
            or future_non_access
            or (valid_logfile_transition and not (normal_create_burst and not delayed_basic))
            or (not normal_create_burst and not copy_like_timestamp)
        )
    )

    # v1.0: Effective SI/FN delta is suppressed by explicit normal write/tunneling evidence.
    simple_create_guard = bool(
        has_filecreate and not has_basic and created and create_anchor
        and _min_delta_minutes_tzsafe(created, create_anchor) is not None
        and _min_delta_minutes_tzsafe(created, create_anchor) <= 5
        and compact_timestamp_vector
    )
    tn_tunneling_candidate = bool((has_delete and has_filecreate) or (i30_sequence_reuse_signal and has_filecreate))
    effective_si_fn_delta = bool(strong_si_fn_nonaccess_delta and not attribute_metadata_change_guard and not (i30_normal_write_support or i30_tunneling_guard_hint or simple_create_guard or normal_write_sequence_guard or tn_tunneling_candidate))

    # v1.0 Causal-Timeline Operation Guard
    # ------------------------------------------------------------
    # This guard is designed to avoid dataset-specific whitelists.  It does not
    # look for names such as BEFORE_TUNNELING_ or COPY_OF_.  Instead, it reasons
    # over the NTFS lifecycle of a file:
    #   - Did the timestamp transition occur during file birth/copy?
    #   - Is the timestamp payload plausible for birth/copy?
    #   - Is an old Modified timestamp explainable as copy/backup inheritance?
    #   - Did metadata change after the file became stable?
    # Only the last condition is a strong causal signature of timestomping.
    creation_or_copy_chain = bool(has_filecreate and (has_data or has_close))
    causality_offsets = _configured_causality_tz_offsets()

    def _delta_birth_min(dt_obj):
        return _min_delta_minutes_tzsafe(dt_obj, create_anchor, offsets=causality_offsets) if isinstance(create_anchor, datetime) else None

    def _near_birth(dt_obj, minutes=5.0):
        d = _delta_birth_min(dt_obj)
        return d is not None and d <= minutes

    def _far_birth(dt_obj, minutes=5.0):
        d = _delta_birth_min(dt_obj)
        return d is not None and d > minutes

    # Payload-time plausibility.  C/M/A far from the FileCreate anchor can be a
    # real mutation signal unless copy/backup inheritance explains it.  EntryChanged
    # may move as a normal metadata side effect, so E alone is not sufficient.
    payload_c_far_from_birth = _far_birth(created, 5.0)
    payload_m_far_from_birth = _far_birth(modified, 5.0)
    payload_a_far_from_birth = _far_birth(accessed, 10.0)
    payload_e_far_from_birth = _far_birth(entry_changed, 10.0)
    cma_payload_far_count = int(bool(payload_c_far_from_birth)) + int(bool(payload_m_far_from_birth)) + int(bool(payload_a_far_from_birth))
    cm_payload_far_count = int(bool(payload_c_far_from_birth)) + int(bool(payload_m_far_from_birth))
    timestamp_payload_far_from_birth = bool(cma_payload_far_count >= 2 or cm_payload_far_count >= 2 or uniform_mace_far or cma_uniform_far or non_access_cluster_far)
    timestamp_payload_plausible_for_birth = bool(not timestamp_payload_far_from_birth)
    # Compatibility aliases for reporting columns introduced during v1.0 development.
    payload_plausible_for_birth = timestamp_payload_plausible_for_birth
    payload_c_near_birth = _near_birth(created, 5.0)
    payload_m_near_birth = _near_birth(modified, 5.0)
    payload_a_near_birth = _near_birth(accessed, 10.0)
    payload_e_near_birth = _near_birth(entry_changed, 10.0)
    payload_c_far_birth = payload_c_far_from_birth
    payload_m_far_birth = payload_m_far_from_birth
    payload_a_far_birth = payload_a_far_from_birth
    payload_e_far_birth = payload_e_far_from_birth

    # Generic copy/backup timestamp inheritance.  A newly created file can inherit
    # an older LastWrite/Modified time from the source.  This pattern is normal only
    # if it is part of a FileCreate+DataWrite/Close chain and there is no late
    # metadata edit after the file becomes stable.
    inherited_modified_shape = False
    if isinstance(created, datetime) and isinstance(modified, datetime):
        try:
            inherited_modified_shape = (created - modified).total_seconds() >= 60.0
        except Exception:
            inherited_modified_shape = False
    if not inherited_modified_shape and copy_like_timestamp:
        inherited_modified_shape = True

    copy_birth_chain = bool(creation_or_copy_chain and has_data and has_close)
    late_basic_after_stable = bool(delayed_basic and delayed_basic_gap > 60)
    strong_explicit_timestamp_vector = bool(
        rel_backdated or cli_pattern or gui_pattern or future_non_access_strong or subsec_suspicious
        or uniform_mace_far or cma_uniform_far or non_access_cluster_far
    )
    copy_backup_payload_explained = bool(
        copy_birth_chain
        and inherited_modified_shape
        and not late_basic_after_stable
        and not (rel_backdated or cli_pattern or gui_pattern or future_non_access_strong or subsec_suspicious)
    )
    copy_inheritance_explains_payload = copy_backup_payload_explained

    unexplained_payload_anomaly = bool(
        timestamp_payload_far_from_birth
        and not copy_backup_payload_explained
        and not attribute_metadata_change_guard
        and not i30_tunneling_guard_hint
        and not normal_write_sequence_guard
    )

    # Tunneling/delete-recreate is recognized by event grammar, not by filename.
    general_tunneling_causality_guard = bool(
        ((has_delete and has_filecreate) or (i30_sequence_reuse_signal and has_filecreate) or i30_tunneling_guard_hint)
        and not (delayed_basic and timestamp_anomaly)
        and not unexplained_payload_anomaly
    )

    # Stable post-creation metadata edit: the positive causal core.
    stable_post_creation_metadata_edit = bool(
        late_basic_after_stable
        and timestamp_anomaly
        and not attribute_metadata_change_guard
        and not copy_backup_payload_explained
        and not general_tunneling_causality_guard
    )
    i30_post_creation_shift = bool(
        i30_target_level
        and i30_reliability >= 0.75
        and i30_cma_moved_from_anchor
        and not i30_e_only_metadata_change
        and not copy_backup_payload_explained
        and not general_tunneling_causality_guard
        and (delayed_basic or effective_si_fn_delta or si_fn_delta_non_access_scoring or future_non_access or unexplained_payload_anomaly)
    )
    post_creation_manipulation_core = bool(
        stable_post_creation_metadata_edit
        or i30_post_creation_shift
        or (effective_si_fn_delta and not copy_backup_payload_explained and not general_tunneling_causality_guard and (late_basic_after_stable or not creation_or_copy_chain or unexplained_payload_anomaly))
        or ((rel_backdated or cli_pattern or gui_pattern or future_non_access_strong or subsec_suspicious) and not copy_backup_payload_explained and not general_tunneling_causality_guard)
    )

    # Normality guards.  Birth-window metadata is normal only if the payload is
    # plausible.  If the event is near birth but the payload is far and unexplained,
    # the decision is capped to Need Review rather than forced to Normal.
    birth_window_metadata_guard = bool(
        creation_or_copy_chain
        and not late_basic_after_stable
        and (log_update or lsn_linked or valid_logfile_transition or i30_found)
        and timestamp_payload_plausible_for_birth
        and not unexplained_payload_anomaly
        and not effective_si_fn_delta
        and not (rel_backdated or cli_pattern or gui_pattern or future_non_access_strong or subsec_suspicious)
    )
    copy_backup_inheritance_guard = bool(
        copy_backup_payload_explained
        and not stable_post_creation_metadata_edit
        and not i30_post_creation_shift
    )
    logfile_creation_phase_guard = bool(
        creation_or_copy_chain
        and valid_logfile_transition
        and not late_basic_after_stable
        and (timestamp_payload_plausible_for_birth or copy_backup_inheritance_guard)
        and not post_creation_manipulation_core
    )
    logfile_payload_conflict_review = bool(
        creation_or_copy_chain
        and valid_logfile_transition
        and unexplained_payload_anomaly
        and not stable_post_creation_metadata_edit
    )
    operation_causality_review_cap = bool(
        logfile_payload_conflict_review
        or (creation_or_copy_chain and unexplained_payload_anomaly and not post_creation_manipulation_core)
    )
    operation_causality_normality_guard = bool(
        (birth_window_metadata_guard or copy_backup_inheritance_guard or logfile_creation_phase_guard or general_tunneling_causality_guard)
        and not post_creation_manipulation_core
        and not operation_causality_review_cap
    )

    if operation_causality_review_cap:
        operation_causality_reason = "payload_conflict_birth_window_review"
    elif copy_backup_inheritance_guard:
        operation_causality_reason = "copy_backup_timestamp_inheritance"
    elif birth_window_metadata_guard:
        operation_causality_reason = "birth_window_metadata_payload_plausible"
    elif logfile_creation_phase_guard:
        operation_causality_reason = "logfile_creation_phase_transition"
    elif general_tunneling_causality_guard:
        operation_causality_reason = "delete_recreate_tunneling_context"
    else:
        operation_causality_reason = "none"

    # v1.0 compatibility aliases for reporting and downstream guards
    payload_plausible_for_birth = bool(timestamp_payload_plausible_for_birth)
    copy_inheritance_explains_payload = bool(copy_backup_payload_explained)
    operation_payload_conflict_review = bool(operation_causality_review_cap)
    payload_c_near_birth = bool(_near_birth(created, 5.0))
    payload_m_near_birth = bool(_near_birth(modified, 5.0))
    payload_a_near_birth = bool(_near_birth(accessed, 10.0))
    payload_e_near_birth = bool(_near_birth(entry_changed, 10.0))
    payload_c_far_birth = bool(payload_c_far_from_birth)
    payload_m_far_birth = bool(payload_m_far_from_birth)
    payload_a_far_birth = bool(payload_a_far_from_birth)
    payload_e_far_birth = bool(payload_e_far_from_birth)
    payload_far_from_birth_any = bool(payload_c_far_from_birth or payload_m_far_from_birth or payload_a_far_from_birth or payload_e_far_from_birth)
    payload_far_from_birth_core = bool(payload_c_far_from_birth or payload_m_far_from_birth or payload_e_far_from_birth)

    ecp_M1_si_fn_delta = 1.0 if effective_si_fn_delta else 0.0
    # v1.0 bias hardening:
    # Delayed BasicInfoChange is not a complete mutation proof by itself.  It becomes
    # strong only when paired with a timestamp-vector anomaly; otherwise it is capped
    # to review-level support.
    ecp_M2_delayed_basicinfo = (
        1.0 if (delayed_basic and timestamp_anomaly)
        else (0.55 if (delayed_basic and (valid_logfile_transition or subsec_suspicious or si_fn_delta_non_access_scoring or future_non_access))
              else (0.35 if delayed_basic else 0.0))
    )
    ecp_M3_vector_anomaly = 1.0 if (rel_backdated or cli_pattern or gui_pattern or future_non_access or ((uniform_indicator or non_access_cluster_far) and not normal_create_burst)) else 0.0
    ecp_M4_logfile_strong = 1.0 if (valid_logfile_transition and (ecp_M1_si_fn_delta >= 1.0 or ecp_M2_delayed_basicinfo >= 0.55 or ecp_M3_vector_anomaly >= 1.0)) else 0.0
    # Artificial sub-second values are only weak corroboration; never standalone.
    ecp_M5_subsecond = 1.0 if (subsec_suspicious and (ecp_M1_si_fn_delta >= 1.0 or ecp_M2_delayed_basicinfo >= 0.55 or ecp_M3_vector_anomaly >= 1.0)) else 0.0
    if attribute_metadata_change_guard:
        # v1.0: delayed BasicInfoChange caused by attribute/metadata-only activity
        # must not continue contributing mutation evidence after the guard is active.
        ecp_M2_delayed_basicinfo = 0.0
        ecp_M4_logfile_strong = 0.0
        ecp_M5_subsecond = 0.0
    i30_anomaly_any = (i30_target_level and not i30_stale_entry and (i30_anchor_contradiction or i30_uniform_mace_far or i30_cma_e_split or i30_cluster_shift)) and not i30_tunneling_guard_hint
    i30_ecp_corroboration = (
        (delayed_basic and timestamp_anomaly)
        or si_fn_delta_non_access_scoring
        or future_non_access
        or rel_backdated
        or cli_pattern
        or gui_pattern
        or non_access_cluster_far
        or (valid_logfile_transition and logfile_has_direct_corroboration and timestamp_anomaly)
        or (known_tool and timestamp_anomaly)
    )
    ecp_M6_i30 = (
        1.0 if (i30_anomaly_any and i30_reliability >= 0.75 and i30_ecp_corroboration)
        else (0.60 if (i30_anomaly_any and i30_reliability >= 0.50) else 0.0)
    )

    if operation_causality_normality_guard:
        # Creation/copy/backup/tunneling grammar can produce SI/FN, $LogFile, or $I30
        # irregularities without anti-forensic timestomping.  Keep raw evidence in the
        # CSV, but cap mutation features below Confirmed unless post-creation mutation
        # evidence exists.
        ecp_M2_delayed_basicinfo = 0.0
        ecp_M3_vector_anomaly = min(ecp_M3_vector_anomaly, 0.35)
        ecp_M4_logfile_strong = 0.0
        ecp_M5_subsecond = 0.0
        ecp_M6_i30 = min(ecp_M6_i30, 0.35)

    # Evidence-capped mutation score. Max-style still preserves strong independent
    # contradictions, but single weak/context-only features are now capped below Confirmed.
    ecp_mutation_score = max(
        0.0,
        ecp_M6_i30,
        ecp_M2_delayed_basicinfo,
        ecp_M3_vector_anomaly,
        min(1.0, 0.55 * ecp_M1_si_fn_delta + 0.30 * ecp_M4_logfile_strong + 0.15 * ecp_M5_subsecond)
    )

    ecp_N1_create_burst = 1.0 if normal_create_burst else 0.0
    ecp_N2_no_delayed = 1.0 if not delayed_basic else 0.0
    ecp_N3_no_strong_delta = 1.0 if not effective_si_fn_delta else 0.0
    ecp_N4_compact_vector = 1.0 if compact_timestamp_vector else 0.0
    ecp_N5_i30_normal = 1.0 if (i30_normal_write_support or i30_tunneling_guard_hint or normal_write_sequence_guard) and not (i30_anchor_contradiction or i30_uniform_mace_far or i30_cma_e_split or i30_cluster_shift) else 0.0
    ecp_normality_score = min(1.0,
        0.25 * ecp_N1_create_burst +
        0.20 * ecp_N2_no_delayed +
        0.20 * ecp_N3_no_strong_delta +
        0.10 * ecp_N4_compact_vector +
        0.35 * ecp_N5_i30_normal
    )

    # Tool context: known timestomping tools are supportive, not decisive.
    try:
        ecp_prefetch_delta = fnum(row.get("prefetch_best_delta_min"), 99999)
    except Exception:
        ecp_prefetch_delta = 99999
    ecp_T1_known_tool = 1.0 if known_tool else 0.0
    if known_tool and ecp_prefetch_delta <= 2.0:
        ecp_T2_near_anchor = 1.0
    elif known_tool and ecp_prefetch_delta <= 5.0:
        ecp_T2_near_anchor = 0.60
    elif known_tool and ecp_prefetch_delta <= 10.0:
        ecp_T2_near_anchor = 0.30
    else:
        ecp_T2_near_anchor = 0.0
    # Target linkage must come from file-level mutation evidence, not merely from
    # the existence of a tool in Prefetch. $I30 may contribute only if it is anomalous.
    mutation_gate = bool(ecp_mutation_score >= 0.30 or ecp_M6_i30 >= 0.60 or rel_backdated or cli_pattern or gui_pattern or future_non_access)
    ecp_target_linkage = bool(known_tool and mutation_gate and ecp_T2_near_anchor > 0.0)
    ecp_T3_target_linkage = 1.0 if ecp_target_linkage else 0.0
    ecp_tool_context_score = min(1.0,
        0.40 * ecp_T1_known_tool +
        0.30 * ecp_T2_near_anchor +
        0.30 * ecp_T3_target_linkage
    )
    prefetch_effective = ecp_T1_known_tool * ecp_T2_near_anchor * (1.0 if mutation_gate else 0.0)

    i30_true_negative_lock = bool(
        (simple_create_guard or normal_write_sequence_guard or i30_normal_write_support or i30_tunneling_guard_hint)
        and ecp_mutation_score < 0.30
        and prefetch_effective < 0.30
        and not (delayed_basic or rel_backdated or cli_pattern or gui_pattern or future_non_access)
        and not (i30_anchor_contradiction or i30_uniform_mace_far or i30_cma_e_split)
    )

    # Confirmed requires high mutation score AND independent file-level corroboration.
    # This prevents a single delayed BasicInfoChange or low-reliability $I30 artifact from
    # becoming Confirmed by the ECP override.
    ecp_confirmed_corroborated = bool(
        (delayed_basic and timestamp_anomaly)
        or effective_si_fn_delta
        or (valid_logfile_transition and logfile_has_direct_corroboration)
        or (i30_direct >= 7 and i30_reliability >= 0.75)
        or (direct_scores.get("LOWLEVEL_SI_FN_METADATA_TIMESTOMP", 0) >= 8)
        or (direct_scores.get("MFT_STRONG_SI_FN_TIMESTAMP_VECTOR_ANOMALY", 0) >= 8 and not artifact_limited)
        or (rel_backdated or cli_pattern or gui_pattern or future_non_access)
    )
    if attribute_metadata_change_guard:
        ecp_class = "Normal Activity / Attribute Change Guard"
    elif operation_causality_review_cap and not post_creation_manipulation_core:
        ecp_class = "Need Review / Causal Payload Conflict"
    elif operation_causality_normality_guard and ecp_mutation_score < 0.70:
        ecp_class = "Normal Activity / Operation-Causality Guard"
    elif i30_tunneling_guard_hint and ecp_mutation_score < 0.30 and not delayed_basic:
        ecp_class = "Normal Activity / I30 Tunneling Lock"
    elif i30_true_negative_lock:
        ecp_class = "Normal Activity / I30 True Negative Lock"
    elif ecp_mutation_score >= 0.70 and ecp_mutation_score > (ecp_normality_score - 0.05) and ecp_confirmed_corroborated and not attribute_metadata_change_guard:
        ecp_class = "Confirmed Timestamp Manipulation"
    elif ecp_mutation_score >= 0.40:
        ecp_class = "Probable Timestamp Manipulation"
    elif prefetch_effective >= 0.50 and ecp_mutation_score >= 0.20:
        ecp_class = "Attempted / Tool-Correlated Manipulation"
    elif ecp_mutation_score < 0.30 and ecp_normality_score >= 0.70 and not ecp_target_linkage:
        ecp_class = "Normal Activity / Tool Context Only" if ecp_tool_context_score >= 0.50 else "Normal Activity"
    else:
        ecp_class = "Need Review"

    ecp_evidence_cap = "AllowConfirmed" if ecp_class == "Confirmed Timestamp Manipulation" else "CapToReviewOrNormal"

    # ---- Final decision hierarchy ----
    # REALCASE v1.0: artifact-limited mode. Jika hanya satu artefak tersedia, aplikasi tetap
    # memberi keputusan terbaik berbasis bukti yang ada, bukan gagal/error.
    mft_available = (s(row.get("mft_found")) == "Yes" or bool(s(row.get("mft_entry"))))
    usn_available = (fnum(row.get("usn_event_count")) > 0 or bool(usn_text))
    log_available = (fnum(row.get("logfile_event_count")) > 0)
    artifact_limited = (int(mft_available) + int(usn_available) + int(log_available)) <= 1

    # v1.0 normal-operation/tunneling grammar (artifact grammar only; no normal folder/name labels). Strong direct evidence should not be
    # inferred from delayed BasicInfoChange or valid $LogFile transition alone when
    # the row has clear normal create/copy/archive/recycle/tunneling grammar and no
    # known timestomping tool. This mirrors the conservative behavior observed in
    # NTFS Log Tracker for tunneling-like normal scenarios.
    normal_activity_guard = (
        attribute_metadata_change_guard
        or operation_causality_normality_guard
        or operation_causality_review_cap
        or normal_write_sequence_guard
        or (has_filecreate and (has_data or has_close) and not known_tool and not (rel_backdated or cli_pattern or gui_pattern or future_non_access or subsec_suspicious))
        or (has_delete and has_filecreate and not known_tool)
        or (has_rename and has_filecreate and not known_tool)
        or (copy_like_timestamp and has_filecreate and (has_data or has_close) and not known_tool and not (rel_backdated or cli_pattern or gui_pattern or future_non_access or subsec_suspicious))
        or (i30_normal_write_support and not ecp_target_linkage and not (i30_anchor_contradiction or i30_uniform_mace_far or i30_cma_e_split))
    )
    tunneling_like_guard = (
        ((has_delete or has_rename) and has_filecreate and not known_tool)
        or (i30_tunneling_guard_hint and has_filecreate and (has_delete or i30_sequence_reuse_signal) and not ecp_target_linkage)
    )
    high_confidence_guard_block = (
        (normal_activity_guard or (operation_payload_conflict_review and not post_creation_manipulation_core))
        and (not known_tool or ((operation_causality_normality_guard or operation_causality_review_cap) and prefetch_effective < 0.50))
        and not (rel_backdated or cli_pattern or gui_pattern or future_non_access or subsec_suspicious)
        and not (si_fn_delta_non_access_scoring and not copy_like_timestamp and not tunneling_like_guard and not operation_causality_normality_guard)
    )

    # v1.0 role-aware non-primary artifact logic.
    # This prevents hard false negatives for scripts/programs/recycle/support files in real cases.
    # The role does not block detection; it raises the evidentiary threshold and changes the label.
    role_aware_strong_evidence = (
        direct_manipulation_score >= 9
        and (
            known_tool
            or (lsn_linked and (valid_logfile_transition or log_update))
            or (delayed_basic and (si_fn_delta_non_access_scoring or future_non_access or subsec_suspicious))
            or (si_fn_delta_non_access_scoring and (valid_logfile_transition or has_basic or delayed_basic))
        )
        and not (normal_activity_guard and not known_tool)
        and not (tunneling_like_guard and not known_tool)
    )
    role_aware_nonprimary_high = (support_temp_reason in nonprimary_high_eligible_roles and role_aware_strong_evidence)
    role_aware_nonprimary_review = (
        support_temp_reason in nonprimary_review_only_roles
        and direct_manipulation_score >= 8
        and (lsn_linked or valid_logfile_transition or si_fn_delta_non_access or delayed_basic or known_tool)
    )

    direct_tp = (
        (not high_confidence_guard_block)
        and not (operation_causality_review_cap and not post_creation_manipulation_core)
        and (
        role_aware_nonprimary_high
        or ((delayed_basic and timestamp_anomaly) and (not support_or_temp_file or strong_override_for_support))
        or (uniform_mace_far and uniform_has_corroboration and not support_or_temp_file)
        or (cma_uniform_far and not support_or_temp_file and (delayed_basic or valid_logfile_transition or known_tool or rel_backdated or cli_pattern or gui_pattern or subsec_suspicious))
        or (non_access_cluster_far and not support_or_temp_file and (has_basic or delayed_basic or valid_logfile_transition or known_tool or subsec_suspicious or si_fn_delta_non_access_scoring or future_non_access or rel_backdated or cli_pattern or gui_pattern))
        or (valid_logfile_transition and logfile_has_direct_corroboration and (not support_or_temp_file or strong_override_for_support))
        or (known_tool and timestamp_anomaly and (not support_or_temp_file or strong_override_for_support))
        or (direct_scores.get("LOWLEVEL_SI_FN_METADATA_TIMESTOMP", 0) >= 8 and not support_or_temp_file)
        or (direct_scores.get("MFT_STRONG_SI_FN_TIMESTAMP_VECTOR_ANOMALY", 0) >= 8 and not support_or_temp_file)
        or (direct_scores.get("BATCH_TOOL_CORRELATED_WEAK_CANDIDATE", 0) >= 6 and not support_or_temp_file)
        or (direct_scores.get("I30_DIRECTORY_INDEX_TIMESTAMP_ANOMALY", 0) >= 8 and not support_or_temp_file)
        or (si_fn_delta_non_access_scoring and delayed_basic and (not support_or_temp_file or strong_override_for_support))
        # USN-only/limited: delayed isolated BasicInfoChange is enough for at least Suspicious Medium, unless it is only a support/temp context.
        or (artifact_limited and delayed_basic and has_basic and (not support_or_temp_file or strong_override_for_support))
        or (artifact_limited and usn_only_suspicious_pattern and has_basic and (not support_or_temp_file or strong_override_for_support))
        # MFT-only/limited: strong timestamp-vector anomaly is enough for Suspicious Medium/High, but uniform-only is not enough.
        or (artifact_limited and (rel_backdated or cli_pattern or gui_pattern or future_non_access or non_access_cluster_far or (subsec_suspicious and (si_fn_delta_non_access or delayed_basic or valid_logfile_transition))) and not access_only_effective and not support_or_temp_file)
        # LogFile-only/limited: valid non-sentinel SI transition needs corroboration.
        or (artifact_limited and valid_logfile_transition and (known_tool or delayed_basic or rel_backdated or cli_pattern or gui_pattern or subsec_suspicious) and (not support_or_temp_file or strong_override_for_support))
        )
    )

    # v1.0 evidence-margin guard: if the only high direct basis is a valid $LogFile
    # transition and the normal operation score is equal/higher, do not report Suspicious High.
    # This prevents normal create/copy files with LSN-linked $STANDARD_INFORMATION transactions
    # from becoming false positives when a timestamp tool was merely present nearby.
    decision_margin_pre = direct_manipulation_score - operation_normality_score
    independent_high_confidence_timestamp_evidence = (
        delayed_basic
        or si_fn_delta_non_access_scoring
        or future_non_access
        or rel_backdated
        or cli_pattern
        or gui_pattern
        or (subsec_suspicious and (si_fn_delta_non_access or delayed_basic or valid_logfile_transition))
        or (lowlevel_candidate and lowlevel_has_nonaccess_delta)
        or direct_scores.get("LOWLEVEL_SI_FN_METADATA_TIMESTOMP", 0) >= 8
        or direct_scores.get("MFT_STRONG_SI_FN_TIMESTAMP_VECTOR_ANOMALY", 0) >= 8
        or direct_scores.get("I30_DIRECTORY_INDEX_TIMESTAMP_ANOMALY", 0) >= 8
    )
    logfile_margin_conflict_review = (
        direct_tp
        and best_direct == "VALID_LOGFILE_TIMESTAMP_TRANSITION"
        and direct_manipulation_score >= 8
        and decision_margin_pre <= 0
        and operation_normality_score >= direct_manipulation_score
        and not independent_high_confidence_timestamp_evidence
    )

    normal_tn = (
        not direct_tp
        and (not uniform_mace_far or support_or_temp_file)
        and (not cma_uniform_far or support_or_temp_file)
        and (not non_access_cluster_far or support_or_temp_file)
        and (not delayed_basic or support_or_temp_file)
        and (
            access_only_effective
            or normal_office_temp_grammar
            or (support_or_temp_file and has_filecreate and (has_data or has_close or has_basic or has_delete) and not strong_override_for_support)
            or (has_filecreate and (has_data or has_close) and created and create_anchor and abs((created - create_anchor).total_seconds()) <= 300)
            or copy_like_timestamp
            or (has_delete and has_filecreate)
            or (has_data and has_close and not has_filecreate)
            or i30_true_negative_lock
            or normal_write_sequence_guard
            or operation_causality_normality_guard
        )
    )

    if role_aware_nonprimary_high:
        # v1.0: non-primary artifacts can be genuinely malicious/timestomped in real cases.
        # They must not be silently downgraded to Normal, but they also should not be mixed
        # with ordinary user/data-file Suspicious High. Report them as a high-risk
        # role-aware artifact anomaly and export them separately.
        prediction = "High-Risk Non-Primary Artifact"
        prediction_type = f"high_risk_nonprimary_artifact_timestamp_anomaly_{support_temp_reason}_{best_direct.lower()}"
        final_score = min(max(direct_manipulation_score, 8), 9)
        mutation_core = "Yes"
        expected_match = "High-risk non-primary artifact anomaly"
        direct_evidence = "Yes"
        normal_guard = "Role-aware"
    elif role_aware_nonprimary_review:
        prediction = "Need Review"
        prediction_type = f"role_aware_context_artifact_anomaly_{support_temp_reason}"
        final_score = min(max(direct_manipulation_score, 7), 8)
        mutation_core = "No"
        expected_match = "Ambiguous non-primary artifact anomaly"
        direct_evidence = "Yes"
        normal_guard = "Yes"
    elif operation_payload_conflict_review and not post_creation_manipulation_core:
        prediction = "Need Review"
        prediction_type = "operation_causality_payload_conflict_review"
        final_score = min(max(direct_manipulation_score, 5), 7)
        mutation_core = "No"
        expected_match = "Ambiguous birth/copy metadata payload"
        direct_evidence = "Partial"
        normal_guard = "OperationCausalityReview"
    elif high_confidence_guard_block:
        # v1.0: an explicit Attribute/Access Metadata Change Guard is a normal
        # metadata-change explanation, not an ambiguous timestamp-manipulation candidate.
        # This handles attrib +R/-R E-only cases and attrib +H/-H A+E-only cases where
        # delayed BasicInfoChange appears after FileCreate but C/M remain stable.
        if attribute_metadata_change_guard:
            prediction = "Normal"
            prediction_type = "ecp_normal_attribute_change_context_guard"
            final_score = 0
            mutation_core = "No"
            expected_match = "Yes"
            direct_evidence = "No"
            normal_guard = "AttributeChangeGuard"
        elif operation_causality_normality_guard:
            prediction = "Normal"
            prediction_type = "ecp_normal_operation_causality_guard"
            final_score = 0
            mutation_core = "No"
            expected_match = "Yes"
            direct_evidence = "No"
            normal_guard = "OperationCausalityGuard"
        elif operation_causality_review_cap:
            prediction = "Need Review"
            prediction_type = "operation_causality_payload_conflict_review"
            final_score = min(max(direct_manipulation_score, 4), 6)
            mutation_core = "No"
            expected_match = "Ambiguous birth/copy metadata payload conflict"
            direct_evidence = "No"
            normal_guard = "OperationCausalityReviewCap"
        elif direct_manipulation_score >= 6 and (delayed_basic or valid_logfile_transition or non_access_cluster_far):
            prediction = "Need Review"
            prediction_type = "normal_activity_or_tunneling_context_review"
            final_score = min(direct_manipulation_score, 6)
            mutation_core = "No"
            expected_match = "Ambiguous normal-context evidence"
            direct_evidence = "No"
            normal_guard = "Yes"
        else:
            prediction = "Normal"
            prediction_type = "normal_activity_or_tunneling_context_guard"
            final_score = 0
            mutation_core = "No"
            expected_match = "Yes"
            direct_evidence = "No"
            normal_guard = "Yes"
    elif normal_office_temp_grammar and not strong_override_for_support:
        prediction = "Normal"
        prediction_type = f"context_guard_{support_temp_reason}"
        final_score = 0
        mutation_core = "No"
        expected_match = "Yes"
        direct_evidence = "No"
        normal_guard = "Yes"
    elif support_or_temp_file and not direct_tp and not strong_override_for_support:
        prediction = "Normal"
        prediction_type = f"context_guard_{support_temp_reason}"
        final_score = 0
        mutation_core = "No"
        expected_match = "Yes"
        direct_evidence = "No"
        normal_guard = "Yes"
    elif logfile_margin_conflict_review:
        prediction = "Need Review"
        prediction_type = "evidence_margin_conflict_logfile_transition_context"
        final_score = min(direct_manipulation_score, 6)
        mutation_core = "No"
        expected_match = "Ambiguous: $LogFile transition equal/less persuasive than normal operation grammar"
        direct_evidence = "No"
        normal_guard = "Evidence-margin"
    elif best_direct == "BATCH_TOOL_CORRELATED_WEAK_CANDIDATE" and direct_manipulation_score >= 6:
        prediction = "Need Review"
        prediction_type = "tool_correlated_weak_metadata_context_review"
        final_score = min(direct_manipulation_score, 6)
        mutation_core = "No"
        expected_match = "Ambiguous: known timestamp tool near metadata transaction but no independent file-level timestamp mutation evidence"
        direct_evidence = "No"
        normal_guard = "Review-level"
    elif direct_tp and direct_manipulation_score >= 8:
        prediction = "Suspicious High"
        prediction_type = f"anchor_vector_confirmed_{best_direct.lower()}"
        final_score = direct_manipulation_score
        mutation_core = "Yes"
        expected_match = "No"
        direct_evidence = "Yes"
        normal_guard = "No"
    elif direct_tp and direct_manipulation_score >= 6:
        prediction = "Suspicious Medium"
        prediction_type = f"anchor_vector_suspected_{best_direct.lower()}"
        final_score = direct_manipulation_score
        mutation_core = "Yes"
        expected_match = "Partial"
        direct_evidence = "Yes"
        normal_guard = "No"
    elif normal_tn:
        prediction = "Normal"
        prediction_type = f"anchor_consistent_normal_{best_operation.lower()}"
        final_score = 0
        mutation_core = "No"
        expected_match = "Yes"
        direct_evidence = "No"
        normal_guard = "Yes"
    elif access_only_effective and not delayed_basic and not valid_logfile_transition and not known_tool:
        prediction = "Normal"
        prediction_type = "anchor_consistent_access_only_normal"
        final_score = 0
        mutation_core = "No"
        expected_match = "Yes"
        direct_evidence = "No"
        normal_guard = "Yes"
    else:
        # REALCASE v1.0 default: semua file adalah Normal kecuali ada bukti manipulasi atau bukti ambigu yang cukup kuat.
        # Need Review hanya untuk bukti parsial yang mendekati threshold, bukan untuk file tanpa evidence.
        if direct_manipulation_score >= 5 or low_strength >= 5 or (known_tool and not timestamp_anomaly):
            prediction = "Need Review"
            prediction_type = "artifact_limited_or_weak_evidence_review"
            final_score = max(direct_manipulation_score, low_strength, 1)
            mutation_core = "No"
            expected_match = "Ambiguous"
            direct_evidence = "Yes" if direct_manipulation_score >= 6 else "No"
            normal_guard = "No"
        else:
            prediction = "Normal"
            prediction_type = "realcase_default_normal_no_strong_manipulation_evidence"
            final_score = 0
            mutation_core = "No"
            expected_match = "No strong manipulation evidence"
            direct_evidence = "No"
            normal_guard = "Yes"

    # ---- Apply ECP override to legacy hierarchy ----
    # The legacy scores remain in the CSV for audit, but the final label follows the
    # evidence-capped class so $LogFile/Prefetch context cannot override normal grammar.
    if not str(prediction).startswith("High-Risk"):
        if ecp_class == "Confirmed Timestamp Manipulation" and direct_tp and not high_confidence_guard_block and not attribute_metadata_change_guard and not operation_causality_normality_guard and not support_or_temp_file:
            prediction = "Suspicious High"
            prediction_type = "ecp_confirmed_timestamp_manipulation"
            final_score = max(final_score, direct_manipulation_score, 8)
            mutation_core = "Yes"
            expected_match = "No"
            direct_evidence = "Yes"
            normal_guard = "No"
        elif ecp_class == "Probable Timestamp Manipulation":
            # v1.0: ECP probable must not convert ordinary system/OS metadata
            # artifacts into Need Review unless the role-aware anomaly logic already
            # marked them as review/high-risk.  Otherwise full-scope scans become noisy.
            if hard_context_artifact and not role_aware_nonprimary_review and not role_aware_nonprimary_high:
                prediction = "Normal"
                prediction_type = f"context_guard_{support_temp_reason}_ecp_probable_suppressed"
                final_score = 0
                mutation_core = "No"
                expected_match = "Context artifact; probable score suppressed by role gate"
                direct_evidence = "No"
                normal_guard = "Role/ECP"
            else:
                prediction = "Need Review"
                prediction_type = "ecp_probable_timestamp_manipulation_review"
                final_score = min(max(final_score, direct_manipulation_score, 6), 7)
                mutation_core = "Partial"
                expected_match = "Partial"
                direct_evidence = "Partial"
                normal_guard = "ECP-review"
        elif ecp_class == "Attempted / Tool-Correlated Manipulation":
            prediction = "Need Review"
            prediction_type = "ecp_attempted_tool_correlated_manipulation_review"
            final_score = min(max(final_score, 5), 6)
            mutation_core = "No"
            expected_match = "Tool context without confirmed file-level mutation"
            direct_evidence = "No"
            normal_guard = "ECP-review"
        elif ecp_class.startswith("Need Review / Causal") or ecp_class.startswith("Need Review / Operation-Causality"):
            prediction = "Need Review"
            prediction_type = "ecp_operation_causality_payload_conflict_review"
            final_score = min(max(final_score, direct_manipulation_score, 5), 7)
            mutation_core = "No"
            expected_match = "Ambiguous birth/copy metadata payload"
            direct_evidence = "Partial"
            normal_guard = "OperationCausalityReview"
        elif ecp_class.startswith("Normal Activity"):
            prediction = "Normal"
            prediction_type = "ecp_normal_activity_tool_context_only" if "Tool Context" in ecp_class else "ecp_normal_activity_no_file_level_mutation"
            final_score = 0
            mutation_core = "No"
            expected_match = "Yes"
            direct_evidence = "No"
            normal_guard = "ECP"
        else:
            if str(prediction).startswith("Suspicious"):
                prediction = "Need Review"
                prediction_type = "ecp_capped_ambiguous_evidence_review"
                final_score = min(max(final_score, 5), 7)
                mutation_core = "Partial"
                expected_match = "Ambiguous"
                direct_evidence = "Partial"
                normal_guard = "ECP-review"

    margin = decision_margin_pre
    reasoning = []
    reasoning.append(f"create_anchor={fmt_dt(create_anchor)}")
    reasoning.append(f"basic_anchor={fmt_dt(basic_last)}")
    reasoning.append(f"delayed_basic={delayed_basic}")
    reasoning.append(f"usn_only_suspicious_pattern={usn_only_suspicious_pattern}")
    reasoning.append(f"uniform_mace_far={uniform_mace_far}")
    reasoning.append(f"cma_uniform_far={cma_uniform_far}")
    reasoning.append(f"cme_uniform_far={cme_uniform_far}")
    reasoning.append(f"cm_uniform_far={cm_uniform_far}")
    reasoning.append(f"non_access_cluster_far={non_access_cluster_far}")
    reasoning.append(f"valid_logfile_transition={valid_logfile_transition}")
    reasoning.append(f"support_temp_reason={support_temp_reason or 'No'}")
    reasoning.append(f"hard_context_artifact={hard_context_artifact}")
    reasoning.append(f"normal_activity_guard={normal_activity_guard}")
    reasoning.append(f"operation_causality_normality_guard={operation_causality_normality_guard}")
    reasoning.append(f"operation_causality_reason={operation_causality_reason}")
    reasoning.append(f"payload_plausible_for_birth={payload_plausible_for_birth}")
    reasoning.append(f"copy_inheritance_explains_payload={copy_inheritance_explains_payload}")
    reasoning.append(f"unexplained_payload_anomaly={unexplained_payload_anomaly}")
    reasoning.append(f"operation_causality_review_cap={operation_causality_review_cap}")
    reasoning.append(f"birth_window_metadata_guard={birth_window_metadata_guard}")
    reasoning.append(f"copy_backup_inheritance_guard={copy_backup_inheritance_guard}")
    reasoning.append(f"logfile_creation_phase_guard={logfile_creation_phase_guard}")
    reasoning.append(f"general_tunneling_causality_guard={general_tunneling_causality_guard}")
    reasoning.append(f"stable_post_creation_metadata_edit={stable_post_creation_metadata_edit}")
    reasoning.append(f"post_creation_manipulation_core={post_creation_manipulation_core}")
    reasoning.append(f"operation_payload_conflict_review={operation_payload_conflict_review}")
    reasoning.append(f"payload_far_from_birth_any={payload_far_from_birth_any}")
    reasoning.append(f"payload_far_from_birth_core={payload_far_from_birth_core}")
    reasoning.append(f"copy_inheritance_explains_payload={copy_inheritance_explains_payload}")
    reasoning.append(f"operation_causality_review_cap={operation_causality_review_cap}")
    reasoning.append(f"timestamp_payload_far_from_birth={timestamp_payload_far_from_birth}")
    reasoning.append(f"unexplained_payload_anomaly={unexplained_payload_anomaly}")
    reasoning.append(f"copy_backup_payload_explained={copy_backup_payload_explained}")
    reasoning.append(f"logfile_payload_conflict_review={logfile_payload_conflict_review}")
    reasoning.append(f"tunneling_like_guard={tunneling_like_guard}")
    reasoning.append(f"high_confidence_guard_block={high_confidence_guard_block}")
    reasoning.append(f"attribute_metadata_change_guard={attribute_metadata_change_guard}")
    reasoning.append(f"attribute_tool_context={attribute_tool_context}")
    reasoning.append(f"entry_only_nonaccess_delta={entry_only_nonaccess_delta}")
    reasoning.append(f"role_aware_nonprimary_high={role_aware_nonprimary_high}")
    reasoning.append(f"role_aware_nonprimary_review={role_aware_nonprimary_review}")
    reasoning.append(f"target_role_reason={support_temp_reason or 'primary_candidate'}")
    reasoning.append(f"uniform_indicator_only={uniform_indicator and not direct_tp}")
    reasoning.append(f"best_operation={best_operation}({operation_normality_score})")
    reasoning.append(f"best_direct={best_direct}({direct_manipulation_score})")
    reasoning.append(f"artifact_confidence={artifact_confidence_score}")
    reasoning.append(f"ecp_mutation_score={ecp_mutation_score:.2f}")
    reasoning.append(f"ecp_normality_score={ecp_normality_score:.2f}")
    reasoning.append(f"ecp_tool_context_score={ecp_tool_context_score:.2f}")
    reasoning.append(f"ecp_confirmed_corroborated={ecp_confirmed_corroborated}")
    reasoning.append(f"dataset_support_tokens_enabled={DATASET_SUPPORT_TOKENS}")
    reasoning.append(f"program_role_gate_strict={PROGRAM_ROLE_GATE_STRICT}")
    reasoning.append(f"simple_create_guard={simple_create_guard}")
    reasoning.append(f"normal_write_sequence_guard={normal_write_sequence_guard}")
    reasoning.append(f"effective_si_fn_delta={effective_si_fn_delta}")
    reasoning.append(f"prefetch_effective={prefetch_effective:.2f}")
    reasoning.append(f"i30_found={i30_found}")
    reasoning.append(f"i30_reliability={i30_reliability:.2f}")
    reasoning.append(f"i30_anchor_contradiction={i30_anchor_contradiction}")
    reasoning.append(f"i30_uniform_mace_far={i30_uniform_mace_far}")
    reasoning.append(f"i30_cma_e_split={i30_cma_e_split}")
    reasoning.append(f"i30_normal_write_support={i30_normal_write_support}")
    reasoning.append(f"i30_tunneling_guard_hint={i30_tunneling_guard_hint}")
    reasoning.append(f"i30_parser_mode={s(row.get('i30_parser_mode'))}")
    reasoning.append(f"i30_target_level={i30_target_level}")
    reasoning.append(f"i30_cma_moved_from_anchor={i30_cma_moved_from_anchor}")
    reasoning.append(f"i30_e_only_metadata_change={i30_e_only_metadata_change}")
    reasoning.append(f"i30_stale_entry={i30_stale_entry}")
    if s(row.get("i30_reason")):
        reasoning.append("i30_evidence=" + s(row.get("i30_reason")))
    reasoning.append(f"ecp_class={ecp_class}")
    reasoning.append(f"ecp_target_linkage={ecp_target_linkage}")
    reasoning.append(f"ecp_evidence_cap={ecp_evidence_cap}")
    reasoning.append(f"decision_margin={margin}")
    if mace_anchor_gap_min is not None:
        reasoning.append(f"mace_anchor_gap_min={mace_anchor_gap_min:.2f}")
    if op_reasons:
        reasoning.append("operation_evidence=" + "; ".join(dict.fromkeys(op_reasons)))
    if direct_reasons:
        reasoning.append("direct/context_evidence=" + "; ".join(dict.fromkeys(direct_reasons)))
    if lsn_linked and log_update and not valid_logfile_transition:
        reasoning.append("LSN/$LogFile linkage treated as transaction context; not direct manipulation")
    if access_only and not non_access_cluster_far:
        reasoning.append("Accessed-only anomaly suppressed unless corroborated by direct TP rule")
    if non_access_cluster_far:
        reasoning.append("Accessed was not allowed to suppress suspicious C/M/E or C/M timestamp-copy cluster")
    if support_or_temp_file:
        reasoning.append(f"Context guard active: {support_temp_reason}; file tetap dianalisis, bukan Excluded")
    if high_confidence_guard_block:
        reasoning.append("Normal/tunneling context guard blocked high-confidence timestamp manipulation classification")
    if uniform_indicator and not direct_tp:
        reasoning.append("Uniform MACE/CMA is retained as anomaly indicator but not enough for timestamp manipulation")

    row.update({
        "score": final_score,
        "prediction": prediction,
        "prediction_type": prediction_type,
        "mutation_core": mutation_core,
        "lowlevel_si_fn_delta_non_access": "Yes" if si_fn_delta_non_access else "No",
        "lowlevel_si_fn_accessed_only": "Yes" if si_fn_delta_access_only else "No",
        "lowlevel_future_non_access": "Yes" if future_non_access else "No",
        "lowlevel_future_accessed_only": "Yes" if future_access_only else "No",
        "near_time_uniform_mace_core": "Yes" if (uniform_mace_far or cma_uniform_far or non_access_cluster_far) else "No",
        "non_access_timestamp_copy_cluster": "Yes" if non_access_cluster_far else "No",
        "cme_uniform_far_from_anchor": "Yes" if cme_uniform_far else "No",
        "cm_uniform_far_from_anchor": "Yes" if cm_uniform_far else "No",
        "accessed_only_lowlevel_log_core": "No",
        "normal_creation_guard": normal_guard,
        "operation_type": best_operation,
        "operation_normality_score": operation_normality_score,
        "direct_manipulation_score": direct_manipulation_score,
        "artifact_confidence_score": artifact_confidence_score,
        "ecp_mutation_score": f"{ecp_mutation_score:.2f}",
        "ecp_normality_score": f"{ecp_normality_score:.2f}",
        "ecp_tool_context_score": f"{ecp_tool_context_score:.2f}",
        "ecp_confirmed_corroborated": "Yes" if ecp_confirmed_corroborated else "No",
        "bias_hardening_dataset_tokens_enabled": "Yes" if DATASET_SUPPORT_TOKENS else "No",
        "bias_hardening_program_role_gate_strict": "Yes" if PROGRAM_ROLE_GATE_STRICT else "No",
        "ecp_class": ecp_class,
        "ecp_target_linkage": "Yes" if ecp_target_linkage else "No",
        "i30_true_negative_lock": "Yes" if i30_true_negative_lock else "No",
        "i30_parser_mode": s(row.get("i30_parser_mode")),
        "i30_target_level": "Yes" if i30_target_level else "No",
        "i30_cma_moved_from_anchor": "Yes" if i30_cma_moved_from_anchor else "No",
        "i30_e_only_metadata_change": "Yes" if i30_e_only_metadata_change else "No",
        "i30_stale_entry": "Yes" if i30_stale_entry else "No",
        "normal_write_sequence_guard": "Yes" if normal_write_sequence_guard else "No",
        "prefetch_effective": f"{prefetch_effective:.2f}",
        "ecp_evidence_cap": ecp_evidence_cap,
        "decision_margin": margin,
        "expected_pattern_match": expected_match,
        "direct_manipulation_evidence": direct_evidence,
        "anchor_consistency": "No" if (uniform_mace_far or cma_uniform_far or non_access_cluster_far or delayed_basic or valid_logfile_transition) else ("Yes" if normal_guard == "Yes" else "Ambiguous"),
        "delayed_basicinfo": "Yes" if delayed_basic else "No",
        "uniform_mace_far_from_anchor": "Yes" if uniform_mace_far else "No",
        "valid_logfile_transition": "Yes" if valid_logfile_transition else "No",
        "attribute_metadata_change_guard": "Yes" if attribute_metadata_change_guard else "No",
        "attribute_tool_context": "Yes" if attribute_tool_context else "No",
        "normal_activity_guard": "Yes" if normal_activity_guard else "No",
        "tunneling_like_guard": "Yes" if tunneling_like_guard else "No",
        "operation_causality_normality_guard": "Yes" if operation_causality_normality_guard else "No",
        "operation_causality_reason": operation_causality_reason,
        "payload_plausible_for_birth": "Yes" if payload_plausible_for_birth else "No",
        "copy_inheritance_explains_payload": "Yes" if copy_inheritance_explains_payload else "No",
        "unexplained_payload_anomaly": "Yes" if unexplained_payload_anomaly else "No",
        "operation_causality_review_cap": "Yes" if operation_causality_review_cap else "No",
        "payload_c_near_birth": "Yes" if payload_c_near_birth else "No",
        "payload_m_near_birth": "Yes" if payload_m_near_birth else "No",
        "payload_a_near_birth": "Yes" if payload_a_near_birth else "No",
        "payload_e_near_birth": "Yes" if payload_e_near_birth else "No",
        "payload_c_far_birth": "Yes" if payload_c_far_birth else "No",
        "payload_m_far_birth": "Yes" if payload_m_far_birth else "No",
        "payload_a_far_birth": "Yes" if payload_a_far_birth else "No",
        "payload_e_far_birth": "Yes" if payload_e_far_birth else "No",
        "birth_window_metadata_guard": "Yes" if birth_window_metadata_guard else "No",
        "copy_backup_inheritance_guard": "Yes" if copy_backup_inheritance_guard else "No",
        "logfile_creation_phase_guard": "Yes" if logfile_creation_phase_guard else "No",
        "general_tunneling_causality_guard": "Yes" if general_tunneling_causality_guard else "No",
        "stable_post_creation_metadata_edit": "Yes" if stable_post_creation_metadata_edit else "No",
        "post_creation_manipulation_core": "Yes" if post_creation_manipulation_core else "No",
        "operation_payload_conflict_review": "Yes" if operation_payload_conflict_review else "No",
        "payload_far_from_birth_any": "Yes" if payload_far_from_birth_any else "No",
        "payload_far_from_birth_core": "Yes" if payload_far_from_birth_core else "No",
        "copy_inheritance_explains_payload": "Yes" if copy_inheritance_explains_payload else "No",
        "high_confidence_guard_block": "Yes" if high_confidence_guard_block else "No",
        "operation_reasoning": " | ".join(reasoning),
        "scoring_rule_version": SCORING_RULE_VERSION,
        "filename_bias_used": "ContextGuardOnly",
        "folder_label_used": "ContextGuardOnly",
        "dataset_label_bias_used": "False",
        "ground_truth_used_for_detection": "False",
        "all_file_detection_mode": "True",
        "target_role": target_role_label(support_temp_reason),
        "target_role_reason": support_temp_reason or "primary_candidate",
        "role_aware_nonprimary_high": "Yes" if role_aware_nonprimary_high else "No",
        "role_aware_nonprimary_review": "Yes" if role_aware_nonprimary_review else "No",
        "evidence_basis": best_direct if str(prediction).startswith("Suspicious") else (best_operation if prediction == "Normal" else "ambiguous_evidence"),
        "reasons": " | ".join(reasoning),
    })
    return row



# ============================================================
# v1.0 Behavior Alert Layer (NLT-like, non-primary)
# ============================================================

DOCUMENT_ALERT_EXTS = {
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "csv", "rtf", "odt", "ods", "odp"
}


def _pick_row_value(row: Dict[str, str], candidates: List[str], contains_any_tokens: List[str] = None) -> str:
    """Pick a value from a row using exact and fuzzy column matching."""
    if not isinstance(row, dict):
        return ""
    norm = {str(k).strip().lower().replace(" ", "").replace("_", "").replace("/", ""): k for k in row.keys()}
    for cand in candidates:
        key = cand.strip().lower().replace(" ", "").replace("_", "").replace("/", "")
        if key in norm and s(row.get(norm[key])):
            return s(row.get(norm[key]))
    toks = [t.lower() for t in (contains_any_tokens or [])]
    if toks:
        for k, v in row.items():
            nk = str(k).strip().lower().replace(" ", "").replace("_", "").replace("/", "")
            if any(t in nk for t in toks) and s(v):
                return s(v)
    return ""


def _usn_row_time(row: Dict[str, str]) -> Optional[datetime]:
    return parse_dt(_pick_row_value(row, [
        "TimeStamp(UTC+7)", "Timestamp(UTC+7)", "TimeStamp", "Timestamp",
        "EventTime", "Event Time", "Time", "DateTime", "Date/Time"
    ], ["timestamp", "eventtime", "datetime"]))


def _usn_row_usn(row: Dict[str, str]) -> int:
    return parse_int(_pick_row_value(row, [
        "USN", "Usn", "USN Number", "Update Sequence Number", "RecordNumber", "Record Number", "Offset"
    ], ["usn", "recordnumber", "offset"]), 0)


def _usn_row_name(row: Dict[str, str]) -> str:
    return _pick_row_value(row, [
        "File/Directory Name", "FileName", "File Name", "Filename", "Name", "TargetName", "Target"
    ], ["filename", "directoryname", "targetname", "name"])


def _usn_row_path(row: Dict[str, str]) -> str:
    return _pick_row_value(row, ["FullPath", "Full Path", "Path", "FilePath"], ["fullpath", "filepath", "path"])


def _usn_row_reason(row: Dict[str, str]) -> str:
    return _pick_row_value(row, [
        "EventInfo", "Event Info", "Reason", "Reasons", "ReasonFlags", "Reason Flags", "Event", "EventName"
    ], ["eventinfo", "reason", "event"])


def _behavior_severity_from_minutes(minutes: float) -> str:
    if minutes >= 360:
        return "very_strong"
    if minutes >= 30:
        return "strong"
    if minutes >= 5:
        return "suspicious"
    return "weak"


def _is_doc_deletion_candidate(name: str, path: str, reason: str) -> bool:
    base = last_component(name or path).strip()
    ext = Path(base).suffix.lower().lstrip(".")
    if ext not in DOCUMENT_ALERT_EXTS:
        return False
    blob = compact_reason(reason)
    # NLT/MFTECmd variants include File_Deleted, FileDeleted, Delete.
    if not any(tok in blob for tok in ["filedeleted", "deleted", "delete"]):
        return False
    low_context = ("\\" + s(path).replace("/", "\\") + "\\" + base).lower()
    low_base = base.lower()
    # Keep behavior alerts focused on user/document files, not temp/support artifacts.
    if low_base.startswith(("~$", "~wrd", "~wrl")) or low_base.endswith(".tmp"):
        return False
    if any(tok in low_context for tok in [
        "\\windows\\", "\\program files", "\\programdata\\microsoft\\search",
        "\\system volume information", "\\$extend", "\\appdata\\local\\temp",
        "\\input_python", "\\oatfd_output", "\\output_python",
    ]):
        return False
    return True


def detect_system_time_reversal_from_usn(usn_rows: List[Dict[str, str]], threshold_minutes: float = 5.0) -> List[Dict[str, object]]:
    """Detect system clock rollback from monotonic USN order vs event timestamps.

    This is a behavior alert, not file-level timestamp manipulation. It is intended
    to be comparable with NLT's "Manipulation of System Time" alert.
    """
    events = []
    for idx, row in enumerate(usn_rows or []):
        dt = _usn_row_time(row)
        if not dt:
            continue
        usn = _usn_row_usn(row)
        events.append({
            "_idx": idx,
            "usn": usn,
            "time": dt,
            "name": _usn_row_name(row),
            "path": _usn_row_path(row),
            "reason": _usn_row_reason(row),
        })
    if not events:
        return []
    # Prefer USN order if present; otherwise preserve CSV order.
    if any(e["usn"] for e in events):
        events.sort(key=lambda e: (e["usn"] if e["usn"] else 10**30, e["_idx"]))
    else:
        events.sort(key=lambda e: e["_idx"])

    alerts = []
    prev = None
    for cur in events:
        if prev is not None:
            delta_min = (cur["time"] - prev["time"]).total_seconds() / 60.0
            # Current event is newer in journal order, but its timestamp moved backward.
            if delta_min < -threshold_minutes:
                reversal = abs(delta_min)
                alerts.append({
                    "alert_type": "System Time Reversal",
                    "source": "$UsnJrnl:$J",
                    "severity": _behavior_severity_from_minutes(reversal),
                    "previous_usn": prev.get("usn", ""),
                    "current_usn": cur.get("usn", ""),
                    "previous_time": fmt_dt(prev.get("time")),
                    "current_time": fmt_dt(cur.get("time")),
                    "reversal_minutes": f"{reversal:.2f}",
                    "previous_file": prev.get("name", ""),
                    "current_file": cur.get("name", ""),
                    "previous_path": prev.get("path", ""),
                    "current_path": cur.get("path", ""),
                    "previous_reason": prev.get("reason", ""),
                    "current_reason": cur.get("reason", ""),
                    "category": "System Time Anomaly",
                    "primary_manipulation": "False",
                    "note": "USN record order advanced, but event timestamp moved backward.",
                })
        prev = cur
    return alerts


def detect_document_deletions_from_usn(usn_rows: List[Dict[str, str]]) -> List[Dict[str, object]]:
    """Detect document deletion behavior from USN reason flags.

    This is a behavior alert / investigative context, not a timestamp manipulation verdict.
    """
    alerts = []
    seen = set()
    for row in usn_rows or []:
        name = _usn_row_name(row)
        path = _usn_row_path(row)
        reason = _usn_row_reason(row)
        if not _is_doc_deletion_candidate(name, path, reason):
            continue
        dt = _usn_row_time(row)
        usn = _usn_row_usn(row)
        key = (usn, name, path, reason)
        if key in seen:
            continue
        seen.add(key)
        alerts.append({
            "alert_type": "Document Deletion",
            "source": "$UsnJrnl:$J",
            "severity": "suspicious",
            "usn": usn,
            "time": fmt_dt(dt),
            "file_name": name or last_component(path),
            "full_path": path,
            "reason": reason,
            "category": "Deletion Behavior",
            "primary_manipulation": "False",
            "note": "Document-like file deletion observed in USN Journal; context alert, not timestamp manipulation verdict.",
        })
    return alerts


def detect_behavior_alerts(usn_rows: List[Dict[str, str]]) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], List[Dict[str, object]]]:
    """Return behavior alerts separated from Primary Manipulation.

    Output order intentionally mirrors NLT-like reporting: document deletion alerts
    and system time anomalies are useful investigative context but must not be
    counted as file-level timestamp manipulation.
    """
    system_time_anomalies = detect_system_time_reversal_from_usn(usn_rows)
    document_deletion_alerts = detect_document_deletions_from_usn(usn_rows)
    behavior_alerts = []
    behavior_alerts.extend(document_deletion_alerts)
    behavior_alerts.extend(system_time_anomalies)
    return behavior_alerts, system_time_anomalies, document_deletion_alerts


FIELDS = [
    "scenario_id", "file_name", "target_name", "folder", "relative_path", "extension", "logical_id", "target_source_artifact",
    "mft_found", "mft_entry", "mft_sequence", "mft_lsn", "mft_parent_path",
    "mft_si_created", "mft_si_modified", "mft_si_accessed", "mft_si_record_changed",
    "mft_fn_created", "mft_fn_modified", "mft_fn_accessed", "mft_fn_record_changed",
    "mft_si_fn_mismatch", "mft_usec_zeros",
    "i30_found", "i30_parent_path", "i30_record_type", "i30_attributes", "i30_child_mft_ref", "i30_child_sequence", "i30_logical_size", "i30_allocated_size",
    "i30_created", "i30_modified", "i30_accessed", "i30_changed", "i30_reliability", "i30_link_type", "i30_match_count",
    "i30_anchor_delta_min", "i30_anchor_contradiction", "i30_mft_c_delta_min", "i30_mft_m_delta_min", "i30_mft_e_delta_min",
    "i30_uniform_mace_far", "i30_cma_e_split", "i30_cluster_shift", "i30_normal_write_support", "i30_sequence_reuse_signal", "i30_tunneling_guard_hint", "i30_true_negative_lock",
    "i30_parser_mode", "i30_target_level", "i30_current_file_match", "i30_cma_moved_from_anchor", "i30_e_only_metadata_change", "i30_stale_entry", "i30_reason",
    "usn_event_count", "usn_first_time", "usn_last_time", "usn_arrival_candidate",
    "usn_filecreate_first_time", "usn_basicinfo_first_time", "usn_basicinfo_last_time", "usn_delayed_basicinfo_change", "usn_delayed_basicinfo_gap_sec", "usn_basicinfo_isolated", "usn_has_filecreate", "usn_has_delete", "usn_has_basic_info_change", "usn_has_security_change", "usn_has_rename", "usn_has_data_change", "usn_basic_move_basic_pattern", "usn_multiple_isolated_basicinfo", "usn_sequence_compact", "usn_reasons",
    "logfile_event_count", "logfile_has_time_reversal", "logfile_has_timestamp_update", "logfile_has_valid_si_timestamp", "logfile_valid_si_timestamp_transition", "logfile_valid_si_timestamp_count", "logfile_only_sentinel_si_timestamps", "logfile_valid_si_values", "logfile_has_rename",
    "logfile_events", "logfile_first_time", "logfile_last_time",
    "logfile_lsn_values", "logfile_previous_lsn_values", "logfile_mft_references",
    "logfile_current_attributes", "logfile_operations",
    "logfile_standard_information_update", "logfile_update_resident_value", "logfile_undo_redo_hint",
    "lsn_mft_record_lsn", "lsn_logfile_values", "lsn_exact_match", "lsn_near_match",
    "lsn_standard_information_update", "lsn_update_resident_value", "lsn_undo_redo_hint",
    "lsn_transition_candidate", "lsn_transition_strength", "lsn_transition_reasons",
    "anchor_time", "relative_threshold_days",
    "delta_c_days", "delta_m_days", "delta_a_days", "delta_e_days",
    "mft_cma_backdated_count", "mft_mace_backdated_count",
    "mft_relative_backdated", "mft_full_cli_timestomp_pattern", "mft_gui_api_setter_pattern",
    "mft_non_uniform_timestamp_anomaly", "timestamp_spread_days", "mft_entry_changed_near_anchor",
    "lowlevel_mode", "lowlevel_timestamp_mutation_candidate", "lowlevel_strength", "lowlevel_reasons",
    "lowlevel_suspicious_fraction_count", "lowlevel_zero_fraction_count", "lowlevel_rounded_second_count",
    "lowlevel_fraction_pattern", "lowlevel_future_timestamp", "lowlevel_future_fields",
    "lowlevel_si_fn_delta_large", "lowlevel_si_fn_delta_pairs", "lowlevel_max_si_fn_delta_min",
    "lowlevel_si_fn_delta_non_access", "lowlevel_si_fn_accessed_only",
    "lowlevel_future_non_access", "lowlevel_future_accessed_only", "near_time_uniform_mace_core", "accessed_only_lowlevel_log_core",
    "lowlevel_metadata_only_grammar",
    "mutation_core", "normal_creation_guard",
    "operation_type", "operation_normality_score", "direct_manipulation_score", "artifact_confidence_score",
    "ecp_mutation_score", "ecp_normality_score", "ecp_tool_context_score", "ecp_confirmed_corroborated", "bias_hardening_dataset_tokens_enabled", "bias_hardening_program_role_gate_strict", "ecp_class", "ecp_target_linkage", "ecp_evidence_cap",
    "decision_margin", "expected_pattern_match", "direct_manipulation_evidence", "anchor_consistency", "delayed_basicinfo", "uniform_mace_far_from_anchor", "non_access_timestamp_copy_cluster", "cme_uniform_far_from_anchor", "cm_uniform_far_from_anchor", "valid_logfile_transition", "attribute_metadata_change_guard", "attribute_tool_context", "normal_activity_guard", "tunneling_like_guard", "operation_causality_normality_guard", "operation_causality_reason", "payload_plausible_for_birth", "copy_inheritance_explains_payload", "unexplained_payload_anomaly", "operation_causality_review_cap", "payload_c_near_birth", "payload_m_near_birth", "payload_a_near_birth", "payload_e_near_birth", "payload_c_far_birth", "payload_m_far_birth", "payload_a_far_birth", "payload_e_far_birth", "birth_window_metadata_guard", "copy_backup_inheritance_guard", "logfile_creation_phase_guard", "general_tunneling_causality_guard", "stable_post_creation_metadata_edit", "post_creation_manipulation_core", "operation_payload_conflict_review", "payload_far_from_birth_any", "payload_far_from_birth_core", "copy_inheritance_explains_payload", "high_confidence_guard_block", "operation_reasoning",
    "scoring_rule_version",
    "prefetch_anchor_time", "prefetch_candidate_count", "prefetch_candidates",
    "prefetch_best_candidate", "prefetch_best_delta_min", "prefetch_best_anchor",
    "prefetch_has_low_run_candidate", "prefetch_masquerade_hint",
    "lnk_windows_hit_count", "lnk_windows_sources", "lnk_office_hit_count", "lnk_office_sources",
    "filename_bias_used", "folder_label_used", "dataset_label_bias_used", "ground_truth_used_for_detection", "all_file_detection_mode",
    "target_role", "target_role_reason", "role_aware_nonprimary_high", "role_aware_nonprimary_review", "evidence_basis",
    "score", "prediction", "prediction_type", "reasons",
]

def detect(input_dir: Path, out_dir: Path, all_files=False, target_keyword="", extensions="", threshold=180, prefetch_window=30, tz_offset=7) -> List[Dict[str, object]]:
    global SUPPORT_MANIFEST_NAMES
    SUPPORT_MANIFEST_NAMES = _load_support_manifest(input_dir)
    data = load_inputs(input_dir)
    exts = [x.strip() for x in (extensions or "docx,doc,xlsx,xls,txt,pdf,pptx,ppt,rtf,pub,accdb,csv,lnk,pf,exe,dll,e01").split(",")]
    targets = infer_targets_from_available(data, exts, target_keyword, all_files)
    pe = prefetch_events(data["pf"])

    rows = []
    reasoning = []
    timeline = []
    suspicious = []

    behavior_alerts, system_time_anomalies, document_deletion_alerts = detect_behavior_alerts(data.get("usn", []))

    for t in targets:
        target = s(t["target_name"])
        folder = s(t.get("folder"))
        selected_mft = select_mft_for_target(data["mft"], t)
        mf = mft_features(selected_mft)
        entry_for_link = mf.get("mft_entry") or t.get("mft_entry_hint", "")
        seq_for_link = mf.get("mft_sequence") or t.get("mft_sequence_hint", "")
        lsn_for_link = mf.get("mft_lsn") or t.get("mft_lsn_hint", "")
        uf = usn_features(data["usn"], target, folder, entry_for_link, seq_for_link)
        lf = log_features(data["log"], target, folder, entry_for_link, lsn_for_link)

        log_anchor = lf.get("_log_anchor") if isinstance(lf.get("_log_anchor"), datetime) else None
        usn_anchor = uf.get("_usn_anchor") if isinstance(uf.get("_usn_anchor"), datetime) else None

        anchor = log_anchor if isinstance(log_anchor, datetime) else usn_anchor
        if not isinstance(anchor, datetime):
            anchor = None

        lf.pop("_log_anchor", None)
        uf.pop("_usn_anchor", None)

        rf = relative_features(mf, anchor, threshold)
        lsnf = lsn_transition_features(mf, lf)
        # $I30 must be compared to the file creation anchor, not to a later LogFile/BasicInfoChange
        # anchor.  Otherwise normal attribute/rename changes can look like false $I30 contradictions.
        i30_anchor = parse_dt(uf.get("usn_filecreate_first_time")) or parse_dt(mf.get("mft_si_created")) or anchor
        i30f = i30_features(data.get("i30", []), target, folder, mf, i30_anchor, threshold)

        prefetch_anchors = []
        if isinstance(usn_anchor, datetime):
            prefetch_anchors.append(("USN", usn_anchor))
        if isinstance(log_anchor, datetime):
            prefetch_anchors.append(("LogFile", log_anchor))
            prefetch_anchors.append(("LogFile_minus_offset", log_anchor - timedelta(hours=tz_offset)))
            prefetch_anchors.append(("LogFile_plus_offset", log_anchor + timedelta(hours=tz_offset)))
        if isinstance(anchor, datetime):
            prefetch_anchors.append(("MainAnchor", anchor))

        # v1.0: collect tool-execution context even when the current MFT state
        # does not yet show a strong timestamp-vector anomaly. Some successful
        # manipulation scenarios can leave weak file-level traces but still occur
        # within a confirmed timestamp-tool batch. Context guard later prevents
        # normal folders from becoming high-confidence false positives.
        pf = prefetch_features(pe, prefetch_anchors, True, prefetch_window)
        lw = lnk_features(data["lnk_w"], target)
        lo = lnk_features(data["lnk_o"], target)

        row = {
            "scenario_id": t.get("scenario_id", ""),
            "file_name": t.get("file_name", ""),
            "target_name": target,
            "folder": folder,
            "relative_path": t.get("relative_path", ""),
            "extension": t.get("extension", ""),
            "logical_id": t.get("logical_id", ""),
            "target_source_artifact": t.get("target_source_artifact", ""),
        }
        row.update(mf)
        row.update(uf)
        row.update(lf)
        row.update(rf)
        row.update(lsnf)
        row.update(i30f)
        row.update(lowlevel_features(mf, uf, lf, rf, lsnf))
        row.update(pf)
        row["lnk_windows_hit_count"] = lw["lnk_hit_count"]
        row["lnk_windows_sources"] = lw["lnk_sources"]
        row["lnk_office_hit_count"] = lo["lnk_hit_count"]
        row["lnk_office_sources"] = lo["lnk_sources"]

        row = score(row)
        rows.append(row)

        reasoning.append({
            "target_name": target,
            "prediction": row["prediction"],
            "prediction_type": row["prediction_type"],
            "score": row["score"],
            "reasoning": row["reasons"],
            "key_relative": f"anchor={row['anchor_time']} C={row['delta_c_days']} M={row['delta_m_days']} A={row['delta_a_days']} E={row['delta_e_days']}",
            "key_mft": f"SI-C={row['mft_si_created']} SI-M={row['mft_si_modified']} SI-A={row['mft_si_accessed']} SI-E={row['mft_si_record_changed']}",
            "key_prefetch": row["prefetch_candidates"],
            "key_lsn": f"MFT_LSN={row.get('mft_lsn','')} exact={row.get('lsn_exact_match','')} near={row.get('lsn_near_match','')} reason={row.get('lsn_transition_reasons','')}",
            "filename_bias_used": row.get("filename_bias_used", "False"),
            "folder_label_used": row.get("folder_label_used", "False"),
            "ground_truth_used_for_detection": row.get("ground_truth_used_for_detection", "False"),
            "evidence_basis": row.get("evidence_basis", ""),
            "ecp_class": row.get("ecp_class", ""),
            "ecp_mutation_score": row.get("ecp_mutation_score", ""),
            "ecp_normality_score": row.get("ecp_normality_score", ""),
            "ecp_tool_context_score": row.get("ecp_tool_context_score", ""),
            "key_i30": f"I30={row.get('i30_found','')} rel={row.get('i30_reliability','')} C={row.get('i30_created','')} M={row.get('i30_modified','')} A={row.get('i30_accessed','')} E={row.get('i30_changed','')} reason={row.get('i30_reason','')}",
        })

        for field, label in [
            ("usn_first_time", "USN first event"),
            ("usn_last_time", "USN last event"),
            ("logfile_first_time", "LogFile first context"),
            ("logfile_last_time", "LogFile last context"),
            ("anchor_time", "Anchor time"),
        ]:
            tv = s(row.get(field))
            # Jangan tampilkan FILETIME null/default seperti 1601-01-01 atau 0000-00-00 pada timeline visual.
            if tv and not (tv.startswith("1601-01-01") or tv.startswith("0000-00-00") or tv.startswith("1970-01-01")):
                timeline.append({
                    "Time": row.get(field),
                    "TargetName": target,
                    "Event": label,
                    "Prediction": row["prediction"],
                    "Detail": row["reasons"],
                })

        if str(row["prediction"]).startswith("Suspicious"):
            suspicious.append({
                "Category": "Timestamp Manipulation",
                "TargetName": target,
                "Prediction": row["prediction"],
                "PredictionType": row["prediction_type"],
                "Score": row["score"],
                "Evidence": row["reasons"],
                "LSNTransitionCandidate": row.get("lsn_transition_candidate", ""),
                "LSNTransitionStrength": row.get("lsn_transition_strength", ""),
                "LSNTransitionReasons": row.get("lsn_transition_reasons", ""),
                "MFT_Record_LSN": row.get("mft_lsn", ""),
                "LogFile_LSN_Values": row.get("logfile_lsn_values", ""),
                "LSNExactMatch": row.get("lsn_exact_match", ""),
                "LSNNearMatch": row.get("lsn_near_match", ""),
                "LowLevelCandidate": row.get("lowlevel_timestamp_mutation_candidate", ""),
                "LowLevelStrength": row.get("lowlevel_strength", ""),
                "LowLevelReasons": row.get("lowlevel_reasons", ""),
                "LowLevelFutureTimestamp": row.get("lowlevel_future_timestamp", ""),
                "LowLevelFutureFields": row.get("lowlevel_future_fields", ""),
                "LowLevelSIFNDelta": row.get("lowlevel_si_fn_delta_large", ""),
                "LowLevelSIFNDeltaPairs": row.get("lowlevel_si_fn_delta_pairs", ""),
                "LowLevelSIFNDeltaNonAccess": row.get("lowlevel_si_fn_delta_non_access", ""),
                "LowLevelSIFNAccessedOnly": row.get("lowlevel_si_fn_accessed_only", ""),
                "LowLevelFutureNonAccess": row.get("lowlevel_future_non_access", ""),
                "LowLevelFutureAccessedOnly": row.get("lowlevel_future_accessed_only", ""),
                "NearTimeUniformMACECore": row.get("near_time_uniform_mace_core", ""),
                "AccessedOnlyLowLevelLogCore": row.get("accessed_only_lowlevel_log_core", ""),
                "LowLevelMetadataOnlyGrammar": row.get("lowlevel_metadata_only_grammar", ""),
                "MutationCore": row.get("mutation_core", ""),
                "NormalCreationGuard": row.get("normal_creation_guard", ""),
                "ScoringRuleVersion": row.get("scoring_rule_version", ""),
                "OperationType": row.get("operation_type", ""),
                "OperationNormalityScore": row.get("operation_normality_score", ""),
                "DirectManipulationScore": row.get("direct_manipulation_score", ""),
                "ArtifactConfidenceScore": row.get("artifact_confidence_score", ""),
                "ECPMutationScore": row.get("ecp_mutation_score", ""),
                "ECPNormalityScore": row.get("ecp_normality_score", ""),
                "ECPToolContextScore": row.get("ecp_tool_context_score", ""),
                "ECPClass": row.get("ecp_class", ""),
                "ECPTargetLinkage": row.get("ecp_target_linkage", ""),
                "DecisionMargin": row.get("decision_margin", ""),
                "ExpectedPatternMatch": row.get("expected_pattern_match", ""),
                "DirectManipulationEvidence": row.get("direct_manipulation_evidence", ""),
                "OperationReasoning": row.get("operation_reasoning", ""),
                "LowLevelFractionPattern": row.get("lowlevel_fraction_pattern", ""),
                "MFT_SI_Created": row["mft_si_created"],
                "MFT_SI_Modified": row["mft_si_modified"],
                "MFT_SI_Accessed": row["mft_si_accessed"],
                "MFT_SI_EntryModified": row["mft_si_record_changed"],
                "USN_Support": row["usn_has_basic_info_change"],
                "LogFile_Support": row["logfile_has_time_reversal"],
                "PrefetchBestCandidate": row["prefetch_best_candidate"],
                "PrefetchCandidates": row["prefetch_candidates"],
                "I30Found": row.get("i30_found", ""),
                "I30Reliability": row.get("i30_reliability", ""),
                "I30Created": row.get("i30_created", ""),
                "I30Modified": row.get("i30_modified", ""),
                "I30Accessed": row.get("i30_accessed", ""),
                "I30Changed": row.get("i30_changed", ""),
                "I30AnchorContradiction": row.get("i30_anchor_contradiction", ""),
                "I30NormalWriteSupport": row.get("i30_normal_write_support", ""),
                "I30TunnelingGuardHint": row.get("i30_tunneling_guard_hint", ""),
                "I30Reason": row.get("i30_reason", ""),
                "LNK_Windows_Hits": row["lnk_windows_hit_count"],
                "LNK_Office_Hits": row["lnk_office_hit_count"],
                "ToolAttributionLevel": "candidate" if s(row["prefetch_best_candidate"]) else "not_available",
                "FilenameBiasUsed": row.get("filename_bias_used", "False"),
                "FolderLabelUsed": row.get("folder_label_used", "False"),
                "GroundTruthUsedForDetection": row.get("ground_truth_used_for_detection", "False"),
                "TargetRole": row.get("target_role", ""),
                "TargetRoleReason": row.get("target_role_reason", ""),
                "EvidenceBasis": row.get("evidence_basis", ""),
                "Caution": "Indikasi berbasis korelasi artefak; bukan atribusi absolut tool pelaku.",
            })

    # v1.0: NLT-like non-primary behavior alert layer.
    write_csv(out_dir / "behavior_alerts.csv", behavior_alerts, [
        "alert_type", "source", "severity", "usn", "time",
        "previous_usn", "current_usn", "previous_time", "current_time", "reversal_minutes",
        "file_name", "full_path", "reason",
        "previous_file", "current_file", "previous_path", "current_path", "previous_reason", "current_reason",
        "category", "primary_manipulation", "note"
    ])
    write_csv(out_dir / "system_time_anomalies.csv", system_time_anomalies, [
        "alert_type", "source", "severity", "previous_usn", "current_usn", "previous_time", "current_time",
        "reversal_minutes", "previous_file", "current_file", "previous_path", "current_path",
        "previous_reason", "current_reason", "category", "primary_manipulation", "note"
    ])
    write_csv(out_dir / "document_deletion_alerts.csv", document_deletion_alerts, [
        "alert_type", "source", "severity", "usn", "time", "file_name", "full_path", "reason",
        "category", "primary_manipulation", "note"
    ])

    for a in behavior_alerts:
        if a.get("alert_type") == "System Time Reversal":
            timeline.append({
                "Time": a.get("current_time", ""),
                "TargetName": "SYSTEM_TIME",
                "Event": "Behavior Alert - System Time Reversal",
                "Prediction": "Behavior Alert",
                "Detail": f"{a.get('previous_time')} -> {a.get('current_time')} reversal_minutes={a.get('reversal_minutes')} severity={a.get('severity')}"
            })
        elif a.get("alert_type") == "Document Deletion":
            timeline.append({
                "Time": a.get("time", ""),
                "TargetName": a.get("file_name", ""),
                "Event": "Behavior Alert - Document Deletion",
                "Prediction": "Behavior Alert",
                "Detail": a.get("note", "")
            })

    timeline.sort(key=lambda r: s(r.get("Time")))

    write_csv(out_dir / "detection_matrix.csv", rows, FIELDS)

    # v1.0: explicit all-file classification export.
    # This file proves the detector is not a "Uji-only" detector: every file
    # target built from MFT / fallback artifacts is listed with its prediction.
    all_file_rows = []
    for r in rows:
        all_file_rows.append({
            "TargetName": r.get("target_name", ""),
            "RelativePath": r.get("relative_path", ""),
            "Extension": r.get("extension", ""),
            "TargetSourceArtifact": r.get("target_source_artifact", ""),
            "TargetRole": r.get("target_role", ""),
            "TargetRoleReason": r.get("target_role_reason", ""),
            "Prediction": r.get("prediction", ""),
            "PredictionType": r.get("prediction_type", ""),
            "Score": r.get("score", ""),
            "OperationType": r.get("operation_type", ""),
            "DirectManipulationScore": r.get("direct_manipulation_score", ""),
            "OperationNormalityScore": r.get("operation_normality_score", ""),
            "ArtifactConfidenceScore": r.get("artifact_confidence_score", ""),
            "ECPMutationScore": r.get("ecp_mutation_score", ""),
            "ECPNormalityScore": r.get("ecp_normality_score", ""),
            "ECPToolContextScore": r.get("ecp_tool_context_score", ""),
            "ECPClass": r.get("ecp_class", ""),
            "ECPTargetLinkage": r.get("ecp_target_linkage", ""),
            "ECPEvidenceCap": r.get("ecp_evidence_cap", ""),
            "I30Found": r.get("i30_found", ""),
            "I30Reliability": r.get("i30_reliability", ""),
            "I30Created": r.get("i30_created", ""),
            "I30Modified": r.get("i30_modified", ""),
            "I30Accessed": r.get("i30_accessed", ""),
            "I30Changed": r.get("i30_changed", ""),
            "I30AnchorContradiction": r.get("i30_anchor_contradiction", ""),
            "I30NormalWriteSupport": r.get("i30_normal_write_support", ""),
            "I30TunnelingGuardHint": r.get("i30_tunneling_guard_hint", ""),
            "I30TrueNegativeLock": r.get("i30_true_negative_lock", ""),
            "I30Reason": r.get("i30_reason", ""),
            "DecisionMargin": r.get("decision_margin", ""),
            "EvidenceBasis": r.get("evidence_basis", ""),
            "NormalActivityGuard": r.get("normal_activity_guard", ""),
            "TunnelingLikeGuard": r.get("tunneling_like_guard", ""),
            "FilenameBiasUsed": r.get("filename_bias_used", "False"),
            "FolderLabelUsed": r.get("folder_label_used", "False"),
            "GroundTruthUsedForDetection": r.get("ground_truth_used_for_detection", "False"),
            "Reasoning": r.get("reasons", ""),
        })
    write_csv(out_dir / "all_file_classification.csv", all_file_rows, [
        "TargetName", "RelativePath", "Extension", "TargetSourceArtifact", "TargetRole", "TargetRoleReason",
        "Prediction", "PredictionType", "Score", "OperationType",
        "DirectManipulationScore", "OperationNormalityScore", "ArtifactConfidenceScore",
        "ECPMutationScore", "ECPNormalityScore", "ECPToolContextScore", "ECPClass", "ECPTargetLinkage", "ECPEvidenceCap",
        "I30Found", "I30Reliability", "I30Created", "I30Modified", "I30Accessed", "I30Changed", "I30AnchorContradiction", "I30NormalWriteSupport", "I30TunnelingGuardHint", "I30TrueNegativeLock", "I30Reason",
        "DecisionMargin", "EvidenceBasis", "NormalActivityGuard", "TunnelingLikeGuard",
        "FilenameBiasUsed", "FolderLabelUsed", "GroundTruthUsedForDetection", "Reasoning"
    ])

    # v1.0: role-aware anomaly triage report. This file is the answer for real cases
    # where non-primary artifacts (.ps1/.exe/.dll/README/recycle/support/container) may
    # themselves be timestamp-manipulated. They are not suppressed; they are separated
    # from high-confidence primary document hits.
    non_primary_artifact_anomalies = []
    for r in rows:
        role = r.get("target_role", "")
        ptype = str(r.get("prediction_type", ""))
        if role != "Primary File Target" and (
            str(r.get("role_aware_nonprimary_high", "")).lower() == "yes"
            or str(r.get("role_aware_nonprimary_review", "")).lower() == "yes"
            or ptype.startswith("role_aware_")
        ):
            non_primary_artifact_anomalies.append({
                "TargetName": r.get("target_name", ""),
                "RelativePath": r.get("relative_path", ""),
                "Extension": r.get("extension", ""),
                "TargetRole": role,
                "TargetRoleReason": r.get("target_role_reason", ""),
                "Prediction": r.get("prediction", ""),
                "PredictionType": r.get("prediction_type", ""),
                "Score": r.get("score", ""),
                "EvidenceBasis": r.get("evidence_basis", ""),
                "DirectManipulationScore": r.get("direct_manipulation_score", ""),
                "ArtifactConfidenceScore": r.get("artifact_confidence_score", ""),
                "PrefetchBestCandidate": r.get("prefetch_best_candidate", ""),
                "LSNExactMatch": r.get("lsn_exact_match", ""),
                "LSNNearMatch": r.get("lsn_near_match", ""),
                "Reasoning": r.get("reasons", ""),
            })
    write_csv(out_dir / "non_primary_artifact_anomalies.csv", non_primary_artifact_anomalies, [
        "TargetName", "RelativePath", "Extension", "TargetRole", "TargetRoleReason",
        "Prediction", "PredictionType", "Score", "EvidenceBasis", "DirectManipulationScore",
        "ArtifactConfidenceScore", "PrefetchBestCandidate", "LSNExactMatch", "LSNNearMatch", "Reasoning"
    ])

    high_risk_non_primary = [r for r in non_primary_artifact_anomalies if str(r.get("Prediction", "")).startswith("High-Risk")]
    write_csv(out_dir / "high_risk_non_primary_artifacts.csv", high_risk_non_primary, [
        "TargetName", "RelativePath", "Extension", "TargetRole", "TargetRoleReason",
        "Prediction", "PredictionType", "Score", "EvidenceBasis", "DirectManipulationScore",
        "ArtifactConfidenceScore", "PrefetchBestCandidate", "LSNExactMatch", "LSNNearMatch", "Reasoning"
    ])

    write_csv(out_dir / "case_reasoning.csv", reasoning, ["target_name", "prediction", "prediction_type", "score", "reasoning", "key_relative", "key_mft", "key_prefetch", "key_lsn", "filename_bias_used", "folder_label_used", "dataset_label_bias_used", "ground_truth_used_for_detection", "evidence_basis", "ecp_class", "ecp_mutation_score", "ecp_normality_score", "ecp_tool_context_score"])
    write_csv(out_dir / "suspicious_behavior_detection.csv", suspicious, [
        "Category", "TargetName", "Prediction", "PredictionType", "Score", "Evidence",
        "LSNTransitionCandidate", "LSNTransitionStrength", "LSNTransitionReasons",
        "MFT_Record_LSN", "LogFile_LSN_Values", "LSNExactMatch", "LSNNearMatch",
        "LowLevelCandidate", "LowLevelStrength", "LowLevelReasons",
        "LowLevelFutureTimestamp", "LowLevelFutureFields",
        "LowLevelSIFNDelta", "LowLevelSIFNDeltaPairs", "LowLevelSIFNDeltaNonAccess", "LowLevelSIFNAccessedOnly",
        "LowLevelFutureNonAccess", "LowLevelFutureAccessedOnly", "NearTimeUniformMACECore",
        "LowLevelMetadataOnlyGrammar", "MutationCore", "NormalCreationGuard", "ScoringRuleVersion", "LowLevelFractionPattern",
        "MFT_SI_Created", "MFT_SI_Modified", "MFT_SI_Accessed", "MFT_SI_EntryModified",
        "USN_Support", "LogFile_Support", "PrefetchBestCandidate", "PrefetchCandidates",
        "I30Found", "I30Reliability", "I30Created", "I30Modified", "I30Accessed", "I30Changed", "I30AnchorContradiction", "I30NormalWriteSupport", "I30TunnelingGuardHint", "I30Reason",
        "LNK_Windows_Hits", "LNK_Office_Hits", "ToolAttributionLevel", "FilenameBiasUsed", "FolderLabelUsed", "GroundTruthUsedForDetection", "TargetRole", "TargetRoleReason", "EvidenceBasis", "Caution",
    ])
    write_csv(out_dir / "timeline_events.csv", timeline, ["Time", "TargetName", "Event", "Prediction", "Detail"])

    # v1.0: explicit official triage files for GUI/report parity.
    high_confidence_rows = [r for r in rows if str(r.get("prediction", "")) == "Suspicious High"]
    need_review_rows = [r for r in rows if str(r.get("prediction", "")) == "Need Review"]
    write_csv(out_dir / "high_confidence_suspicious.csv", high_confidence_rows, FIELDS)
    write_csv(out_dir / "need_review_candidates.csv", need_review_rows, FIELDS)
    unique_summary = []
    for pred in ["Suspicious High", "High-Risk Non-Primary Artifact", "Need Review", "Normal", "Excluded"]:
        vals = [r for r in rows if str(r.get("prediction", "")) == pred]
        unique_summary.append({"prediction": pred, "count": len(vals)})
    write_csv(out_dir / "unique_detection_summary.csv", unique_summary, ["prediction", "count"])
    comparison_summary = [
        {"field": "scoring_rule_version", "value": SCORING_RULE_VERSION},
        {"field": "high_confidence_suspicious", "value": len(high_confidence_rows)},
        {"field": "need_review", "value": len(need_review_rows)},
        {"field": "normal", "value": sum(1 for r in rows if str(r.get("prediction", "")) == "Normal")},
        {"field": "high_risk_non_primary", "value": sum(1 for r in rows if str(r.get("prediction", "")) == "High-Risk Non-Primary Artifact")},
        {"field": "behavior_alerts", "value": len(behavior_alerts)},
        {"field": "note", "value": "Only Suspicious High is high-confidence primary manipulation; Need Review and behavior alerts are triage/context."},
    ]
    write_csv(out_dir / "comparison_ready_summary.csv", comparison_summary, ["field", "value"])

    manipulation_count = sum(1 for r in rows if str(r["prediction"]).startswith("Suspicious"))
    need_review_count = sum(1 for r in rows if str(r["prediction"]) == "Need Review")
    excluded_count = sum(1 for r in rows if str(r["prediction"]) == "Excluded")
    normal_count = sum(1 for r in rows if str(r["prediction"]) == "Normal")
    behavior_alert_count = len(behavior_alerts)
    system_time_anomaly_count = len(system_time_anomalies)
    document_deletion_alert_count = len(document_deletion_alerts)
    summary = [
        {"field": "target_count", "value": len(rows)},
        {"field": "manipulation_count", "value": manipulation_count},
        {"field": "suspicious_count", "value": manipulation_count},
        {"field": "need_review_count", "value": need_review_count},
        {"field": "normal_count", "value": normal_count},
        {"field": "excluded_count", "value": excluded_count},
        {"field": "behavior_alert_count", "value": behavior_alert_count},
        {"field": "system_time_anomaly_count", "value": system_time_anomaly_count},
        {"field": "document_deletion_alert_count", "value": document_deletion_alert_count},
        {"field": "all_files", "value": all_files},
        {"field": "target_path_keyword", "value": target_keyword},
        {"field": "relative_threshold_days", "value": threshold},
        {"field": "prefetch_window_min", "value": prefetch_window},
        {"field": "timezone_offset_hours", "value": tz_offset},
        {"field": "support_manifest_count", "value": len(SUPPORT_MANIFEST_NAMES)},
        {"field": "scoring_rule_version", "value": SCORING_RULE_VERSION},
        {"field": "algorithm", "value": OATFD_VERSION + " Evidence-Capped Cross-Artifact Plausibility Scoring + FP Guards + Behavior Alerts"},
        {"field": "missing_artifacts", "value": ",".join(data.get("_missing_artifacts", []))},
        {"field": "note", "value": "Real-case mode: no Excluded label; all non-manipulated files default to Normal; detection still runs with single-artifact and partial-artifact modes such as raw Jung Oh USN-only / $UsnJrnl_$J.bin, MFT-only, LogFile-only, Prefetch/LNK-only, or any combination."},
    ]
    write_csv(out_dir / "run_summary.csv", summary, ["field", "value"])

    return rows


# ============================================================
# Main CLI
# ============================================================

def main() -> int:
    ap = argparse.ArgumentParser(description="OATFD detection engine for NTFS timestamp manipulation analysis.")
    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--case", default="", help="Folder case. Dipakai untuk parse+detect.")
    src.add_argument("--input", default="", help="Folder INPUT_PYTHON jika hanya ingin detect.")

    ap.add_argument("--raw-dir", default="", help="Folder artefak mentah. Default: <case> atau <case>\\RAW_ARTIFACTS jika ada.")
    ap.add_argument("--output", default="", help="Folder output final. Default: <case>\\OATFD_OUTPUT atau <input>\\OATFD_OUTPUT.")
    ap.add_argument("--tool-roots", default="Z:\\,C:\\TOOLS,C:\\Users\\vboxuser\\Downloads,C:\\")
    ap.add_argument("--mftecmd", default="")
    ap.add_argument("--pecmd", default="")
    ap.add_argument("--lecmd", default="")

    ap.add_argument("--parse-only", action="store_true")
    ap.add_argument("--detect-only", action="store_true")
    ap.add_argument("--all", action="store_true", help="Parse lalu detect.")
    ap.add_argument("--all-files", action="store_true", help="Detect semua file aktif dari MFT.")
    ap.add_argument("--target-path-keyword", default="")
    ap.add_argument("--extensions", default="docx,doc,xlsx,xls,txt,pdf,pptx,ppt,rtf,pub,accdb,csv,lnk,pf,exe,dll,e01")
    ap.add_argument("--relative-threshold-days", type=int, default=180)
    ap.add_argument("--prefetch-window", type=int, default=30)
    ap.add_argument("--timezone-offset", type=int, default=7)
    ap.add_argument("--dry-run", action="store_true")

    args = ap.parse_args()

    if not args.case and not args.input:
        say("[ERROR] Gunakan --case atau --input.")
        return 1

    if args.input:
        input_dir = Path(args.input)
        case_dir = input_dir.parent
    else:
        case_dir = Path(args.case)
        input_dir = case_dir / "INPUT_PYTHON"

    raw_dir = Path(args.raw_dir) if args.raw_dir else ((case_dir / "RAW_ARTIFACTS") if (case_dir / "RAW_ARTIFACTS").exists() else case_dir)
    parsed_dir = case_dir / "Parsed_CSV"
    out_dir = Path(args.output) if args.output else case_dir / "OATFD_OUTPUT"

    ensure_dir(input_dir)
    ensure_dir(parsed_dir)
    ensure_dir(out_dir)

    do_parse = args.all or args.parse_only or (not args.detect_only and not args.input)
    do_detect = args.all or args.detect_only or (not args.parse_only)

    if do_parse:
        roots = parse_roots(args.tool_roots)
        mftecmd = Path(args.mftecmd) if args.mftecmd else find_first(roots, "MFTECmd.exe")
        pecmd = Path(args.pecmd) if args.pecmd else find_first(roots, "PECmd.exe")
        lecmd = Path(args.lecmd) if args.lecmd else find_first(roots, "LECmd.exe")

        say("[TOOLS]")
        say(f"MFTECmd: {mftecmd if mftecmd else 'NOT FOUND'}")
        say(f"PECmd   : {pecmd if pecmd else 'NOT FOUND'}")
        say(f"LECmd   : {lecmd if lecmd else 'NOT FOUND / OPTIONAL'}")

        if not mftecmd:
            say("[ERROR] MFTECmd.exe wajib untuk parse MFT/USN.")
            return 2
        if not pecmd:
            say("[ERROR] PECmd.exe wajib untuk parse Prefetch.")
            return 2

        say("")
        say("[STEP] Parse artifacts")
        parse_mft(raw_dir, input_dir, parsed_dir, mftecmd, args.dry_run)
        parse_usn(raw_dir, input_dir, parsed_dir, mftecmd, args.dry_run)
        parse_prefetch(raw_dir, input_dir, parsed_dir, pecmd, args.dry_run)
        parse_lnk(raw_dir, input_dir, parsed_dir, lecmd, args.dry_run)
        copy_or_build_logfile_csv(case_dir, raw_dir, input_dir, target_keyword=args.target_path_keyword)

    if do_detect:
        say("")
        say("[STEP] Detect/correlate")
        rows = detect(
            input_dir=input_dir,
            out_dir=out_dir,
            all_files=args.all_files,
            target_keyword=args.target_path_keyword,
            extensions=args.extensions,
            threshold=args.relative_threshold_days,
            prefetch_window=args.prefetch_window,
            tz_offset=args.timezone_offset,
        )
        say(f"[DONE] Detection selesai. Target={len(rows)}")
        say(f"[OUTPUT] {out_dir}")
        say("- detection_matrix.csv")
        say("- case_reasoning.csv")
        say("- suspicious_behavior_detection.csv")
        say("- timeline_events.csv")
        say("- run_summary.csv")
        say("- non_primary_artifact_anomalies.csv")
        say("- high_risk_non_primary_artifacts.csv")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
