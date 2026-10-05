# OATFD v1.0 — Operational Artifact-based Timestamp Forensic Detector

**Thesis Edition · Telkom University 2026**

## Overview

OATFD v1.0 is the thesis implementation of a causal-timeline reasoning engine for NTFS artifact-based timestamp-manipulation analysis. The system evaluates timestamp-manipulation indications by combining evidence from available NTFS-related artifacts:

- MFT-derived metadata
- USN Journal records
- $LogFile transitions
- Prefetch / LNK context
- $I30 directory-index evidence (when available)

A timestamp anomaly is **not** automatically classified as manipulation. The engine applies causal-timeline reasoning to distinguish high-confidence post-creation metadata manipulation from normal lifecycle behavior (file creation, copy/backup timestamp inheritance, tunneling-like delete-create sequences, parser timezone representation differences, and context-only support artifacts).

## Output Categories

| Label | Meaning |
|---|---|
| **Suspicious High** | High-confidence primary timestamp-manipulation decision |
| **Need Review** | Ambiguous or insufficiently corroborated candidate — requires analyst review |
| **High-Risk Non-Primary Artifact** | Contextual signals; not a final timestamp-manipulation verdict |
| **Normal** | Observed artifact pattern sufficiently explained by ordinary operation grammar |

## How to Run

1. Extract the package to a short path, e.g. `C:\OATFD_V1\`
2. Run `RUN_FILEPICKER_LFP_APP.bat`
3. Select the relevant artifact files through the GUI
4. Review outputs in the generated `OATFD_OUTPUT` folder

## Version Constants

```
OATFD_VERSION        = OATFD v1.0 Causal-Timeline Guard Thesis Edition
SCORING_RULE_VERSION = OATFD_v1_0_causal_timeline_guard
```

## Recommended Thesis Citation Wording

> "This thesis uses OATFD v1.0 Thesis Edition as the evaluated implementation. Version 1.0 denotes the consolidated thesis release, not a sequence of public software revisions."

## Files

| File | Description |
|---|---|
| `oatfd_engine.py` | Core detection engine |
| `artifact_filepicker_engine.py` | GUI artifact file picker |
| `artifact_filepicker_lfp_engine.py` | GUI artifact file picker (LFP variant) |
| `NTFS_Artifact_FilePicker_App.py` | App launcher |
| `NTFS_Artifact_FilePicker_LFP_App.py` | App launcher (LFP variant) |
| `visual_report_generator.py` | Visual report generator |
| `TOOLS/` | Bundled dependencies (sqlite3.dll, etc.) |
