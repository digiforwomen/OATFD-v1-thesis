# OATFD v1.0 — Thesis Release

**OATFD (Operational Artifact-based Timestamp Forensic Detector) v1.0** is a cross-artifact forensic triage system for detecting indicators of NTFS timestamp manipulation. This repository contains the implementation submitted with and cited in:

> Husnul Hafshah Devi, Maman Abdurohman, and Yudi Prayudi, *"A Cross-Artifact Forensic Triage Method for Detecting NTFS Timestamp Manipulation,"* International Journal of Electrical and Computer Engineering (IJECE), 2026.

> Husnul Hafshah Devi, *"Development of a Cross-Artifact Forensic Triage Method for Detecting Indicators of NTFS Timestamp Manipulation"* (M.S.F. thesis), School of Computing, Telkom University, Bandung, Indonesia, 2026.

---

## Repository contents

| File / Folder | Description |
|---|---|
| `OATFD_v1/oatfd_engine.py` | **Main engine.** Scoring-rule version `OATFD_v1_0_causal_timeline_guard`. Contains the ECP scoring model, ten-guard normality architecture, and eleven-level decision cascade. |
| `OATFD_v1/artifact_filepicker_lfp_engine.py` | Full-pipeline launcher (includes $LogFile corroboration path — recommended). |
| `OATFD_v1/artifact_filepicker_engine.py` | Simplified launcher (without $LogFile). |
| `OATFD_v1/visual_report_generator.py` | Report visualisation helper. |
| `OATFD_v1/TOOLS/` | Third-party forensic utilities (MFTECmd, PECmd, LECmd, LogFileParser). Each retains its own licence (see `LICENSE_*.md` files). |
| `OATFD_v1/README_OATFD_V1_THESIS.txt` | Detailed operational notes and version constants. |

---

## Output labels

| Label | Meaning |
|---|---|
| **Suspicious High** | High-confidence primary timestamp-manipulation verdict. |
| **Need Review** | Ambiguous or insufficiently corroborated; requires analyst review. |
| **High-Risk Non-Primary Artifact** | Non-primary system file with suspicious mutation pattern; flagged for analyst attention, distinct from primary-target verdicts. |
| **Normal** | Pattern is sufficiently explained by ordinary filesystem operation. |

---

## How to run

1. Extract the package to a short path, e.g. `C:\OATFD_V1\`.
2. Run `RUN_FILEPICKER_LFP_APP.bat` (recommended — includes $LogFile corroboration).
3. Select artifact files through the GUI.
4. Review results in the generated `OATFD_OUTPUT` folder.

Command-line (direct):
```
python OATFD_v1/oatfd_engine.py --case "Z:\Thesis\Case_E01" --all
python OATFD_v1/oatfd_engine.py --input "Z:\Thesis\Case_E01\INPUT_PYTHON" --detect-only --all-files
```

---

## Version constants

```
OATFD_VERSION        = "OATFD v1.0 Causal-Timeline Guard Thesis Edition"
SCORING_RULE_VERSION = "OATFD_v1_0_causal_timeline_guard"
```

---

## Evaluation dataset

The forensic disk image (E01) underlying the final evaluation is **not distributed** due to its size. MD5 and SHA1 checksums are reported in the thesis (Section 4.1) and the journal paper (Section 4.1) to support independent integrity verification.

---

## Contact

**Corresponding author:** Husnul Hafshah Devi — devii.hafshah@gmail.com  
ORCID: [0009-0007-7508-6629](https://orcid.org/0009-0007-7508-6629)  
Google Scholar: [jEY28OcAAAAJ](https://scholar.google.com/citations?user=jEY28OcAAAAJ)  
SINTA: [7023376](https://sinta.kemdiktisaintek.go.id/authors/profile/7023376)
