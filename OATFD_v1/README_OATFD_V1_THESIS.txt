OATFD v1.0 Thesis Edition
==========================

Purpose
-------
OATFD v1.0 is a single thesis-release build for NTFS artifact-based timestamp-manipulation analysis. The release label has been normalized to Version 1.0 so the package can be cited as one coherent thesis artifact rather than as an incremental revision chain.

Core capability
---------------
The system evaluates timestamp-manipulation indications by combining evidence from available NTFS-related artifacts, including MFT-derived metadata, USN Journal records, $LogFile transitions, Prefetch/LNK context, and $I30 directory-index evidence when available.

Methodological position
-----------------------
A timestamp anomaly is not automatically classified as manipulation. The engine applies causal-timeline reasoning to distinguish high-confidence post-creation metadata manipulation from normal lifecycle behavior such as file creation, writing, copy/backup timestamp inheritance, tunneling-like delete-create sequences, parser timezone representation differences, and context-only support artifacts.

Output interpretation
---------------------
- Suspicious High: final high-confidence primary timestamp-manipulation decision.
- Need Review: ambiguous or insufficiently corroborated candidate requiring analyst review.
- Behavior Alerts: contextual signals, not final timestamp-manipulation verdicts.
- Normal: observed artifact pattern is sufficiently explained by ordinary operation grammar.

Version constants
-----------------
OATFD_VERSION = OATFD v1.0 Causal-Timeline Guard Thesis Edition
SCORING_RULE_VERSION = OATFD_v1_0_causal_timeline_guard

Recommended thesis wording
--------------------------
"This thesis uses OATFD v1.0 Thesis Edition as the evaluated implementation. Version 1.0 denotes the consolidated thesis release, not a sequence of public software revisions."

How to run
----------
1. Extract the package into a short path, for example C:\OATFD_V1\.
2. Run RUN_FILEPICKER_LFP_APP.bat.
3. Select the relevant artifact files through the GUI.
4. Review outputs in the generated OATFD_OUTPUT folder.
