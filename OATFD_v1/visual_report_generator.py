
# -*- coding: utf-8 -*-
r'''
visual_report_generator.py

Membuat dashboard HTML visual dari output deteksi:
- suspicious_behavior_detection.csv
- timeline_events.csv
- case_reasoning.csv
- run_summary.csv
'''

from __future__ import annotations

import argparse
import csv
import html
from pathlib import Path


def ensure(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def read_rows(path: Path):
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append({str(k): ("" if v is None else str(v)) for k, v in row.items()})
    return rows


def esc(x):
    return html.escape("" if x is None else str(x))


def short(x, n=170):
    x = "" if x is None else str(x)
    return x if len(x) <= n else x[:n] + "..."


def to_int(x, default=0):
    try:
        return int(float(str(x).strip()))
    except Exception:
        return default


def badge(label, ok):
    return f'<span class="badge {"ok" if ok else "no"}">{label}</span>'


def generate(case: Path) -> bool:
    out_dir = case / "MINI_NLT_OUTPUT"
    ensure(out_dir)

    files = {
        "suspicious": out_dir / "suspicious_behavior_detection.csv",
        "timeline": out_dir / "timeline_events.csv",
        "reasoning": out_dir / "case_reasoning.csv",
        "summary": out_dir / "run_summary.csv",
        "matrix": out_dir / "detection_matrix.csv",
        "all_file": out_dir / "all_file_classification.csv",
        "behavior_alerts": out_dir / "behavior_alerts.csv",
        "system_time_anomalies": out_dir / "system_time_anomalies.csv",
        "document_deletion_alerts": out_dir / "document_deletion_alerts.csv",
    }

    required_keys = ["timeline", "reasoning", "summary"]
    missing = [str(files[k]) for k in required_keys if not files[k].exists()]
    if missing:
        print("[ERROR] Detection output files are incomplete for the visual report:", flush=True)
        for m in missing:
            print("  - " + m, flush=True)
        print("Run Detect + Timeline first.", flush=True)
        return False

    suspicious = read_rows(files["suspicious"]) if files["suspicious"].exists() else []
    timeline = read_rows(files["timeline"])
    reasoning = read_rows(files["reasoning"])
    summary_rows = read_rows(files["summary"])
    matrix = read_rows(files["matrix"]) if files["matrix"].exists() else []
    all_file = read_rows(files["all_file"]) if files.get("all_file") and files["all_file"].exists() else []
    behavior_alerts = read_rows(files["behavior_alerts"]) if files.get("behavior_alerts") and files["behavior_alerts"].exists() else []
    system_time_anomalies = read_rows(files["system_time_anomalies"]) if files.get("system_time_anomalies") and files["system_time_anomalies"].exists() else []
    document_deletion_alerts = read_rows(files["document_deletion_alerts"]) if files.get("document_deletion_alerts") and files["document_deletion_alerts"].exists() else []
    if not all_file and matrix:
        all_file = []
        for r in matrix:
            all_file.append({
                "TargetName": r.get("target_name", r.get("TargetName", "")),
                "RelativePath": r.get("relative_path", r.get("RelativePath", "")),
                "Extension": r.get("extension", r.get("Extension", "")),
                "Prediction": r.get("prediction", r.get("Prediction", "")),
                "PredictionType": r.get("prediction_type", r.get("PredictionType", "")),
                "Score": r.get("score", r.get("Score", "")),
                "EvidenceBasis": r.get("evidence_basis", r.get("EvidenceBasis", "")),
                "FilenameBiasUsed": r.get("filename_bias_used", r.get("FilenameBiasUsed", "False")),
                "FolderLabelUsed": r.get("folder_label_used", r.get("FolderLabelUsed", "False")),
                "GroundTruthUsedForDetection": r.get("ground_truth_used_for_detection", r.get("GroundTruthUsedForDetection", "False")),
            })

    # Fallback penting: jika suspicious_behavior_detection.csv kosong/baru header,
    # bangun ulang daftar suspicious dari detection_matrix.csv.
    if not suspicious and matrix:
        rebuilt = []
        for r in matrix:
            pred = r.get("prediction", r.get("Prediction", ""))
            if pred and str(pred) == "Suspicious High":
                rebuilt.append({
                    "TargetName": r.get("target_name", r.get("TargetName", "")),
                    "Prediction": pred,
                    "PredictionType": r.get("prediction_type", r.get("PredictionType", "")),
                    "Score": r.get("score", r.get("Score", "0")),
                    "Evidence": r.get("reasons", r.get("Evidence", "")),
                    "USN_Support": "Yes" if r.get("usn_has_basic_info_change", "") == "Yes" else "No",
                    "LogFile_Support": "Yes" if r.get("logfile_event_count", "0") not in ("", "0", 0) else "No",
                    "LNK_Windows_Hits": r.get("lnk_windows_hit_count", "0"),
                    "LNK_Office_Hits": r.get("lnk_office_hit_count", "0"),
                    "PrefetchBestCandidate": r.get("prefetch_best_candidate", ""),
                    "LSNTransitionCandidate": r.get("lsn_transition_candidate", ""),
                    "LSNTransitionStrength": r.get("lsn_transition_strength", ""),
                    "LSNTransitionReasons": r.get("lsn_transition_reasons", ""),
                    "MFT_Record_LSN": r.get("mft_lsn", ""),
                    "LogFile_LSN_Values": r.get("logfile_lsn_values", ""),
                    "LSNExactMatch": r.get("lsn_exact_match", ""),
                    "LSNNearMatch": r.get("lsn_near_match", ""),
                    "LowLevelCandidate": r.get("lowlevel_timestamp_mutation_candidate", ""),
                    "LowLevelStrength": r.get("lowlevel_strength", ""),
                    "LowLevelReasons": r.get("lowlevel_reasons", ""),
                    "LowLevelFutureTimestamp": r.get("lowlevel_future_timestamp", ""),
                    "LowLevelSIFNDelta": r.get("lowlevel_si_fn_delta_large", ""),
                    "LowLevelSIFNDeltaPairs": r.get("lowlevel_si_fn_delta_pairs", ""),
                    "LowLevelSIFNDeltaNonAccess": r.get("lowlevel_si_fn_delta_non_access", ""),
                    "LowLevelSIFNAccessedOnly": r.get("lowlevel_si_fn_accessed_only", ""),
                    "LowLevelMetadataOnlyGrammar": r.get("lowlevel_metadata_only_grammar", ""),
                    "MutationCore": r.get("mutation_core", ""),
                    "NormalCreationGuard": r.get("normal_creation_guard", ""),
                    "ScoringRuleVersion": r.get("scoring_rule_version", ""),
                    "LowLevelFractionPattern": r.get("lowlevel_fraction_pattern", ""),
                })
        suspicious = rebuilt
        print(f"[VISUAL] suspicious_behavior_detection.csv is empty; rebuilding from detection_matrix: {len(suspicious)} rows", flush=True)

    summary_dict = {}
    for r in summary_rows:
        if "field" in r and "value" in r:
            summary_dict[str(r["field"])] = str(r["value"])

    target_count = to_int(summary_dict.get("target_count", len(reasoning)), len(reasoning))
    suspicious_count = to_int(summary_dict.get("manipulation_count", summary_dict.get("suspicious_count", len(suspicious))), len(suspicious))
    high_risk_non_primary_count = sum(1 for r in all_file if str(r.get("Prediction", r.get("prediction", ""))).startswith("High-Risk"))
    normal_count = to_int(summary_dict.get("normal_count", max(0, target_count - suspicious_count - high_risk_non_primary_count)), max(0, target_count - suspicious_count - high_risk_non_primary_count))
    need_review_count = to_int(summary_dict.get("need_review_count", 0), 0)
    behavior_alert_count = to_int(summary_dict.get("behavior_alert_count", len(behavior_alerts)), len(behavior_alerts))
    system_time_anomaly_count = to_int(summary_dict.get("system_time_anomaly_count", len(system_time_anomalies)), len(system_time_anomalies))
    document_deletion_alert_count = to_int(summary_dict.get("document_deletion_alert_count", len(document_deletion_alerts)), len(document_deletion_alerts))
    excluded_count = to_int(summary_dict.get("excluded_count", 0), 0)
    unique_total = to_int(summary_dict.get("unique_logical_total", 0), 0)
    unique_high = to_int(summary_dict.get("unique_high_confidence_logical", summary_dict.get("unique_high_confidence_target_names", 0)), 0)

    official_status = summary_dict.get("official_detection_status", "")
    artifact_mode = summary_dict.get("artifact_mode", "")
    if str(official_status).upper() == "FULL_ENGINE_FAILED" or "fallback" in str(artifact_mode).lower():
        dashboard_note = (
            '<b>WARNING:</b> The full MFT-centered cross-artifact engine did not produce an official detection result. '
            'This dashboard only shows diagnostic status; fallback context reports are available in fallback_detection_matrix.csv, '
            'fallback_tool_context.csv, and fallback_need_review.csv. Do not count fallback results as final Primary Manipulation.'
        )
    else:
        dashboard_note = (
            '<b>Detection classification explanation:</b> '
            '<b>Primary Manipulation</b> indicates files supported by strong, linked evidence from core artifacts such as MFT/SI-FN, USN, $LogFile/LSN, and the causal timeline; this category is counted as the primary manipulation result. '
            '<b>High-Risk Non-Primary</b> indicates high-risk anomalies in supporting artifacts such as tool traces, Prefetch, LNK, $I30, or behavior rows, but these are not yet sufficient as final evidence without linkage to the target file. '
            '<b>Need Review</b> refers to ambiguous cases that show partial indicators but do not yet meet the threshold to be classified as manipulation or normal. '
            '<b>Behavior Alerts</b> are contextual warnings, such as system time anomalies or file deletions, that assist the investigation but are not automatically counted as manipulation. '
            '<b>Normal</b> refers to files that are consistent with legitimate activity or protected by a true-negative guard. '
            '<b>Manipulation ratio</b> is calculated from Primary Manipulation divided by the total logical files examined; Need Review and contextual alerts are not automatically counted as FP/FN.'
        )

    suspicious_pct = (suspicious_count / target_count * 100) if target_count else 0
    suspicious_degrees = (suspicious_count / target_count * 360) if target_count else 0

    suspicious_sorted = sorted(
        suspicious,
        key=lambda r: (-to_int(r.get("Score", r.get("score", 0))), str(r.get("TargetName", r.get("target_name", ""))))
    )

    score_rows = []
    for r in suspicious_sorted:
        score_rows.append({
            "file": r.get("TargetName", r.get("target_name", "")),
            "score": to_int(r.get("Score", r.get("score", 0))),
            "type": r.get("PredictionType", r.get("prediction_type", "")),
            "usn": r.get("USN_Support", r.get("usn_support", "")),
            "log": r.get("LogFile_Support", r.get("logfile_support", "")),
            "lnkw": to_int(r.get("LNK_Windows_Hits", r.get("lnk_windows_hits", 0))),
            "lnko": to_int(r.get("LNK_Office_Hits", r.get("lnk_office_hits", 0))),
            "prefetch": r.get("PrefetchBestCandidate", r.get("prefetch_best_candidate", "")),
            "evidence": r.get("Evidence", r.get("evidence", "")),
            "lsn_transition": r.get("LSNTransitionCandidate", r.get("lsn_transition_candidate", "")),
            "lsn_strength": r.get("LSNTransitionStrength", r.get("lsn_transition_strength", "")),
            "lsn_reasons": r.get("LSNTransitionReasons", r.get("lsn_transition_reasons", "")),
            "mft_lsn": r.get("MFT_Record_LSN", r.get("mft_lsn", "")),
            "log_lsn_values": r.get("LogFile_LSN_Values", r.get("logfile_lsn_values", "")),
            "lsn_exact": r.get("LSNExactMatch", r.get("lsn_exact_match", "")),
            "lsn_near": r.get("LSNNearMatch", r.get("lsn_near_match", "")),
            "lowlevel": r.get("LowLevelCandidate", r.get("lowlevel_timestamp_mutation_candidate", "")),
            "lowlevel_strength": r.get("LowLevelStrength", r.get("lowlevel_strength", "")),
            "lowlevel_reasons": r.get("LowLevelReasons", r.get("lowlevel_reasons", "")),
            "lowlevel_future": r.get("LowLevelFutureTimestamp", r.get("lowlevel_future_timestamp", "")),
            "lowlevel_future_fields": r.get("LowLevelFutureFields", r.get("lowlevel_future_fields", "")),
            "lowlevel_sifn": r.get("LowLevelSIFNDelta", r.get("lowlevel_si_fn_delta_large", "")),
            "lowlevel_sifn_pairs": r.get("LowLevelSIFNDeltaPairs", r.get("lowlevel_si_fn_delta_pairs", "")),
            "lowlevel_sifn_non_access": r.get("LowLevelSIFNDeltaNonAccess", r.get("lowlevel_si_fn_delta_non_access", "")),
            "lowlevel_sifn_accessed_only": r.get("LowLevelSIFNAccessedOnly", r.get("lowlevel_si_fn_accessed_only", "")),
            "lowlevel_metaonly": r.get("LowLevelMetadataOnlyGrammar", r.get("lowlevel_metadata_only_grammar", "")),
            "lowlevel_fraction": r.get("LowLevelFractionPattern", r.get("lowlevel_fraction_pattern", "")),
            "mutation_core": r.get("mutation_core", r.get("MutationCore", "")),
            "normal_creation_guard": r.get("normal_creation_guard", r.get("NormalCreationGuard", "")),
            "scoring_rule_version": r.get("scoring_rule_version", r.get("ScoringRuleVersion", "")),
        })

    # v1.0: Large USN-only benchmarks may contain thousands of candidates.
    # Keep CSV outputs complete, but cap the HTML dashboard to avoid browser/app freezes.
    full_score_rows = list(score_rows)
    html_cap = 500
    score_rows = score_rows[:html_cap]
    if len(full_score_rows) > html_cap:
        print(f"[VISUAL] Large suspicious list capped in HTML: showing top {html_cap} of {len(full_score_rows)}. Full list remains in suspicious_behavior_detection.csv and visual_summary_table.csv.", flush=True)

    max_score = max([r["score"] for r in score_rows] + [1])
    suspicious_names = {str(r["file"]) for r in score_rows}

    summary_csv = out_dir / "visual_summary_table.csv"
    with summary_csv.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["file", "score", "type", "usn", "log", "lnkw", "lnko", "prefetch",
                  "lsn_transition", "lsn_strength", "lsn_reasons", "mft_lsn", "log_lsn_values", "lsn_exact", "lsn_near",
                  "lowlevel", "lowlevel_strength", "lowlevel_reasons", "lowlevel_future",
                  "lowlevel_sifn", "lowlevel_sifn_non_access", "lowlevel_sifn_accessed_only", "lowlevel_metaonly", "mutation_core", "normal_creation_guard", "scoring_rule_version", "evidence"]
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(full_score_rows)

    bars = ""
    for r in score_rows:
        width = max(5, r["score"] / max_score * 100)
        bars += f'''
        <div class="bar-row">
          <div class="bar-label" title="{esc(r['file'])}">{esc(r['file'])}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%"></div></div>
          <div class="bar-score">{r['score']}</div>
        </div>
        '''

    evidence_rows = ""
    for r in score_rows:
        evidence_rows += f'''
        <tr>
          <td class="file">{esc(r['file'])}</td>
          <td>{esc(r['type'])}</td>
          <td><b>{r['score']}</b></td>
          <td>
            {badge('LSN', r.get('lsn_transition', '').lower() == 'yes')}
            {badge('LowLevel', r.get('lowlevel', '').lower() == 'yes')}
            {badge('USN', r['usn'].lower() == 'yes')}
            {badge('LogFile', r['log'].lower() == 'yes')}
            {badge('LNK-W', r['lnkw'] > 0)}
            {badge('LNK-O', r['lnko'] > 0)}
            {badge('MutationCore', str(r.get('mutation_core','')).lower() == 'yes')}
            {badge('Guard', str(r.get('normal_creation_guard','')).lower() == 'yes')}
          </td>
          <td>{esc(r['prefetch'])}</td>
        </tr>
        '''



    lsn_rows_html = ""
    for r in score_rows:
        if str(r.get("lsn_transition", "")).lower() == "yes" or r.get("mft_lsn") or r.get("log_lsn_values"):
            lsn_rows_html += f"""
            <tr>
              <td class="file">{esc(r['file'])}</td>
              <td><b>{esc(r.get('lsn_strength', ''))}</b></td>
              <td>{badge('Exact', str(r.get('lsn_exact','')).lower() == 'yes')} {badge('Near', str(r.get('lsn_near','')).lower() == 'yes')}</td>
              <td>{esc(r.get('mft_lsn', ''))}</td>
              <td>{esc(short(r.get('log_lsn_values', ''), 180))}</td>
              <td>{esc(r.get('lsn_reasons', ''))}</td>
            </tr>
            """
    if not lsn_rows_html:
        lsn_rows_html = '<tr><td colspan="6">No LSN-linked transition candidates were found in the suspicious results.</td></tr>'


    lowlevel_rows_html = ""
    for r in score_rows:
        if str(r.get("lowlevel", "")).lower() == "yes" or r.get("lowlevel_reasons") or r.get("lowlevel_sifn_pairs") or r.get("lowlevel_future_fields"):
            lowlevel_rows_html += f"""
            <tr>
              <td class="file">{esc(r['file'])}</td>
              <td><b>{esc(r.get('lowlevel_strength', ''))}</b></td>
              <td>{esc(r.get('lowlevel_reasons', ''))}</td>
              <td>{esc(r.get('lowlevel_sifn_pairs', ''))}</td>
              <td>{esc(r.get('lowlevel_future_fields', ''))}</td>
              <td>{esc(r.get('lowlevel_fraction', ''))}</td>
            </tr>
            """

    if not lowlevel_rows_html:
        lowlevel_rows_html = '<tr><td colspan="6">No low-level mutation candidates were found in the suspicious results.</td></tr>'


    tl_by_name = {}
    for r in timeline:
        name = str(r.get("TargetName", r.get("target_name", "")))
        if name in suspicious_names:
            tl_by_name.setdefault(name, []).append(r)

    timeline_html = ""
    for name in sorted(tl_by_name)[:250]:
        events = tl_by_name[name]
        events.sort(key=lambda r: str(r.get("Time", r.get("time", ""))))
        items = ""
        for ev in events:
            items += f'''
            <div class="tl-item">
              <div class="tl-dot"></div>
              <div class="tl-content">
                <div class="tl-time">{esc(ev.get('Time', ev.get('time', '')))}</div>
                <div class="tl-event">{esc(ev.get('Event', ev.get('event', '')))}</div>
                <div class="tl-detail">{esc(short(ev.get('Detail', ev.get('detail', '')), 190))}</div>
              </div>
            </div>
            '''
        timeline_html += f'''
        <details class="timeline-card" open>
          <summary>{esc(name)}</summary>
          <div class="tl-list">{items}</div>
        </details>
        '''

    suspicious_reason = []
    for r in reasoning:
        name = str(r.get("target_name", r.get("TargetName", "")))
        if name in suspicious_names:
            suspicious_reason.append(r)

    suspicious_reason.sort(key=lambda r: (-to_int(r.get("score", r.get("Score", 0))), str(r.get("target_name", r.get("TargetName", "")))))
    reason_html = ""
    for r in suspicious_reason[:500]:
        name = r.get("target_name", r.get("TargetName", ""))
        score = r.get("score", r.get("Score", ""))
        pred = r.get("prediction", r.get("Prediction", ""))
        ptype = r.get("prediction_type", r.get("PredictionType", ""))
        reason = r.get("reasoning", r.get("Reasoning", ""))
        key_rel = r.get("key_relative", "")
        key_mft = r.get("key_mft", "")
        key_pf = r.get("key_prefetch", "")
        key_lsn = r.get("key_lsn", "")
        key_i30 = r.get("key_i30", "")
        reason_html += f'''
        <article class="reason-card">
          <h3>{esc(name)}</h3>
          <p><b>{esc(pred)}</b> · {esc(ptype)} · Score {esc(score)}</p>
          <p>{esc(reason)}</p>
          <details>
            <summary>Artifact details</summary>
            <pre>{esc(key_rel)}\n{esc(key_mft)}\n{esc(key_lsn)}\n{esc(key_pf)}</pre>
          </details>
        </article>
        '''


    def render_all_file_table(rows, title, limit=180):
        body = []
        for r in rows[:limit]:
            pred = r.get("Prediction", r.get("prediction", ""))
            score = r.get("Score", r.get("score", ""))
            target = r.get("TargetName", r.get("target_name", ""))
            rel = r.get("RelativePath", r.get("relative_path", ""))
            ptype = r.get("PredictionType", r.get("prediction_type", ""))
            eb = r.get("EvidenceBasis", r.get("evidence_basis", ""))
            fb = r.get("FilenameBiasUsed", r.get("filename_bias_used", "False"))
            flb = r.get("FolderLabelUsed", r.get("folder_label_used", "False"))
            gtb = r.get("GroundTruthUsedForDetection", r.get("ground_truth_used_for_detection", "False"))
            body.append(f"""
              <tr>
                <td class=\"file\">{esc(target)}</td>
                <td>{esc(short(rel, 105))}</td>
                <td>{esc(pred)}</td>
                <td>{esc(score)}</td>
                <td>{esc(short(ptype, 90))}</td>
                <td>{esc(short(eb, 120))}</td>
                <td>{esc(fb)}/{esc(flb)}/{esc(gtb)}</td>
              </tr>
            """)
        if not body:
            body.append('<tr><td colspan="7">No data available.</td></tr>')
        more = ""
        if len(rows) > limit:
            more = f'<p style="color:var(--muted);font-size:12px">Showing {limit} of {len(rows)} rows. The complete file is available in all_file_classification.csv.</p>'
        return f"""
        <section class=\"panel\"><h2>{esc(title)}</h2>{more}
          <table><thead><tr><th>Target</th><th>Path</th><th>Prediction</th><th>Score</th><th>Type</th><th>Evidence Basis</th><th>Bias Audit F/F/G</th></tr></thead><tbody>{''.join(body)}</tbody></table>
        </section>
        """

    all_file_sorted = sorted(all_file, key=lambda r: (
        0 if str(r.get("Prediction", r.get("prediction", ""))) == "Suspicious High" else (1 if str(r.get("Prediction", r.get("prediction", ""))).startswith("High-Risk") else (2 if str(r.get("Prediction", r.get("prediction", ""))) == "Need Review" else 3)),
        str(r.get("RelativePath", r.get("relative_path", ""))).lower(),
        str(r.get("TargetName", r.get("target_name", ""))).lower()
    ))
    high_risk_non_primary_rows = [r for r in all_file if str(r.get("Prediction", r.get("prediction", ""))).startswith("High-Risk")]
    need_review_rows = [r for r in all_file if str(r.get("Prediction", r.get("prediction", ""))) == "Need Review"]
    def render_behavior_alert_rows(rows):
        if not rows:
            return '<tr><td colspan="7">No behavior alerts.</td></tr>'
        out=[]
        for r in rows[:120]:
            out.append(f"<tr><td>{esc(r.get('alert_type',''))}</td><td><b>{esc(r.get('severity',''))}</b></td><td>{esc(r.get('current_time', r.get('time','')))}</td><td>{esc(r.get('previous_time',''))}</td><td class='file'>{esc(r.get('current_file', r.get('file_name','')))}</td><td>{esc(short(r.get('current_reason', r.get('reason','')), 120))}</td><td>{esc(short(r.get('note',''), 180))}</td></tr>")
        return ''.join(out)
    behavior_rows = render_behavior_alert_rows(behavior_alerts)
    normal_rows = [r for r in all_file if str(r.get("Prediction", r.get("prediction", ""))) == "Normal"]

    html_doc = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NTFS Timestamp Detection Dashboard</title>
<style>
:root {{
  --bg:#f5f7fb; --panel:#fff; --text:#1f2937; --muted:#6b7280; --line:#e5e7eb;
  --danger:#b91c1c; --ok:#047857; --blue:#1d4ed8; --shadow:0 10px 25px rgba(15,23,42,.08);
}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:"Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--text)}}
header{{padding:28px 34px;background:linear-gradient(135deg,#0f172a,#1e3a8a);color:white}}
header h1{{margin:0 0 8px;font-size:28px}} header p{{margin:0;opacity:.88}}
main{{padding:26px 34px 50px;max-width:1360px;margin:auto}}
.grid{{display:grid;gap:18px}} .cards{{grid-template-columns:repeat(5,minmax(170px,1fr));margin-bottom:20px}}
.card,.panel,.reason-card,.timeline-card{{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow)}}
.card{{padding:20px}} .card .label{{color:var(--muted);font-size:13px;margin-bottom:8px}} .card .value{{font-size:32px;font-weight:800}} .card .note{{color:var(--muted);font-size:12px;margin-top:8px}}
.panel{{padding:22px;margin-bottom:20px}} .panel h2{{margin:0 0 16px;font-size:20px}}
.two{{grid-template-columns:1.1fr .9fr}}
.warning{{background:#fffbeb;border:1px solid #fde68a;color:#92400e;padding:14px 16px;border-radius:16px;margin-bottom:20px}}
.donut-wrap{{display:flex;gap:24px;align-items:center}}
.donut{{width:170px;height:170px;border-radius:50%;background:conic-gradient(var(--danger) 0deg {suspicious_degrees:.2f}deg,#e5e7eb {suspicious_degrees:.2f}deg 360deg);display:grid;place-items:center}}
.donut::after{{content:"{suspicious_count}/{target_count}";width:104px;height:104px;border-radius:50%;background:white;display:grid;place-items:center;font-weight:800;font-size:22px;box-shadow:inset 0 0 0 1px var(--line)}}
.legend div{{margin:8px 0}} .dot{{display:inline-block;width:12px;height:12px;border-radius:4px;margin-right:8px;vertical-align:-1px}} .red{{background:var(--danger)}} .gray{{background:#cbd5e1}}
.bar-row{{display:grid;grid-template-columns:210px 1fr 42px;gap:12px;align-items:center;margin:12px 0}}
.bar-label{{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bar-track{{height:16px;background:#e5e7eb;border-radius:999px;overflow:hidden}} .bar-fill{{height:100%;background:linear-gradient(90deg,#f97316,#b91c1c);border-radius:999px}} .bar-score{{font-weight:800;text-align:right}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{border-bottom:1px solid var(--line);padding:10px 8px;text-align:left;vertical-align:top}} th{{color:var(--muted);font-weight:700;background:#f8fafc}} td.file{{font-weight:700}}
.badge{{display:inline-block;padding:4px 7px;border-radius:999px;font-size:11px;font-weight:700;margin:2px}} .badge.ok{{background:#dcfce7;color:var(--ok)}} .badge.no{{background:#f1f5f9;color:#64748b}}
.timeline-card{{padding:0;margin-bottom:12px;overflow:hidden}} .timeline-card summary{{cursor:pointer;padding:14px 18px;font-weight:800;background:#f8fafc}} .tl-list{{padding:8px 18px 18px}}
.tl-item{{display:grid;grid-template-columns:18px 1fr;gap:10px;position:relative}} .tl-item:not(:last-child)::before{{content:"";position:absolute;left:7px;top:18px;bottom:-2px;width:2px;background:#e5e7eb}}
.tl-dot{{width:14px;height:14px;border-radius:50%;background:var(--blue);margin-top:6px;z-index:1}} .tl-content{{padding-bottom:12px}} .tl-time{{font-weight:700;color:var(--blue);font-size:12px}} .tl-event{{font-weight:700}} .tl-detail{{color:var(--muted);font-size:12px;margin-top:3px}}
.reason-grid{{grid-template-columns:repeat(2,minmax(250px,1fr))}} .reason-card{{padding:18px}} .reason-card h3{{margin:0 0 8px}} .reason-card p{{margin:8px 0;font-size:13px}} pre{{white-space:pre-wrap;background:#f8fafc;border:1px solid var(--line);padding:12px;border-radius:12px;font-size:12px;color:#334155}}
@media(max-width:980px){{.cards,.two,.reason-grid{{grid-template-columns:1fr}}.bar-row{{grid-template-columns:1fr;gap:5px}}}}
</style>
</head>
<body>
<header>
  <h1>NTFS Timestamp Detection Dashboard</h1>
  <p>Visualization of timestamp manipulation detection results based on MFT, USN, $LogFile, Prefetch, LNK, and $I30.</p>
</header>
<main>
  <section class="grid cards">
    <div class="card"><div class="label">Total rows examined</div><div class="value">{target_count}</div><div class="note">Unique logical: {unique_total if unique_total else 'n/a'}.</div></div>
    <div class="card"><div class="label">Primary Manipulation</div><div class="value" style="color:var(--danger)">{suspicious_count}</div><div class="note">High-confidence primary file rows. Unique: {unique_high if unique_high else 'n/a'}.</div></div>
    <div class="card"><div class="label">High-Risk Non-Primary</div><div class="value" style="color:#b45309">{high_risk_non_primary_count}</div><div class="note">Role-aware artifact anomalies.</div></div>
    <div class="card"><div class="label">Need Review</div><div class="value" style="color:#b45309">{need_review_count}</div><div class="note">Ambiguous; not counted as FP/FN.</div></div>
    <div class="card"><div class="label">Behavior Alerts</div><div class="value" style="color:#1d4ed8">{behavior_alert_count}</div><div class="note">System time: {system_time_anomaly_count} · deletion: {document_deletion_alert_count}</div></div>
    <div class="card"><div class="label">Normal</div><div class="value" style="color:var(--ok)">{normal_count}</div><div class="note">Explained by normal activity.</div></div>
    <div class="card"><div class="label">Manipulation ratio</div><div class="value">{suspicious_pct:.1f}%</div><div class="note">Excluded: {excluded_count}</div></div>
  </section>

  <div class="warning">{dashboard_note}</div>

  <section class="grid two">
    <div class="panel"><h2>Prediction Distribution</h2><div class="donut-wrap"><div class="donut"></div><div class="legend">
      <div><span class="dot red"></span>Primary Manipulation: <b>{suspicious_count}</b></div>
      <div><span class="dot" style="background:#b45309"></span>High-Risk Non-Primary: <b>{high_risk_non_primary_count}</b></div>
      <div><span class="dot gray"></span>Normal: <b>{normal_count}</b></div>
      <div style="color:var(--muted);margin-top:12px;">Relative threshold: {esc(summary_dict.get("relative_threshold_days","180"))} days · Prefetch window: {esc(summary_dict.get("prefetch_window_minutes","30"))} minutes</div>
    </div></div></div>
    <div class="panel"><h2>High-Confidence Suspicious Score</h2>{bars}</div>
  </section>

  <section class="panel"><h2>Evidence Matrix</h2><table><thead><tr><th>Target</th><th>Type</th><th>Score</th><th>Supporting Artifacts</th><th>Best Prefetch Candidate</th></tr></thead><tbody>{evidence_rows}</tbody></table></section>
  <section class="panel"><h2>LSN-Linked Transition Evidence</h2>
    <table>
      <thead>
        <tr>
          <th>Target</th>
          <th>Strength</th>
          <th>Match</th>
          <th>MFT Record LSN</th>
          <th>LogFile LSN Values</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>{lsn_rows_html}</tbody>
    </table>
  </section>
  <section class="panel"><h2>Low-Level Mutation Evidence</h2>
    <table>
      <thead>
        <tr>
          <th>Target</th>
          <th>Strength</th>
          <th>Low-Level Reason</th>
          <th>SI/FN Delta</th>
          <th>Future Fields</th>
          <th>Fraction Pattern</th>
        </tr>
      </thead>
      <tbody>{lowlevel_rows_html}</tbody>
    </table>
  </section>
  {render_all_file_table(all_file_sorted, "All Files Analyzed (Full-Scope Detection)", 220)}

  <section class="panel"><h2>Behavior Alerts / System-Level Context</h2>
    <p style="color:var(--muted);font-size:12px">These alerts are not counted as Primary Manipulation. Use them as investigative context.</p>
    <table><thead><tr><th>Type</th><th>Severity</th><th>Time / Current</th><th>Previous</th><th>Target/File</th><th>Reason</th><th>Note</th></tr></thead><tbody>{behavior_rows}</tbody></table>
  </section>

  {render_all_file_table(high_risk_non_primary_rows, "High-Risk Non-Primary Artifact Anomalies", 120)}
  {render_all_file_table(need_review_rows, "Need Review / Context-Guarded Candidates", 120)}
  {render_all_file_table(normal_rows, "Normal / Context-Explained Files", 120)}

  <section class="panel"><h2>Timeline of Suspicious Files</h2>{timeline_html}</section>
  <section class="panel"><h2>Reasoning per File</h2><div class="grid reason-grid">{reason_html}</div></section>
</main>
</body>
</html>'''

    html_path = out_dir / "visual_dashboard.html"
    html_path.write_text(html_doc, encoding="utf-8")
    print(f"[VISUAL] HTML report created: {html_path}", flush=True)
    print(f"[VISUAL] Summary CSV created: {summary_csv}", flush=True)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    args = ap.parse_args()
    return 0 if generate(Path(args.case)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
