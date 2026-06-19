
# -*- coding: utf-8 -*-
r'''
visual_report_generator.py

Generates a human-friendly HTML report from OATFD detection output:
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
    out_dir = case / "OATFD_OUTPUT"
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

    suspicious_pct = (suspicious_count / target_count * 100) if target_count else 0
    suspicious_degrees = (suspicious_count / target_count * 360) if target_count else 0

    # Plain-English summary box and explanation note for non-forensic readers
    if str(official_status).upper() == "FULL_ENGINE_FAILED" or "fallback" in str(artifact_mode).lower():
        plain_summary = (
            "<strong>Warning:</strong> The full analysis engine could not run completely &mdash; results below are "
            "based on limited available data. Do not treat these findings as a final verdict. A fallback report is "
            "available in the output folder."
        )
        info_box_cls = "warn-box"
        explanation_note = (
            "<b>Why did this happen?</b> The full detection engine requires MFT data as its primary artifact. "
            "When MFT is missing, a reduced analysis runs on whatever artifacts are available. "
            "The findings below may be incomplete."
        )
    else:
        if suspicious_count == 0:
            plain_summary = (
                f"<strong>No tampering detected</strong> &mdash; all {target_count} file(s) examined appear "
                f"consistent with normal activity. No file shows strong evidence of deliberate timestamp manipulation."
            )
        elif suspicious_count == 1:
            plain_summary = (
                f"<strong>1 file</strong> out of <strong>{target_count}</strong> examined shows strong evidence "
                f"that its timestamps were deliberately altered. The file&rsquo;s recorded times do not match "
                f"what the underlying system logs show."
            )
        else:
            plain_summary = (
                f"<strong>{suspicious_count} files</strong> out of <strong>{target_count}</strong> examined "
                f"({suspicious_pct:.1f}%) show strong evidence of deliberate timestamp tampering. "
                f"These files have timestamps that contradict what the underlying system records show."
            )
        if need_review_count:
            plain_summary += (
                f" <strong>{need_review_count}</strong> additional file(s) show partial indicators "
                f"and need a closer look."
            )
        if behavior_alert_count:
            plain_summary += (
                f" {behavior_alert_count} system-level warning sign(s) were also detected "
                f"(see <em>Warning Signs</em> below)."
            )
        info_box_cls = "info-box"
        explanation_note = (
            "<b>How to read this report:</b> "
            "&ldquo;Likely Tampered&rdquo; means strong, cross-artifact evidence shows a file&rsquo;s timestamps "
            "were deliberately changed after the fact. "
            "&ldquo;Needs Closer Look&rdquo; means some suspicious signals exist but are not conclusive on their own. "
            "&ldquo;Warning Signs&rdquo; are system events &mdash; such as a system-clock change or file deletion &mdash; "
            "that provide investigative context but are not manipulation verdicts by themselves. "
            "The <em>Risk Score</em> is relative: higher means more evidence sources agree on tampering. "
            "This tool provides indicators for analyst review &mdash; it does not automatically prove intent."
        )

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
            {badge('Log Record', r.get('lsn_transition', '').lower() == 'yes')}
            {badge('Timestamp Irregular', r.get('lowlevel', '').lower() == 'yes')}
            {badge('Change Journal', r['usn'].lower() == 'yes')}
            {badge('System Log', r['log'].lower() == 'yes')}
            {badge('Windows Recent', r['lnkw'] > 0)}
            {badge('Office Recent', r['lnko'] > 0)}
            {badge('Core Evidence', str(r.get('mutation_core','')).lower() == 'yes')}
            {badge('FP Guard', str(r.get('normal_creation_guard','')).lower() == 'yes')}
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
              <td>{badge('Exact Match', str(r.get('lsn_exact','')).lower() == 'yes')} {badge('Near Match', str(r.get('lsn_near','')).lower() == 'yes')}</td>
              <td>{esc(r.get('mft_lsn', ''))}</td>
              <td>{esc(short(r.get('log_lsn_values', ''), 180))}</td>
              <td>{esc(r.get('lsn_reasons', ''))}</td>
            </tr>
            """
    if not lsn_rows_html:
        lsn_rows_html = '<tr><td colspan="6">No log record matches found for the suspicious files.</td></tr>'

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
        lowlevel_rows_html = '<tr><td colspan="6">No timestamp irregularities found in the suspicious files.</td></tr>'

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

        if "Suspicious" in str(pred):
            verdict_cls, verdict_label = "suspicious", "Likely Tampered"
        elif "Need Review" in str(pred):
            verdict_cls, verdict_label = "review", "Needs Closer Review"
        else:
            verdict_cls, verdict_label = "normal", "Appears Normal"

        reason_html += f'''
        <article class="reason-card">
          <h3>{esc(name)}</h3>
          <span class="verdict {verdict_cls}">{verdict_label}</span>
          <span class="score-chip">Score&nbsp;{esc(score)}</span>
          <p class="reason-text">{esc(reason)}</p>
          <details class="tech-details">
            <summary>&#9654; Technical artifact details</summary>
            <pre>{esc(key_rel)}\n{esc(key_mft)}\n{esc(key_lsn)}\n{esc(key_pf)}</pre>
          </details>
        </article>
        '''

    def _pred_label(pred):
        if str(pred) == "Suspicious High":
            return "Likely Tampered"
        if str(pred).startswith("High-Risk"):
            return "High-Risk Indicator"
        if str(pred) == "Need Review":
            return "Needs Review"
        return pred

    def render_all_file_table(rows, title, desc, limit=180):
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
                <td class="file">{esc(target)}</td>
                <td>{esc(short(rel, 105))}</td>
                <td>{esc(_pred_label(pred))}</td>
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
            more = f'<p class="table-note">Showing {limit} of {len(rows)} rows. Full data is in all_file_classification.csv.</p>'
        return f"""
        <section class="panel"><h2>{esc(title)}</h2><p class="section-desc">{esc(desc)}</p>{more}
          <table><thead><tr>
            <th>File Name</th><th>Location</th><th>Assessment</th><th>Risk Score</th>
            <th>Finding Type</th><th>Evidence</th><th>Bias Check</th>
          </tr></thead><tbody>{''.join(body)}</tbody></table>
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
            return '<tr><td colspan="7">No warning signs detected.</td></tr>'
        out = []
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
<title>OATFD Analysis Report</title>
<style>
:root {{
  --bg:#f0f4f8; --panel:#fff; --text:#1a202c; --muted:#718096; --line:#e2e8f0;
  --danger:#c53030; --warn:#c05621; --ok:#276749; --blue:#2b6cb0;
  --shadow:0 4px 20px rgba(0,0,0,.07);
}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:"Segoe UI",system-ui,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
header{{padding:30px 36px;background:linear-gradient(135deg,#1a365d,#2a69ac);color:white}}
header h1{{margin:0 0 6px;font-size:28px;letter-spacing:-.3px}} header .subtitle{{margin:0;opacity:.88;font-size:14px}}
main{{padding:28px 36px 60px;max-width:1380px;margin:auto}}
.what-found{{background:#fff7e6;border-left:5px solid #ed8936;padding:16px 22px;border-radius:0 14px 14px 0;margin:0 0 20px;font-size:15px;line-height:1.75}}
.info-box{{background:#ebf4ff;border:1px solid #bee3f8;color:#2b6cb0;padding:14px 18px;border-radius:12px;margin-bottom:20px;font-size:13px;line-height:1.65}}
.warn-box{{background:#fffbeb;border:1px solid #fde68a;color:#92400e;padding:14px 18px;border-radius:12px;margin-bottom:20px;font-size:13px;line-height:1.65}}
.grid{{display:grid;gap:16px}} .cards{{grid-template-columns:repeat(4,minmax(155px,1fr));margin-bottom:20px}}
.card,.panel,.reason-card,.timeline-card{{background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow)}}
.card{{padding:20px 22px}} .card .label{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}} .card .value{{font-size:34px;font-weight:800;line-height:1}} .card .note{{color:var(--muted);font-size:12px;margin-top:8px}}
.card.danger .value{{color:var(--danger)}} .card.warn .value{{color:var(--warn)}} .card.ok .value{{color:var(--ok)}} .card.blue .value{{color:var(--blue)}}
.panel{{padding:24px;margin-bottom:20px}} .panel h2{{margin:0 0 4px;font-size:20px}} .section-desc{{color:var(--muted);font-size:13px;margin:0 0 16px;line-height:1.6}}
.two{{grid-template-columns:1.1fr .9fr}}
.donut-wrap{{display:flex;gap:24px;align-items:center;flex-wrap:wrap}}
.donut{{width:160px;height:160px;border-radius:50%;background:conic-gradient(var(--danger) 0deg {suspicious_degrees:.2f}deg,#e2e8f0 {suspicious_degrees:.2f}deg 360deg);display:grid;place-items:center;flex-shrink:0}}
.donut::after{{content:"{suspicious_count}/{target_count}";width:100px;height:100px;border-radius:50%;background:white;display:grid;place-items:center;font-weight:800;font-size:20px;box-shadow:inset 0 0 0 1px var(--line)}}
.legend div{{margin:7px 0;font-size:13px}} .dot{{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:7px;vertical-align:-1px}}
.bar-row{{display:grid;grid-template-columns:220px 1fr 44px;gap:12px;align-items:center;margin:10px 0}}
.bar-label{{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bar-track{{height:14px;background:#e2e8f0;border-radius:999px;overflow:hidden}} .bar-fill{{height:100%;background:linear-gradient(90deg,#f6ad55,#c53030);border-radius:999px}} .bar-score{{font-weight:800;text-align:right}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{border-bottom:1px solid var(--line);padding:10px 8px;text-align:left;vertical-align:top}} th{{color:var(--muted);font-weight:700;background:#f7fafc;font-size:11px;text-transform:uppercase;letter-spacing:.4px}} td.file{{font-weight:700;color:#2d3748}}
.badge{{display:inline-flex;align-items:center;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:700;margin:2px}} .badge.ok{{background:#c6f6d5;color:var(--ok)}} .badge.no{{background:#f1f5f9;color:#94a3b8}}
.timeline-card{{padding:0;margin-bottom:12px;overflow:hidden}} .timeline-card summary{{cursor:pointer;padding:14px 20px;font-weight:700;background:#f7fafc;list-style:none}} .timeline-card summary::-webkit-details-marker{{display:none}}
.tl-list{{padding:10px 20px 20px}} .tl-item{{display:grid;grid-template-columns:14px 1fr;gap:12px;position:relative}} .tl-item:not(:last-child)::before{{content:"";position:absolute;left:6px;top:18px;bottom:-4px;width:2px;background:#e2e8f0}}
.tl-dot{{width:14px;height:14px;border-radius:50%;background:var(--blue);margin-top:5px;z-index:1}} .tl-content{{padding-bottom:14px}} .tl-time{{font-weight:700;color:var(--blue);font-size:12px}} .tl-event{{font-weight:700;font-size:13px}} .tl-detail{{color:var(--muted);font-size:12px;margin-top:2px}}
.reason-grid{{grid-template-columns:repeat(2,minmax(250px,1fr))}} .reason-card{{padding:20px}} .reason-card h3{{margin:0 0 10px;font-size:15px;color:#2d3748;word-break:break-word}}
.verdict{{display:inline-block;padding:3px 12px;border-radius:999px;font-size:12px;font-weight:700;margin-bottom:8px}}
.verdict.suspicious{{background:#fed7d7;color:var(--danger)}} .verdict.normal{{background:#c6f6d5;color:var(--ok)}} .verdict.review{{background:#fefcbf;color:#744210}}
.score-chip{{display:inline-block;background:#f7fafc;color:#4a5568;border:1px solid var(--line);border-radius:8px;padding:2px 10px;font-weight:700;font-size:12px;margin-left:6px;vertical-align:1px}}
.reason-text{{font-size:13px;color:#4a5568;margin:10px 0;line-height:1.75}}
.tech-details>summary{{font-size:12px;color:var(--muted);cursor:pointer;margin-top:8px;list-style:none;user-select:none}} .tech-details>summary::-webkit-details-marker{{display:none}}
pre{{white-space:pre-wrap;background:#f7fafc;border:1px solid var(--line);padding:12px;border-radius:10px;font-size:12px;color:#4a5568;margin:8px 0 0}}
.table-note{{color:var(--muted);font-size:12px;margin:0 0 10px}}
@media(max-width:980px){{.cards,.two,.reason-grid{{grid-template-columns:1fr}}.bar-row{{grid-template-columns:1fr;gap:4px}}}}
</style>
</head>
<body>
<header>
  <h1>OATFD Analysis Report</h1>
  <p class="subtitle">Timestamp Forensics &mdash; NTFS Artifact Detection &middot; Thesis Edition v1.0</p>
</header>
<main>

  <div class="what-found">{plain_summary}</div>

  <section class="grid cards">
    <div class="card"><div class="label">Files Examined</div><div class="value">{target_count}</div><div class="note">Unique: {unique_total if unique_total else "n/a"}</div></div>
    <div class="card danger"><div class="label">Likely Tampered</div><div class="value">{suspicious_count}</div><div class="note">Unique files: {unique_high if unique_high else "n/a"}</div></div>
    <div class="card warn"><div class="label">High-Risk Indicators</div><div class="value">{high_risk_non_primary_count}</div><div class="note">Supporting artifact anomalies</div></div>
    <div class="card warn"><div class="label">Needs Closer Look</div><div class="value">{need_review_count}</div><div class="note">Partial signals, not conclusive</div></div>
    <div class="card blue"><div class="label">Warning Signs</div><div class="value">{behavior_alert_count}</div><div class="note">System time: {system_time_anomaly_count} &middot; deletions: {document_deletion_alert_count}</div></div>
    <div class="card ok"><div class="label">No Tampering Found</div><div class="value">{normal_count}</div><div class="note">Consistent with normal activity</div></div>
    <div class="card"><div class="label">Tampering Rate</div><div class="value">{suspicious_pct:.1f}%</div><div class="note">Excluded from analysis: {excluded_count}</div></div>
  </section>

  <div class="{info_box_cls}">{explanation_note}</div>

  <section class="grid two">
    <div class="panel">
      <h2>Analysis Summary</h2>
      <p class="section-desc">How the examined files were classified overall.</p>
      <div class="donut-wrap">
        <div class="donut"></div>
        <div class="legend">
          <div><span class="dot" style="background:var(--danger)"></span>Likely Tampered: <b>{suspicious_count}</b></div>
          <div><span class="dot" style="background:var(--warn)"></span>High-Risk Indicators: <b>{high_risk_non_primary_count}</b></div>
          <div><span class="dot" style="background:#cbd5e1"></span>No Tampering Found: <b>{normal_count}</b></div>
          <div style="color:var(--muted);margin-top:12px;font-size:12px">
            Backdating threshold: {esc(summary_dict.get("relative_threshold_days","180"))} days<br>
            Program-run window: {esc(summary_dict.get("prefetch_window_minutes","30"))} minutes
          </div>
        </div>
      </div>
    </div>
    <div class="panel">
      <h2>Risk Score per Suspicious File</h2>
      <p class="section-desc">Higher score = more independent evidence sources agree on tampering.</p>
      {bars if bars else "<p style='color:var(--muted)'>No suspicious files found.</p>"}
    </div>
  </section>

  <section class="panel">
    <h2>File Evidence Summary</h2>
    <p class="section-desc">
      Each row is a file flagged as likely tampered, sorted by risk score.
      The coloured badges show which evidence sources support the finding &mdash;
      green means that source confirmed tampering activity, grey means it was not available or did not fire.
      <b>Log Record</b> = file-system transaction log matched the change.
      <b>Timestamp Irregular</b> = internal timestamp fields conflict with each other.
      <b>Change Journal</b> = the Windows change journal recorded an unusual metadata-only update.
      <b>System Log</b> = the $LogFile corroborates.
      <b>Windows/Office Recent</b> = shortcut files link a program run to this file at the relevant time.
      <b>Core Evidence</b> = primary mutation signal is present.
    </p>
    <table>
      <thead><tr><th>File Name</th><th>Finding Type</th><th>Risk Score</th><th>Evidence Sources</th><th>Related Program Run</th></tr></thead>
      <tbody>{evidence_rows}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Log Record Verification</h2>
    <p class="section-desc">
      The file system keeps an internal transaction log that records every structural change.
      When a suspicious file&rsquo;s log entry number matches a known timestamp-change transaction, that is strong corroborating evidence.
      &ldquo;Exact Match&rdquo; means the numbers align precisely; &ldquo;Near Match&rdquo; means they are within close sequence, which can occur due to buffering.
    </p>
    <table>
      <thead><tr>
        <th>File Name</th><th>Confidence</th><th>Log Match</th>
        <th>File System Log #</th><th>System Log #s</th><th>Why It Matters</th>
      </tr></thead>
      <tbody>{lsn_rows_html}</tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Timestamp Irregularity Details</h2>
    <p class="section-desc">
      NTFS stores timestamps in two separate places: $STANDARD_INFORMATION (visible to users) and $FILE_NAME (maintained by the kernel).
      Legitimate file operations keep them consistent. When they disagree by a large margin, or when timestamps show unusual patterns
      (e.g., artificially rounded times, dates set in the future, or decimal fractions that match known tools),
      that is a strong irregularity.
    </p>
    <table>
      <thead><tr>
        <th>File Name</th><th>Confidence</th><th>Irregularity Found</th>
        <th>Time Gap (SI vs FN)</th><th>Future Timestamp Fields</th><th>Artificial Pattern</th>
      </tr></thead>
      <tbody>{lowlevel_rows_html}</tbody>
    </table>
  </section>

  {render_all_file_table(all_file_sorted, "All Files Analyzed", "Complete list of every file examined, sorted by risk level. Use this table to get a quick overview of all assessed files.", 220)}

  <section class="panel">
    <h2>Warning Signs &amp; System Events</h2>
    <p class="section-desc">
      These are contextual signals that do not by themselves prove tampering, but are worth noting as part of the investigation.
      Examples: the system clock was changed while files were being accessed, or relevant files were deleted.
      They provide background context for the analyst.
    </p>
    <table>
      <thead><tr><th>Alert Type</th><th>Severity</th><th>Time / Current</th><th>Previous</th><th>Related File</th><th>Reason</th><th>Note</th></tr></thead>
      <tbody>{behavior_rows}</tbody>
    </table>
  </section>

  {render_all_file_table(high_risk_non_primary_rows, "High-Risk Indicators (Supporting Artifacts)", "Anomalies found in supporting artifacts such as Prefetch traces, shortcut files, directory index entries, or known tampering tool names. These strengthen the overall case picture but are not standalone proof of tampering.", 120)}
  {render_all_file_table(need_review_rows, "Files Needing Closer Review", "These files show some suspicious signals but not enough evidence to confirm tampering conclusively. A human analyst should examine them in more detail before drawing conclusions.", 120)}
  {render_all_file_table(normal_rows, "Files with No Tampering Signs", "These files were fully examined and no indicators of timestamp manipulation were found. They are consistent with normal file activity.", 120)}

  <section class="panel">
    <h2>Event Timeline for Suspicious Files</h2>
    <p class="section-desc">
      Chronological sequence of recorded system events for each file flagged as likely tampered.
      Each event comes from a different artifact source (MFT, USN journal, $LogFile, Prefetch, LNK).
      Click a file name to expand its timeline.
    </p>
    {timeline_html if timeline_html else "<p style='color:var(--muted)'>No timeline events available for suspicious files.</p>"}
  </section>

  <section class="panel">
    <h2>Detailed Findings per File</h2>
    <p class="section-desc">
      Plain-English explanation of why each suspicious file was flagged.
      Click &ldquo;Technical artifact details&rdquo; under each entry to see the raw evidence values used to reach the conclusion.
    </p>
    <div class="grid reason-grid">{reason_html if reason_html else "<p style='color:var(--muted)'>No detailed reasoning available.</p>"}</div>
  </section>

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
