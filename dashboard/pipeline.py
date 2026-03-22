"""
pipeline.py — SentinelTrace Unified Analysis Pipeline
=======================================================
THIS IS THE MISSING GLUE.

Connects all engines in the correct order:
  1. Parser / enrichment (already done at ingest time)
  2. Baseline Engine      → deviation scores
  3. Sequence Engine      → attack-chain detection
  4. Correlation Engine   → campaign linking
  5. Feedback Engine      → analyst-verdict adjustments
  6. Scoring Engine       → final fused risk score
  7. Decision Layer       → recommended analyst action

Previously these were all isolated. This module wires them together
so every burst passes through every stage before hitting the UI.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

log = logging.getLogger("pipeline")


# ---------------------------------------------------------------------------
# 1. Decision layer
# ---------------------------------------------------------------------------

DECISION_RULES = [
    # (condition_fn, action, reason)
    (lambda c: c["attack_conf_score"] >= 80 or c.get("has_injection"),
     "ESCALATE",
     "High-confidence attack or process injection detected — escalate immediately"),

    (lambda c: c["attack_conf_score"] >= 60
               or c.get("has_persistence")
               or c.get("highest_kill_chain") in ("Persistence", "Privilege Escalation",
                                                    "Credential Access"),
     "INVESTIGATE",
     "Persistence or privilege escalation evidence — full investigation required"),

    (lambda c: c["attack_conf_score"] >= 40
               or c.get("highest_kill_chain") in ("Command and Control", "Lateral Movement"),
     "INVESTIGATE",
     "Suspicious multi-stage activity — review C2/lateral movement indicators"),

    (lambda c: c["attack_conf_score"] >= 20 or c.get("detections_count", 0) > 0,
     "MONITOR",
     "Low-confidence detections — monitor for escalation and correlate with other sources"),

    (lambda c: True,
     "BASELINE",
     "Activity consistent with known baseline — no immediate action required"),
]


def compute_decision(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a fully-scored analysis context, produce a recommended action.
    Returns {"action": str, "reason": str, "priority": str, "response_tasks": list}
    """
    for condition, action, reason in DECISION_RULES:
        try:
            if condition(context):
                priority = {
                    "ESCALATE":    "P1",
                    "INVESTIGATE": "P2",
                    "MONITOR":     "P3",
                    "BASELINE":    "P4",
                }.get(action, "P4")

                tasks = _build_response_tasks(action, context)
                return {
                    "action":         action,
                    "reason":         reason,
                    "priority":       priority,
                    "response_tasks": tasks,
                }
        except Exception:
            continue

    return {"action": "BASELINE", "reason": "Insufficient data", "priority": "P4",
            "response_tasks": []}


def _build_response_tasks(action: str, context: Dict[str, Any]) -> List[Dict[str, str]]:
    tasks = []
    stage = context.get("highest_kill_chain") or "Execution"

    if action == "ESCALATE":
        tasks += [
            {"task": "Isolate affected host from network",               "priority": "immediate"},
            {"task": "Preserve memory and disk image",                   "priority": "immediate"},
            {"task": "Reset credentials for affected accounts",          "priority": "urgent"},
            {"task": "Block identified IOCs at firewall and DNS",        "priority": "urgent"},
            {"task": "Notify security management and open P1 ticket",   "priority": "urgent"},
        ]
    if action in ("ESCALATE", "INVESTIGATE"):
        tasks += [
            {"task": "Review parent/child process relationships",        "priority": "high"},
            {"task": "Check for persistence in Run keys and startup",    "priority": "high"},
            {"task": "Pivot on destination IPs and DNS queries",         "priority": "high"},
        ]
    if stage in ("Lateral Movement", "Command and Control"):
        tasks.append({"task": "Hunt for lateral movement on adjacent hosts", "priority": "high"})
    if stage == "Credential Access":
        tasks.append({"task": "Audit privileged account usage immediately",  "priority": "high"})
    if action == "MONITOR":
        tasks += [
            {"task": "Set alert threshold for this process image",       "priority": "normal"},
            {"task": "Correlate with network telemetry",                 "priority": "normal"},
        ]

    return tasks


# ---------------------------------------------------------------------------
# 2. Attack narrative builder
# ---------------------------------------------------------------------------

def build_attack_narrative(
    bursts: List[Dict[str, Any]],
    campaigns: List[Dict[str, Any]],
    sequence_detections: List[Dict[str, Any]],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Produce a human-readable attack story from all available signals.
    This is the "Attack Story" the analyst sees at the top of the dashboard.
    """
    lines: List[str] = []
    stage = context.get("highest_kill_chain") or "Execution"
    score = context.get("attack_conf_score", 0)

    # Opening summary
    if score >= 70:
        lines.append(
            f"HIGH CONFIDENCE ATTACK DETECTED — {score}/100 confidence, "
            f"progressed to {stage}."
        )
    elif score >= 40:
        lines.append(
            f"SUSPICIOUS ACTIVITY — {score}/100 confidence, "
            f"kill-chain evidence up to {stage}."
        )
    else:
        lines.append("Low-risk baseline activity. No confirmed attack indicators.")

    # Sequence detections — most specific evidence
    for seq in sequence_detections[:3]:
        lines.append(f"• Attack chain detected: {seq.get('chain_str', seq.get('rule_name'))}")

    # Persistence / injection
    attack_bursts = [b for b in bursts if b.get("classification") == "attack_candidate"]
    for b in sorted(attack_bursts, key=lambda x: x.get("risk_score", 0), reverse=True)[:3]:
        img = b.get("image", "?")
        kc  = b.get("kill_chain_stage", "?")
        sc  = b.get("risk_score", 0)
        indicators = []
        if b.get("has_persistence"): indicators.append("persistence")
        if b.get("has_injection"):   indicators.append("injection")
        if b.get("has_net"):         indicators.append("network activity")
        ind_str = (", ".join(indicators) + " — ") if indicators else ""
        lines.append(f"• {img} [{kc}] — {ind_str}risk score {sc}")

    # Campaigns
    for camp in campaigns[:2]:
        lines.append(
            f"• Multi-stage campaign detected across "
            f"{len(camp.get('computers', []))} host(s): "
            f"confidence {camp.get('confidence', 0):.0f}%"
        )

    return {
        "summary": lines[0] if lines else "No activity.",
        "bullets": lines[1:],
        "full_text": "\n".join(lines),
        "stage": stage,
        "score": score,
        "is_attack": score >= 40,
    }


# ---------------------------------------------------------------------------
# 3. Top-threats prioritiser
# ---------------------------------------------------------------------------

def prioritise_bursts(bursts: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """
    Return the top-N highest-risk bursts, ranked by multi-factor priority score.
    This replaces the flat list that shows everything equally.
    """
    KILL_CHAIN_ORDER = [
        "Background", "Delivery", "Execution", "Defense Evasion",
        "Persistence", "Privilege Escalation", "Credential Access",
        "Discovery", "Lateral Movement", "Collection",
        "Command and Control", "Exfiltration", "Actions on Objectives",
    ]
    kc_rank = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

    def _priority_score(b: Dict) -> float:
        sc    = float(b.get("risk_score") or b.get("peak_score") or 0)
        stage = b.get("kill_chain_stage") or "Background"
        kc    = kc_rank.get(stage, 0)
        bonus = (
            (10 if b.get("has_persistence") else 0) +
            (15 if b.get("has_injection")   else 0) +
            (5  if b.get("has_correlation") else 0) +
            (5  if b.get("has_net")         else 0)
        )
        return sc + kc * 2 + bonus

    return sorted(bursts, key=_priority_score, reverse=True)[:limit]


# ---------------------------------------------------------------------------
# 4. Full pipeline runner
# ---------------------------------------------------------------------------

def run_full_pipeline(
    events_df: pd.DataFrame,
    detections_df: pd.DataFrame,
    run_id: str,
    partial_context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Given raw events + detections already stored in DB (by analysis_engine),
    run the full enrichment pipeline and augment the context dict.

    This is called at the END of run_full_analysis() to layer on the
    missing pieces: sequence detection, feedback, decision, narrative.

    Returns the augmented context.
    """
    ctx = dict(partial_context)

    # ── A. Sequence engine ──────────────────────────────────────────────
    sequence_detections: List[Dict[str, Any]] = []
    if not events_df.empty:
        try:
            from dashboard.sequence_engine import get_sequence_engine
            seq_engine = get_sequence_engine()
            # Normalize column name used by sequence engine
            df_seq = events_df.copy()
            if "event_time" in df_seq.columns and "utc_time" not in df_seq.columns:
                df_seq["utc_time"] = df_seq["event_time"]
            sequence_detections = seq_engine.process_dataframe(df_seq)

            # Tag run_id
            for sd in sequence_detections:
                sd["run_id"] = run_id

            log.info("[Pipeline] Sequence engine: %d chain detections", len(sequence_detections))

            # Merge sequence detections into the main detections list
            if sequence_detections:
                ctx.setdefault("detections", [])
                ctx["detections"] = list(ctx["detections"]) + sequence_detections
                ctx["detections_count"] = len(ctx["detections"])

                # Boost attack_conf_score for each high-confidence sequence hit
                for sd in sequence_detections:
                    conf = int(sd.get("confidence_score") or sd.get("confidence") or 0)
                    if conf >= 80:
                        ctx["attack_conf_score"] = min(
                            100, ctx.get("attack_conf_score", 0) + 15
                        )
                    elif conf >= 60:
                        ctx["attack_conf_score"] = min(
                            100, ctx.get("attack_conf_score", 0) + 8
                        )

                # Update kill-chain if sequence found a higher stage
                KILL_CHAIN_ORDER = [
                    "Background", "Delivery", "Execution", "Defense Evasion",
                    "Persistence", "Privilege Escalation", "Credential Access",
                    "Discovery", "Lateral Movement", "Collection",
                    "Command and Control", "Exfiltration", "Actions on Objectives",
                ]
                kc_rank = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}
                for sd in sequence_detections:
                    seq_stage = sd.get("kill_chain_stage") or "Execution"
                    cur_stage = ctx.get("highest_kill_chain") or "Execution"
                    if kc_rank.get(seq_stage, 0) > kc_rank.get(cur_stage, 0):
                        ctx["highest_kill_chain"] = seq_stage

        except Exception as exc:
            log.warning("[Pipeline] Sequence engine failed: %s", exc)

    ctx["sequence_detections"] = sequence_detections

    # ── B. Apply feedback suppressions ─────────────────────────────────
    bursts = list(ctx.get("timeline", []) or [])
    if bursts:
        try:
            from dashboard.feedback_engine import load_suppressions, apply_feedback_adjustment
            suppressions = load_suppressions()
            if suppressions:
                for burst in bursts:
                    delta, reason = apply_feedback_adjustment(burst, suppressions)
                    if delta != 0:
                        old = burst.get("risk_score", 0)
                        burst["risk_score"] = max(0, min(100, old + delta))
                        burst.setdefault("confidence_reasons", [])
                        burst["confidence_reasons"].append(
                            f"Feedback adjustment {delta:+d}: {reason}"
                        )
                log.info("[Pipeline] Feedback applied to %d bursts", len(bursts))
        except Exception as exc:
            log.warning("[Pipeline] Feedback engine failed: %s", exc)

    ctx["timeline"] = bursts

    # ── C. Re-prioritise burst aggregates with sequence boost ───────────
    burst_aggregates = list(ctx.get("burst_aggregates", []) or [])

    # Apply sequence confidence to matching images
    seq_by_image: Dict[str, int] = {}
    for sd in sequence_detections:
        img  = (sd.get("image") or "").lower()
        conf = int(sd.get("confidence_score") or sd.get("confidence") or 0)
        seq_by_image[img] = max(seq_by_image.get(img, 0), conf)

    for ba in burst_aggregates:
        img = (ba.get("image") or "").lower()
        seq_boost = seq_by_image.get(img, 0)
        if seq_boost > 0:
            old = ba.get("peak_score") or ba.get("risk_score") or 0
            ba["peak_score"] = min(100, int(old) + seq_boost // 5)
            ba["has_sequence_detection"] = True

    ctx["burst_aggregates"] = prioritise_bursts(burst_aggregates)

    # ── D. Decision layer ───────────────────────────────────────────────
    # Build a minimal context dict the decision function can consume
    top_burst  = burst_aggregates[0] if burst_aggregates else {}
    dec_input  = {
        "attack_conf_score":   ctx.get("attack_conf_score", 0),
        "highest_kill_chain":  ctx.get("highest_kill_chain"),
        "has_persistence":     any(b.get("has_persistence") for b in bursts),
        "has_injection":       any(b.get("has_injection") for b in bursts),
        "detections_count":    ctx.get("detections_count", 0),
    }
    decision = compute_decision(dec_input)
    ctx["recommended_action"] = decision["action"]
    ctx["action_reason"]      = decision["reason"]
    ctx["action_priority"]    = decision["priority"]
    ctx["response_tasks"]     = decision["response_tasks"]

    # ── E. Attack narrative ─────────────────────────────────────────────
    campaigns = ctx.get("correlation_campaigns", []) or []
    narrative = build_attack_narrative(bursts, campaigns, sequence_detections, ctx)
    ctx["attack_narrative"] = narrative

    # ── F. Final conf-level recompute (now that sequence boosted score) ──
    score = ctx.get("attack_conf_score", 0)
    ctx["attack_conf_level"] = (
        "High"   if score >= 80
        else "Medium" if score >= 50
        else "Low"    if score >= 20
        else "None"
    )
    ctx["is_alertable"] = score >= 40

    log.info(
        "[Pipeline] Complete: score=%d level=%s action=%s sequence_hits=%d",
        score, ctx["attack_conf_level"], decision["action"], len(sequence_detections),
    )
    return ctx
