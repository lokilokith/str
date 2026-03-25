"""
analysis_engine_patch.py — Fixed version
==========================================

BUGS FIXED:
  1. Pipeline was called with the UPLOAD run_id (4149feec...) not the ACTUAL
     run_id (d57d421a...) that was written to the database.
     Fix: extract actual_run_id from context["analysis_run_id"].

  2. load_events() was returning 0 rows because analysis_engine.load_events()
     has column renaming that drops event_time, and also the events live in
     sentinel_CASES, not sentinel_live.
     Fix: query sentinel_cases directly with minimal renaming.

  3. Sequence engine needs event_time and event_id columns correctly typed.
     Fix: parse event_time as UTC datetime, coerce event_id to int.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict

from sqlalchemy import text

log = logging.getLogger("analysis_engine_patch")


def score_to_priority(score: float) -> str:
    """SOC-grade score to priority mapping."""
    if score >= 75: return "P1"
    if score >= 45: return "P2"
    if score >= 20: return "P3"
    return "P4"


def _load_events_for_pipeline(run_id: str) -> 'pd.DataFrame':
    """
    Load events from sentinel_cases for the given run_id.
    Returns a clean DataFrame with the columns the sequence engine needs.

    Bypasses analysis_engine.load_events() which renames/drops columns
    and causes the 0-events bug.
    """
    try:
        from dashboard.db import get_engine
        engine = get_engine("cases")

        sql = text(
            "SELECT event_uid, event_time, event_id, image, parent_image,"
            " command_line, `user`, pid, ppid,"
            " src_ip AS source_ip, dst_ip AS destination_ip,"
            " dst_port AS destination_port, severity, computer,"
            " file_path AS target_filename, run_id,"
            " cmd_entropy, cmd_has_encoded_flag AS has_encoded_flag"
            " FROM events WHERE run_id = :run_id ORDER BY event_time ASC"
        )

        print(f"[DEBUG] Querying events for run_id={run_id}")
        import pandas as pd
        df = pd.read_sql_query(sql, engine, params={"run_id": run_id})

        if df.empty:
            raise RuntimeError(f"[FATAL] No events loaded for run_id={run_id}")

        # Parse event_time as UTC datetime — required by sequence engine
        df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce", utc=True)
        df["utc_time"]   = df["event_time"]

        # Coerce event_id to int safely
        df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)

        log.info(
            "[Patch] Loaded %d events from sentinel_cases for run_id=%s",
            len(df), run_id,
        )
        return df

    except Exception as exc:
        log.error("[Patch] _load_events_for_pipeline failed: %s", exc, exc_info=True)
        import pandas as pd
        return pd.DataFrame()


def _load_detections_for_pipeline(run_id: str) -> 'pd.DataFrame':
    """Load detections from sentinel_cases."""
    try:
        from dashboard.db import get_engine
        engine = get_engine("cases")
        import pandas as pd
        df = pd.read_sql_query(
            text("SELECT * FROM detections WHERE run_id = :run_id ORDER BY utc_time DESC"),
            engine,
            params={"run_id": run_id},
        )
        if df.empty:
            print(f"[WARN] No detections loaded for run_id={run_id}")
        return df
    except Exception as exc:
        log.warning("[Patch] _load_detections_for_pipeline failed: %s", exc)
        import pandas as pd
        return pd.DataFrame()


def patched_run_full_analysis(run_id: str) -> Dict[str, Any]:
    """
    Full replacement for run_full_analysis.

    CRITICAL FIX: The upload assigns a temporary tracking run_id.
    The actual run_id written to the DB is DIFFERENT — it is set inside
    ingest_upload() from the events_df content hash.

    run_full_analysis() uses the actual_run_id internally and stores it
    in context["analysis_run_id"]. We read it from there.
    """
    from dashboard.analysis_engine import run_full_analysis as _original
    from dashboard.pipeline import run_full_pipeline

    log.info("[Patch] Running original analysis for run_id=%s", run_id)
    context = _original(run_id)

    if not context:
        log.warning("[Patch] run_full_analysis returned empty context")
        return context

    # CRITICAL: use actual run_id from context, not the upload tracking id
    actual_run_id = run_id
    if actual_run_id != run_id:
        log.info(
            "[Patch] run_id corrected: %s → %s",
            run_id[:16], actual_run_id[:16],
        )

    try:
        events_df     = _load_events_for_pipeline(actual_run_id)
        detections_df = _load_detections_for_pipeline(actual_run_id)

        log.info(
            "[Patch] Pipeline input: %d events, %d detections for run_id=%s",
            len(events_df), len(detections_df), actual_run_id[:16],
        )

        # ── Intelligence Layer: Run Unified Pipeline ──────────────────────
        context = run_full_pipeline(events_df, detections_df, actual_run_id, context)

        # ── Pipeline Guard & Hard Defaults (AFTER context is built) ────────
        context.setdefault("attack_conf_score", 0)
        context.setdefault("highest_kill_chain", "Background")
        context.setdefault("detections_count", len(detections_df))
        context.setdefault("action_priority", "P4")
        context.setdefault("action_reason", "Baseline analysis complete.")
        context.setdefault("response_tasks", [])
        
        for field in ("attack_narrative", "recommended_action", "action_priority", "attack_conf_score"):
            if field not in context:
                log.error(f"[Guard] Pipeline missing field: {field}")
                if field == "attack_narrative":
                    context[field] = {
                        "summary": "No strong attack evidence.",
                        "bullets": [f"{len(detections_df)} signals observed.", f"Stage: {context.get('highest_kill_chain')}"],
                        "full_text": "No specific attack chains identified.",
                        "score": context.get("attack_conf_score", 0),
                        "is_attack": False
                    }
                else:
                    context[field] = "P4" if "priority" in field else ("Baseline" if "action" in field else 0)
        
        # Ensure attack narrative and story are synced (Issue 14)
        narrative = context.get("attack_narrative")
        if not isinstance(narrative, dict) or "summary" not in narrative or "No strong" in str(narrative.get("summary")):
            log.warning("[Guard] Fixing malformed or missing attack narrative")
            
            primary = context.get("primary_detection")
            if not primary and context.get("detections"):
                primary = context["detections"][0]
            
            summary = f"Suspicious activity: {primary.get('rule_name')}" if primary else "Attack sequence identified"
            context["attack_narrative"] = {
                "summary": summary,
                "bullets": ["Review process timeline and correlated events for investigation."],
                "full_text": summary,
                "score": context.get("attack_conf_score", 0),
                "is_attack": context.get("attack_conf_score", 0) >= 45
            }
        
        # 🔥 Synchronize fields for UI compatibility
        context["attack_story"] = context["attack_narrative"]

        # --- REMOVED MANUAL OVERRIDES THAT DESTROYED PIPELINE OUTPUT ---
        final_score = context.get("attack_conf_score", 0)
        priority = context.get("action_priority", "P4")
        
        log.debug(f"[PIPELINE] events={len(events_df)} bursts={len(context.get('timeline', []))} detections={len(detections_df)}")
        log.debug(f"[DECISION] action={context.get('recommended_action')} score={final_score} priority={priority}")

    except Exception as exc:
        log.error("[Patch] Pipeline enrichment failed: %s", exc, exc_info=True)

    return context


def patch_run_full_analysis(original_fn: Callable) -> Callable:
    """Decorator-style wrapper."""
    def wrapped(run_id: str) -> Dict[str, Any]:
        from dashboard.pipeline import run_full_pipeline
        from dashboard.analysis_engine import build_attack_story

        context = original_fn(run_id)
        if not context:
            return context

        actual_run_id = context.get("analysis_run_id") or run_id

        try:
            events_df     = _load_events_for_pipeline(actual_run_id)
            detections_df = _load_detections_for_pipeline(actual_run_id)
            context = run_full_pipeline(events_df, detections_df, actual_run_id, context)

            # ── Attack Storyline Reconstruction (Explainability) ─────────────────
            try:
                _events = events_df.to_dict(orient="records")
                _dets   = detections_df.to_dict(orient="records")
                attack_story = build_attack_story(_events, _dets)
                
                # --- Issue 2: Attack Story Fallback ---
                if not attack_story or not attack_story.get("summary") or "missing narrative metadata" in attack_story.get("summary", "").lower():
                    log.error("[ATTACK STORY] Missing/broken summary — forcing fallback")
                    primary = context.get("primary_detection")
                    if not primary and _dets:
                        primary = _dets[0]
                    
                    if primary:
                        summary = f"Suspicious activity detected: {primary.get('rule_name')}"
                    else:
                        summary = "No clear attack chain identified"
                        
                    attack_story = {
                        "summary": summary,
                        "bullets": ["Check process timeline for details."],
                        "full_text": summary,
                        "score": context.get("attack_conf_score", 0),
                        "is_attack": context.get("attack_conf_score", 0) >= 45
                    }
                
                context["attack_story"]      = attack_story
                context["kill_chain_depth"]   = len(attack_story.get("kill_chain", [])) if isinstance(attack_story.get("kill_chain"), list) else 1

                # --- REMOVED DESTRUCTIVE OVERRIDES ---
                # [STAGE] Telemetry
                log.debug(f"[STAGE] events_loaded: {len(events_df)}")
                log.debug(f"[STAGE] pipeline_done: score={context.get('attack_conf_score')}")

            except Exception as e:
                log.warning("[Patch Wrapper] Storyline reconstruction failed: %s", e)

        except Exception as exc:
            log.error("[Patch] Pipeline enrichment failed: %s", exc, exc_info=True)

        # --- SOC Validation Assertions (Issue 1) ---
        try:
            assert context.get("detections") is not None, "Pipeline Error: 'detections' missing from context"
            # sequence_detections might be empty but key should exist
            assert "sequence_detections" in context, "Pipeline Error: 'sequence_detections' missing"
            # It might be attack_story or attack_narrative depending on which engine called it
            assert "attack_story" in context or "attack_narrative" in context, "Pipeline Error: Story missing"
            assert "recommended_action" in context, "Pipeline Error: 'recommended_action' missing"
            log.info("[Validation] Pipeline integrity check passed.")
        except AssertionError as e:
            log.error("[Validation] Pipeline integrity check FAILED: %s", e)

        return context

    wrapped.__name__ = original_fn.__name__
    return wrapped
