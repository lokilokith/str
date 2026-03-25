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

  4. SQL syntax error: MySQL rejected the multi-line triple-quoted query with
     `event_time AS utc_time` on a separate indented line. Also `user` is a
     reserved word in MySQL and must be backtick-quoted.
     Fix: rewrite as a flat single-string query with proper quoting.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict

import pandas as pd
from sqlalchemy import text

log = logging.getLogger("analysis_engine_patch")


def _load_events_for_pipeline(run_id: str) -> pd.DataFrame:
    """
    Load events from sentinel_cases for the given run_id.
    Returns a clean DataFrame with the columns the sequence engine needs.

    Bypasses analysis_engine.load_events() which renames/drops columns
    and causes the 0-events bug.
    """
    try:
        from dashboard.db import get_engine
        engine = get_engine("cases")

        # Single flat string — no indentation, no heredoc, no duplicate aliases.
        # `user` is backtick-quoted because it is a MySQL reserved word.
        # utc_time is NOT aliased in SQL — it is added as a Python column copy
        # below to avoid the MySQL syntax error caused by selecting the same
        # column twice with different aliases in a multi-line query.
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
        df = pd.read_sql_query(sql, engine, params={"run_id": run_id})

        if df.empty:
            raise RuntimeError(f"[FATAL] No events loaded for run_id={run_id}")

        # Parse event_time as UTC datetime — required by sequence engine
        df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce", utc=True)

        # Add utc_time as a Python copy — never alias the same column twice in SQL
        df["utc_time"] = df["event_time"]

        # Coerce event_id to int safely
        df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)

        log.info(
            "[Patch] Loaded %d events from sentinel_cases for run_id=%s",
            len(df), run_id,
        )
        return df

    except Exception as exc:
        log.error("[Patch] _load_events_for_pipeline failed: %s", exc, exc_info=True)
        return pd.DataFrame()


def _load_detections_for_pipeline(run_id: str) -> pd.DataFrame:
    """Load detections from sentinel_cases."""
    try:
        from dashboard.db import get_engine
        engine = get_engine("cases")
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

        context = run_full_pipeline(events_df, detections_df, actual_run_id, context)

    except Exception as exc:
        log.error("[Patch] Pipeline enrichment failed: %s", exc, exc_info=True)

    return context


def patch_run_full_analysis(original_fn: Callable) -> Callable:
    """Decorator-style wrapper."""
    def wrapped(run_id: str) -> Dict[str, Any]:
        from dashboard.pipeline import run_full_pipeline

        context = original_fn(run_id)
        if not context:
            return context

        actual_run_id = context.get("analysis_run_id") or run_id

        try:
            events_df     = _load_events_for_pipeline(actual_run_id)
            detections_df = _load_detections_for_pipeline(actual_run_id)
            context = run_full_pipeline(events_df, detections_df, actual_run_id, context)
        except Exception as exc:
            log.error("[Patch] Pipeline enrichment failed: %s", exc, exc_info=True)

        return context

    wrapped.__name__ = original_fn.__name__
    return wrapped
