from dashboard.analysis_engine_patch import patched_run_full_analysis as run_full_analysis
from dashboard.analysis_cache import set_analysis_snapshot
import logging

log = logging.getLogger("analysis_service")

def execute_analysis(run_id):
    """
    Orchestrates the full analysis pipeline for a given run_id.
    1. Runs the patched full analysis engine.
    2. Validates the resulting context.
    3. Persists a snapshot for the dashboard/UI.
    """
    log.info("[AnalysisService] Starting execution for run_id=%s", run_id)
    try:
        context = run_full_analysis(run_id)

        if not context or "recommended_action" not in context:
            log.error("[AnalysisService] Invalid analysis context for %s", run_id)
            return None

        set_analysis_snapshot(run_id, context)
        log.info("[AnalysisService] Execution complete and snapshot persisted for %s", run_id)
        return context
    except Exception as e:
        log.error("[AnalysisService] Execution crashed for %s: %s", run_id, e, exc_info=True)
        return None
