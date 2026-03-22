"""
app_patch.py — Minimal diff to wire pipeline into app.py
=========================================================
Apply these changes to dashboard/app.py.

CHANGE 1: Replace the import of run_full_analysis:

    # OLD (in app.py imports section):
    from dashboard.analysis_engine import (
        ingest_upload,
        persist_case,
        run_full_analysis,
    )

    # NEW:
    from dashboard.analysis_engine import (
        ingest_upload,
        persist_case,
    )
    from dashboard.analysis_engine_patch import patched_run_full_analysis as run_full_analysis

CHANGE 2: In the dashboard() route, after getting context, ensure it renders
the new fields. The template patch (index_patch.html) handles the UI side.

That is literally it. Two lines changed in app.py.
The rest of the fixes are in:
  - dashboard/pipeline.py          (new file — unified pipeline)
  - dashboard/analysis_engine_patch.py (new file — wraps run_full_analysis)
  - dashboard/templates/index.html (patched to show action/narrative/sequence)

CHANGE 3: In _run_analysis_async, replace:
    context = run_full_analysis(actual_run_id)
with:
    context = run_full_analysis(actual_run_id)   # same call, now patched

No change needed — the import swap in CHANGE 1 handles it automatically.
"""

# This file is documentation only — see instructions above.
# The actual patch files are:
#   dashboard/pipeline.py
#   dashboard/analysis_engine_patch.py
#   dashboard/templates/index.html  (full replacement below)
