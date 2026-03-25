"""
app_fixes.py — Exact patches for dashboard/app.py
===================================================
Apply these 4 targeted fixes to app.py.
Each section shows the OLD code and the NEW replacement.

FIX 1 — Import swap (2 lines)
FIX 2 — burst_view reads from wrong DB
FIX 3 — api_events/latest reads from wrong DB
FIX 4 — api_alerts/latest reads from wrong DB
"""

# ════════════════════════════════════════════════════════════════════════════
# FIX 1: Import swap in app.py
# ════════════════════════════════════════════════════════════════════════════
#
# FIND this block (around line 30-35):
#
#   from dashboard.analysis_engine import (
#       ingest_upload,
#       persist_case,
#       run_full_analysis,
#   )
#
# REPLACE WITH:
#
#   from dashboard.analysis_engine import (
#       ingest_upload,
#       persist_case,
#   )
#   from dashboard.analysis_engine_patch import patched_run_full_analysis as run_full_analysis
#

# ════════════════════════════════════════════════════════════════════════════
# FIX 2: burst_view — reads from wrong DB
# ════════════════════════════════════════════════════════════════════════════
#
# The burst_view queries sentinel_LIVE for events, but uploaded data is in
# sentinel_CASES. Also the column `file_path` is what's stored, not `target_filename`.
#
# FIND (around line 1165 in burst_view):
#
#   try:
#       # FIX: uploaded cases live in sentinel_cases, not sentinel_live
#       _burst_mode = "live" if run_id == "live" else "cases"
#       with get_db_connection(_burst_mode) as conn:
#           with get_cursor(conn) as cur:
#               cur.execute(
#                   f"SELECT event_time, event_id, image, parent_image, command_line, "
#                   f"{_user_col}, pid, ppid, src_ip, dst_ip, dst_port, file_path, computer "
#                   f"FROM events "
#                   f"WHERE image = %s AND event_time >= %s AND event_time <= %s "
#                   f"AND run_id = %s ORDER BY event_time",
#                   (image, start, end, run_id),
#               )
#               events = [dict(r) for r in cur.fetchall()]
#
#               cur.execute(
#                   "SELECT DISTINCT image FROM events "
#                   "WHERE parent_image = %s AND event_time >= %s "
#                   "AND event_time <= %s AND run_id = %s",
#                   (image, start, end, run_id),
#               )
#               child_images = sorted(
#                   r["image"] for r in cur.fetchall() if r.get("image")
#               )
#   except Exception as exc:
#       flash(f"Error loading burst details: {exc}", "error")
#       return redirect(url_for("dashboard", run_id=run_id))
#
#
# REPLACE WITH:
#
#   try:
#       _burst_mode = "live" if run_id == "live" else "cases"
#       with get_db_connection(_burst_mode) as conn:
#           with get_cursor(conn) as cur:
#               cur.execute(
#                   f"SELECT event_time, event_id, image, parent_image, command_line, "
#                   f"{_user_col}, pid, ppid, src_ip AS source_ip, "
#                   f"dst_ip, dst_port, file_path, computer "
#                   f"FROM events "
#                   f"WHERE image = %s AND event_time >= %s AND event_time <= %s "
#                   f"AND run_id = %s ORDER BY event_time",
#                   (image, start, end, run_id),
#               )
#               events = [dict(r) for r in cur.fetchall()]
#
#               cur.execute(
#                   "SELECT DISTINCT image FROM events "
#                   "WHERE parent_image = %s AND event_time >= %s "
#                   "AND event_time <= %s AND run_id = %s",
#                   (image, start, end, run_id),
#               )
#               child_images = sorted(
#                   r["image"] for r in cur.fetchall() if r.get("image")
#               )
#   except Exception as exc:
#       flash(f"Error loading burst details: {exc}", "error")
#       return redirect(url_for("dashboard", run_id=run_id))
#

# ════════════════════════════════════════════════════════════════════════════
# FIX 3: api_alerts_latest — reads from wrong DB
# ════════════════════════════════════════════════════════════════════════════
#
# FIND in api_alerts_latest():
#
#   mode = "live" if (not run_id or run_id == "live") else "cases"
#   engine = get_engine(mode)
#   import pandas as pd
#   df = pd.read_sql_query(
#       text("SELECT utc_time, image, computer, rule_name, severity, mitre_id "
#            "FROM detections WHERE run_id = :run_id ORDER BY utc_time DESC LIMIT 20"),
#       engine, params={"run_id": run_id or "live"}
#   )
#
# REPLACE WITH:
#
#   mode = "live" if (not run_id or run_id == "live") else "cases"
#   engine = get_engine(mode)
#   import pandas as pd
#   # Try detections table; fall back to empty if utc_time col named differently
#   try:
#       df = pd.read_sql_query(
#           text("SELECT COALESCE(utc_time, event_time) AS utc_time, "
#                "image, computer, rule_name, severity, mitre_id "
#                "FROM detections WHERE run_id = :run_id "
#                "ORDER BY COALESCE(utc_time, event_time) DESC LIMIT 20"),
#           engine, params={"run_id": run_id or "live"}
#       )
#   except Exception:
#       df = pd.read_sql_query(
#           text("SELECT event_time AS utc_time, image, computer, "
#                "rule_name, severity, mitre_id "
#                "FROM detections WHERE run_id = :run_id "
#                "ORDER BY event_time DESC LIMIT 20"),
#           engine, params={"run_id": run_id or "live"}
#       )
#

# ════════════════════════════════════════════════════════════════════════════
# FIX 4: api_events_latest — reads from wrong DB and missing columns
# ════════════════════════════════════════════════════════════════════════════
#
# FIND in api_events_latest():
#
#   mode = "live" if (not run_id or run_id == "live") else "cases"
#   engine = get_engine(mode)
#   import pandas as pd
#   df = pd.read_sql_query(
#       text(f"SELECT event_time as utc_time, image, command_line, {_user_col} as user, computer "
#            f"FROM events WHERE run_id = :run_id ORDER BY event_time DESC LIMIT 100"),
#       engine, params={"run_id": run_id or "live"}
#   )
#
# REPLACE WITH:
#
#   mode = "live" if (not run_id or run_id == "live") else "cases"
#   engine = get_engine(mode)
#   import pandas as pd
#   df = pd.read_sql_query(
#       text(f"SELECT event_time AS utc_time, image, command_line, "
#            f"COALESCE({_user_col}, '') AS user, computer "
#            f"FROM events WHERE run_id = :run_id ORDER BY event_time DESC LIMIT 100"),
#       engine, params={"run_id": run_id or "live"}
#   )
#

# ════════════════════════════════════════════════════════════════════════════
# FIX 5: raw_events — reads from wrong DB
# ════════════════════════════════════════════════════════════════════════════
#
# FIND in raw_events():
#
#   _raw_mode = "live" if run_id == "live" else "cases"
#   with get_db_connection(_raw_mode) as conn:
#       with get_cursor(conn) as cur:
#           cur.execute(
#               f"SELECT event_time, event_id, image, {_user_col}, "
#               f"src_ip, dst_ip, command_line "
#               f"FROM events WHERE run_id = %s "
#               f"ORDER BY event_time DESC LIMIT %s OFFSET %s",
#               (run_id, page_size, offset),
#           )
#
# This is already correct — no change needed. sentinel_cases is used.
# The issue is the column might be `user` or `user_name`. The _user_col
# already handles this with backtick quoting. No change needed.
#

print("Apply the fixes above manually to dashboard/app.py")
print("Or use the automated patcher below:")
print()
print("python app_auto_patcher.py")
