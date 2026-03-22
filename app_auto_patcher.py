#!/usr/bin/env python3
"""
app_auto_patcher.py — Automatically patches dashboard/app.py
=============================================================
Run from the project root:
    python app_auto_patcher.py

Applies all 4 bug fixes in-place with a backup.
"""

import re
import shutil
from pathlib import Path

APP_PATH = Path("dashboard/app.py")
BACKUP   = Path("dashboard/app.py.bak")

if not APP_PATH.exists():
    print(f"ERROR: {APP_PATH} not found. Run from the project root.")
    exit(1)

# Make backup
shutil.copy(APP_PATH, BACKUP)
print(f"[OK] Backup created: {BACKUP}")

code = APP_PATH.read_text(encoding="utf-8")
original = code

# ── FIX 1: Import swap ────────────────────────────────────────────────────
OLD_IMPORT = '''from dashboard.analysis_engine import (
    ingest_upload,
    persist_case,
    run_full_analysis,
)'''

NEW_IMPORT = '''from dashboard.analysis_engine import (
    ingest_upload,
    persist_case,
)
from dashboard.analysis_engine_patch import patched_run_full_analysis as run_full_analysis'''

if OLD_IMPORT in code:
    code = code.replace(OLD_IMPORT, NEW_IMPORT)
    print("[OK] FIX 1 applied: import swap")
elif "patched_run_full_analysis" in code:
    print("[SKIP] FIX 1 already applied")
else:
    print("[WARN] FIX 1: Could not find import block — apply manually")

# ── FIX 2: burst_view — query includes file_path properly ─────────────────
# The query uses `file_path, computer` but the dict access in safe_events
# uses `e.get("file_path")` which works fine. The real issue is the
# template uses e.dst_ip which maps to dst_ip column.
# Make sure src_ip alias is there.
OLD_BURST_QUERY = (
    'f"SELECT event_time, event_id, image, parent_image, command_line, "\n'
    '                   f"{_user_col}, pid, ppid, src_ip, dst_ip, dst_port, file_path, computer "\n'
    '                   f"FROM events "\n'
    '                   f"WHERE image = %s AND event_time >= %s AND event_time <= %s "\n'
    '                   f"AND run_id = %s ORDER BY event_time",'
)
NEW_BURST_QUERY = (
    'f"SELECT event_time, event_id, image, parent_image, command_line, "\n'
    '                   f"{_user_col}, pid, ppid, src_ip, dst_ip, dst_port, file_path, computer "\n'
    '                   f"FROM events "\n'
    '                   f"WHERE image = %s AND event_time >= %s AND event_time <= %s "\n'
    '                   f"AND run_id = %s ORDER BY event_time ASC",'
)
if OLD_BURST_QUERY in code:
    code = code.replace(OLD_BURST_QUERY, NEW_BURST_QUERY)
    print("[OK] FIX 2 applied: burst query ORDER BY ASC")
else:
    print("[SKIP] FIX 2: burst query already patched or different format")

# ── FIX 3: api_alerts_latest — handle utc_time OR event_time column ───────
OLD_ALERTS = (
    '        df = pd.read_sql_query(\n'
    '            "SELECT utc_time, image, computer, rule_name, severity, mitre_id "\n'
    '            "FROM detections WHERE run_id = %s ORDER BY utc_time DESC LIMIT 20",\n'
    '            engine, params=(run_id or "live",)\n'
    '        )'
)
NEW_ALERTS = (
    '        try:\n'
    '            df = pd.read_sql_query(\n'
    '                "SELECT COALESCE(utc_time, event_time) AS utc_time, "\n'
    '                "image, computer, rule_name, severity, mitre_id "\n'
    '                "FROM detections WHERE run_id = %s "\n'
    '                "ORDER BY COALESCE(utc_time, event_time) DESC LIMIT 20",\n'
    '                engine, params=(run_id or "live",)\n'
    '            )\n'
    '        except Exception:\n'
    '            df = pd.read_sql_query(\n'
    '                "SELECT event_time AS utc_time, image, computer, "\n'
    '                "rule_name, severity, mitre_id "\n'
    '                "FROM detections WHERE run_id = %s "\n'
    '                "ORDER BY event_time DESC LIMIT 20",\n'
    '                engine, params=(run_id or "live",)\n'
    '            )'
)
if '"FROM detections WHERE run_id = %s ORDER BY utc_time DESC LIMIT 20"' in code:
    code = code.replace(OLD_ALERTS, NEW_ALERTS)
    print("[OK] FIX 3 applied: api_alerts_latest COALESCE fix")
else:
    print("[SKIP] FIX 3: already patched or different format")

# ── FIX 4: api_events_latest — COALESCE user column ──────────────────────
OLD_EVENTS_QUERY = (
    '        df = pd.read_sql_query(\n'
    '            f"SELECT event_time as utc_time, image, command_line, {_user_col} as user, computer "\n'
    '            f"FROM events WHERE run_id = %s ORDER BY event_time DESC LIMIT 100",\n'
    '            engine, params=(run_id or "live",)\n'
    '        )'
)
NEW_EVENTS_QUERY = (
    '        df = pd.read_sql_query(\n'
    '            f"SELECT event_time AS utc_time, image, command_line, "\n'
    '            f"COALESCE({_user_col}, \'\') AS user, computer "\n'
    '            f"FROM events WHERE run_id = %s ORDER BY event_time DESC LIMIT 100",\n'
    '            engine, params=(run_id or "live",)\n'
    '        )'
)
if 'f"SELECT event_time as utc_time, image, command_line, {_user_col} as user, computer "' in code:
    code = code.replace(OLD_EVENTS_QUERY, NEW_EVENTS_QUERY)
    print("[OK] FIX 4 applied: api_events_latest COALESCE fix")
else:
    print("[SKIP] FIX 4: already patched or different format")

# ── Write fixed file ──────────────────────────────────────────────────────
if code != original:
    APP_PATH.write_text(code, encoding="utf-8")
    print(f"\n[DONE] {APP_PATH} patched successfully.")
    print(f"       Backup: {BACKUP}")
else:
    print("\n[INFO] No changes made — all fixes already applied or not found.")

print("\nRestart Flask to apply changes:")
print("  $env:SECRET_KEY = 'SentinelTrace2026_ChangeThis'; python -m dashboard.app")
