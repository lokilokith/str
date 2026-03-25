import sqlite3
import pandas as pd
from dashboard.db import get_engine, get_db_connection
from dashboard.analysis_engine import process_event
from dashboard.analysis_engine_patch import patched_run_full_analysis
import json

print("\n--- PART 4: REAL VERIFICATION (Dataset & Coverage) ---")
engine = get_engine("cases")
try:
    events_df = pd.read_sql_query("SELECT * FROM events", engine)
    print("\n1. Dataset Validation (Top 5 Event IDs):")
    print(events_df["event_id"].value_counts().head(5))

    detections_df = pd.read_sql_query("SELECT * FROM detections", engine)
    print("\n2. Detection Validation (Kill Chain Stages):")
    if not detections_df.empty and "kill_chain_stage" in detections_df.columns:
        print(detections_df["kill_chain_stage"].value_counts())
    else:
        print("No detections found or column missing.")

    persistence_count = len(events_df[events_df["event_id"].astype(str).isin(["12", "13", "14"])])
    all_count = len(events_df)
    print(f"\n3. Coverage Ratio (Persistence Events / All Events):")
    print(f"{persistence_count} / {all_count} = {persistence_count/all_count:.4f}" if all_count else "N/A")

except Exception as e:
    print(f"Failed to query database: {e}")

print("\n--- PART 5: LIVE PIPELINE VALIDATION ---")
mock_live_event = {
    "event_uid": "live-test-persist-999",
    "event_id": 13,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "reg_key": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilPayload",
    "target_filename": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilPayload",
    "command_line": "powershell -enc ...",
    "utc_time": "2023-10-27T10:00:00.000Z",
    "computer": "TEST-PC",
    "run_id": "live"
}
try:
    with get_db_connection("live") as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM live_events WHERE event_uid = 'live-test-persist-999'")
            cur.execute("DELETE FROM detections WHERE event_id = 13 AND run_id = 'live' AND image LIKE '%powershell%'")
        conn.commit()
    print("Cleaned up old test events.")

    # Route through process_event (which calls detection_engine match_rules and persists)
    print("Testing process_event...")
    process_event(mock_live_event)
    print("Event processed via live pipeline.")

    # Check detections
    with get_db_connection("live") as conn:
        live_dets = pd.read_sql_query("SELECT * FROM detections WHERE run_id = 'live' AND event_id = 13 AND image LIKE '%powershell%' ORDER BY utc_time DESC LIMIT 1", conn)
        print("\nLive Detections Generated:")
        if not live_dets.empty:
            print(live_dets[["rule_name", "kill_chain_stage", "severity"]].to_string())
        else:
            print("FAILED: No live detection persisted!")

except Exception as e:
    print(f"Live pipeline test failed: {e}")

