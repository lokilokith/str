
import sys
import os
import pandas as pd
import datetime
from typing import Any, Dict, List
import uuid

# Add directory to path
sys.path.append(os.getcwd())

from dashboard.scoring_engine import ScoringEngine
from dashboard.sequence_engine import SequenceEngine

# Global state for stateful tests
from collections import defaultdict
GLOBAL_HISTORY = defaultdict(list)
GLOBAL_LAST_SEEN = {}

def run_test_case(name: str, events: List[Dict[str, Any]], expected: Dict[str, Any], t_now: datetime.datetime = None):
    print(f"\n[TEST] {name}")
    global GLOBAL_HISTORY, GLOBAL_LAST_SEEN
    
    if t_now is None:
        t_now = datetime.datetime.now(datetime.timezone.utc)

    df = pd.DataFrame(events)
    if not df.empty:
        if "event_time" not in df.columns:
            df["event_time"] = t_now
        df["event_time"] = pd.to_datetime(df["event_time"], utc=True)
        if "event_id" not in df.columns:
            df["event_id"] = 1
        df["event_id"] = df["event_id"].astype(int)
        
    # 1. Sequence Engine
    seq_engine = SequenceEngine()
    seq_hits = seq_engine.process_dataframe(df)
    
    # 2. Scoring Engine
    scorer = ScoringEngine()
    scorer.history = GLOBAL_HISTORY
    scorer.last_seen = GLOBAL_LAST_SEEN

    burst = events[0].copy()
    burst["burst_id"] = str(uuid.uuid4())
    burst["count"] = len(events)
    burst["kill_chain_stage"] = "Execution"
    
    # Basic rule mocks
    detections = []
    if "-enc" in str(burst.get("command_line", "")):
        detections.append({"rule_id": "DET-001", "rule_name": "Encoded PowerShell", "confidence": 85, "severity": "high"})
    if "schtasks" in str(burst.get("image", "")):
        detections.append({"rule_id": "DET-010", "rule_name": "Task Persistence", "confidence": 90, "severity": "critical"})

    chain_depth = len(set(e.get("image") for e in events))
    if seq_hits:
        chain_depth = max(chain_depth, 2)

    res = scorer.score_burst(
        burst,
        detections=detections,
        sequence_detections=seq_hits,
        chain_depth=chain_depth,
        now=t_now
    )
    
    score = res.score
    print(f"Score: {score:.1f}")
    
    # Update global state for next tests
    GLOBAL_HISTORY = scorer.history
    GLOBAL_LAST_SEEN = scorer.last_seen

    # --- ASSERTIONS ---
    if "min_score" in expected:
        assert score >= expected["min_score"], f"❌ Score too low: {score}"
    if "max_score" in expected:
        assert score <= expected["max_score"], f"❌ Score too high: {score}"
    if expected.get("expect_sequence"):
        assert len(seq_hits) > 0, "❌ Missing sequence detection"
    
    print("✅ PASS")

def test_benign():
    events = [
        {"image": "explorer.exe", "parent_image": "winlogon.exe", "user": "LOKI", "computer": "WKSTN01"},
        {"image": "notepad.exe", "parent_image": "explorer.exe", "user": "LOKI", "computer": "WKSTN01"},
    ]
    run_test_case("Benign Activity", events, {"max_score": 30})

def test_lolbin_floor():
    events = [
        {"image": "powershell.exe", "command_line": "powershell", "user": "LOKI", "computer": "WKSTN01"}
    ]
    run_test_case("LOLBIN Floor", events, {"min_score": 25})

def test_quiet_attack():
    events = [
        {
            "image": "powershell.exe",
            "parent_image": "winword.exe",
            "user": "LOKI",
            "computer": "WKSTN01",
            "command_line": "powershell -enc aGVsbG8=",
            "cmd_has_encoded_flag": True
        }
    ]
    run_test_case("Quiet Attack", events, {"min_score": 75})

def test_sequence():
    events = [
        {"image": "winword.exe", "event_id": 1, "computer": "WKSTN01"},
        {"image": "powershell.exe", "parent_image": "winword.exe", "event_id": 1, "computer": "WKSTN01"},
        {"image": "schtasks.exe", "parent_image": "powershell.exe", "command_line": "/create", "event_id": 1, "computer": "WKSTN01"},
    ]
    run_test_case("Attack Chain", events, {"min_score": 70, "expect_sequence": True})

def test_accumulation():
    # Reset history for clear test
    global GLOBAL_HISTORY, GLOBAL_LAST_SEEN
    GLOBAL_HISTORY = defaultdict(list)
    GLOBAL_LAST_SEEN = {}
    
    t0 = datetime.datetime.now(datetime.timezone.utc)
    for i in range(3):
        t_current = t0 + datetime.timedelta(minutes=10 * i)
        run_test_case(f"Accumulation Step {i+1}", [
            {"image": "powershell.exe", "command_line": "powershell -enc aGVsbG8=", "cmd_has_encoded_flag": True, "user": "LOKI", "computer": "WKSTN01", "parent_image": "explorer.exe"}
        ], {"min_score": 45}, t_now=t_current)

def test_session_reset():
    t0 = datetime.datetime.now(datetime.timezone.utc)
    # Already have accumulation from test_accumulation
    t_later = t0 + datetime.timedelta(hours=2)
    run_test_case("Session Reset after 2h", [
        {"image": "powershell.exe", "command_line": "powershell -enc aGVsbG8=", "cmd_has_encoded_flag": True, "user": "LOKI", "computer": "WKSTN01", "parent_image": "explorer.exe"}
    ], {"max_score": 50}, t_now=t_later)

def test_false_positive():
    events = [
        {
            "image": "powershell.exe",
            "command_line": "powershell -File backup.ps1",
            "user": "ADMIN",
            "computer": "WKSTN01",
            "parent_image": "services.exe"
        }
    ]
    run_test_case("Admin Script", events, {"max_score": 60})

if __name__ == "__main__":
    try:
        test_benign()
        test_lolbin_floor()
        test_quiet_attack()
        test_sequence()
        test_accumulation()
        test_session_reset()
        test_false_positive()
        print("\n🔥 ALL TESTS PASSED")
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 ERROR: {e}")
        sys.exit(1)
