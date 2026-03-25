
import sys
import os
import pandas as pd
import datetime
from typing import Any, Dict, List
import uuid
from collections import defaultdict

# Add directory to path
sys.path.append(os.getcwd())

from dashboard.scoring_engine import ScoringEngine
from dashboard.sequence_engine import SequenceEngine

# Global state for stateful tests
GLOBAL_HISTORY = defaultdict(list)
GLOBAL_LAST_SEEN = {}
GLOBAL_CAMPAIGN = defaultdict(set)

def run_test_case(name: str, events: List[Dict[str, Any]], expected: Dict[str, Any], t_now: datetime.datetime = None):
    print(f"\n[TEST] {name}")
    global GLOBAL_HISTORY, GLOBAL_LAST_SEEN, GLOBAL_CAMPAIGN
    
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
    scorer.global_user_history = GLOBAL_CAMPAIGN

    burst = events[0].copy()
    burst["burst_id"] = str(uuid.uuid4())
    burst["count"] = len(events)
    burst["kill_chain_stage"] = "Execution"
    
    # Basic rule mocks
    detections = []
    cmd = str(burst.get("command_line", "")).lower()
    if "-enc" in cmd or "-e " in cmd:
        detections.append({"rule_id": "DET-001", "rule_name": "Encoded PowerShell", "confidence": 85, "severity": "high"})
    if "schtasks" in str(burst.get("image", "")):
        detections.append({"rule_id": "DET-010", "rule_name": "Task Persistence", "confidence": 90, "severity": "critical"})
    if "psexec" in str(burst.get("image", "")):
        detections.append({"rule_id": "DET-020", "rule_name": "Remote Execution Tool", "confidence": 80, "severity": "high"})

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
    GLOBAL_CAMPAIGN = scorer.global_user_history

    # --- ASSERTIONS ---
    if "min_score" in expected:
        assert score >= expected["min_score"], f"❌ Score too low: {score}"
    if "max_score" in expected:
        assert score <= expected["max_score"], f"❌ Score too high: {score}"
    if expected.get("expect_sequence"):
        assert len(seq_hits) > 0, "❌ Missing sequence detection"
    
    print("✅ PASS")

def test_benign():
    events = [{"image": "explorer.exe", "user": "LOKI", "computer": "WKSTN01"}]
    run_test_case("Benign Activity", events, {"max_score": 30})

def test_quiet_attack():
    events = [{"image": "powershell.exe", "parent_image": "winword.exe", "user": "LOKI", "computer": "WKSTN01", "command_line": "powershell -enc aGVsbG8=", "cmd_has_encoded_flag": True}]
    run_test_case("Quiet Attack", events, {"min_score": 75})

def test_accumulation():
    # Reset for clean test
    global GLOBAL_HISTORY, GLOBAL_LAST_SEEN, GLOBAL_CAMPAIGN
    GLOBAL_HISTORY = defaultdict(list)
    GLOBAL_LAST_SEEN = {}
    GLOBAL_CAMPAIGN = defaultdict(set)
    
    t0 = datetime.datetime.now(datetime.timezone.utc)
    for i in range(3):
        t_current = t0 + datetime.timedelta(minutes=10 * i)
        run_test_case(f"Accumulation Step {i+1}", [
            {"image": "powershell.exe", "command_line": "powershell -enc ZzZ6", "cmd_has_encoded_flag": True, "user": "LOKI", "computer": "WKSTN01", "parent_image": "explorer.exe"}
        ], {"min_score": 48}, t_now=t_current)

def test_lateral_movement():
    print("\n--- Lateral Movement Test ---")
    # Step 1: User runs psexec on Host A
    run_test_case("Host A Launch", [
        {"image": "psexec.exe", "user": "ADMIN", "computer": "WKSTN01", "parent_image": "cmd.exe"}
    ], {"min_score": 25})
    
    # Step 2: Same user runs same psexec on Host B (Campaign detection)
    run_test_case("Host B Launch (Lateral)", [
        {"image": "psexec.exe", "user": "ADMIN", "computer": "WKSTN02", "parent_image": "cmd.exe"}
    ], {"min_score": 40}) # Should be higher due to campaign bonus

def test_evasion_resilience():
    print("\n--- Evasion Resilience Test ---")
    # PowerShell obfuscated with backticks and spaced Base64
    events = [
        {"image": "p`o`w`e`r`s`h`e`l`l.exe", "command_line": "powershell -enc Z m 9 v", "user": "LOKI", "computer": "WKSTN01"}
    ]
    # This should still be seen as an 'encoded powershell' due to normalization
    run_test_case("Obfuscated Launch", events, {"min_score": 25})

if __name__ == "__main__":
    try:
        test_benign()
        test_quiet_attack()
        test_accumulation()
        test_lateral_movement()
        test_evasion_resilience()
        print("\n🔥 10/10 CERTIFICATION PASSED")
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 ERROR: {e}")
        sys.exit(1)
