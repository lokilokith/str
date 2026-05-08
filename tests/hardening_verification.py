
import sys
import os
import pandas as pd
import datetime
import unittest
from unittest.mock import MagicMock, patch

# Add path
sys.path.append(os.getcwd())

from dashboard.analysis_engine import match_detection_to_burst
from dashboard.feedback_engine import apply_feedback_adjustment
from dashboard.soc_verdict import validate_transition

class TestHardening(unittest.TestCase):

    # --- MATCHER TESTS (10/10 Lock) ---
    def test_matcher_host_isolation(self):
        """Test 1: Host Isolation (Non-negotiable)"""
        det = {"computer": "WKSTN-A", "process_id": 1234, "utc_time": "2026-03-26T12:00:00Z"}
        burst = {"computer": "WKSTN-B", "process_id": 1234, "start_time": "2026-03-26T12:00:00Z"}
        self.assertFalse(match_detection_to_burst(det, burst), "FAILED: Matcher failed host isolation")

    def test_matcher_pid_time_lock(self):
        """Test 2: PID + Time Hard Constraint"""
        det = {"computer": "WKSTN-A", "process_id": 1234, "utc_time": "2026-03-26T12:00:00Z"}
        
        # Exact match
        burst_exact = {"computer": "WKSTN-A", "process_id": 1234, "start_time": "2026-03-26T12:00:00Z"}
        self.assertTrue(match_detection_to_burst(det, burst_exact), "FAILED: Matcher failed exact PID+Time match")

        # Outside 5s window
        burst_late = {"computer": "WKSTN-A", "process_id": 1234, "start_time": "2026-03-26T12:00:10Z"}
        # Note: Scored fallback might still pick it up if other fields match, 
        # but the hard PID+Time branch should fail here.
        # Let's ensure PID+Time alone doesn't trigger it if outside 5s.
        res = match_detection_to_burst(det, burst_late)
        self.assertFalse(res, "FAILED: Matcher allowed >5s drift for same PID")

    def test_matcher_scored_fallback(self):
        """Test 3: Scored Fallback Logic (Threshold >= 5)"""
        # Scenario: PID changed, but Image + Parent + Rule match
        det = {
            "computer": "WKSTN-A", 
            "process_id": 1111, 
            "image": "powershell.exe", 
            "parent_image": "winword.exe",
            "rule_id": "ST-001",
            "utc_time": "2026-03-26T12:00:00Z"
        }
        burst = {
            "computer": "WKSTN-A", 
            "process_id": 2222, 
            "image": "powershell.exe", 
            "parent_image": "winword.exe",
            "rule_id": "ST-001",
            "start_time": "2026-03-26T12:00:00Z"
        }
        # Score calculation: Rule(3) + Parent(2) + Image(2) = 7 (>= 5)
        self.assertTrue(match_detection_to_burst(det, burst), "FAILED: Scored fallback failed high-fidelity match")

        # Scenario: PID changed, only Image matches
        burst_weak = {
            "computer": "WKSTN-A", 
            "process_id": 3333, 
            "image": "powershell.exe", 
            "parent_image": "explorer.exe",
            "rule_id": "OTHER",
            "start_time": "2026-03-26T12:00:00Z"
        }
        # Score: Image(2) = 2 (< 5)
        self.assertFalse(match_detection_to_burst(det, burst_weak), "FAILED: Matcher allowed weak single-field match")

    # --- FEEDBACK TESTS (10/10 Lock) ---
    def test_feedback_clamp(self):
        """Test 4: Suppression Adjustment Clamp [-20, 15]"""
        # Create a rule with -50 adjustment
        sup = [{"image": "sys.exe", "kill_chain_stage": "Background", "confidence_adj": -50, "verdict": "FP"}]
        burst = {"image": "sys.exe", "kill_chain_stage": "Background"}
        
        adj, _ = apply_feedback_adjustment(burst, sup)
        self.assertEqual(adj, -20, f"FAILED: Feedback clamp failed (got {adj}, expected -20)")

    def test_feedback_high_risk_strictness(self):
        """Test 5: High-Risk Stage Strict Matching"""
        # Scenario: Credential Access suppression rule for 'mimikatz.exe'
        sup = [{
            "image": "mimi.exe", 
            "kill_chain_stage": "Credential Access", 
            "confidence_adj": -20, 
            "rule_id": "RULE-1",
            "verdict": "FP"
        }]
        
        # Burst: same image and stage, but NO rule ID match
        burst = {"image": "mimi.exe", "kill_chain_stage": "Credential Access", "rule_id": "RULE-DIFF"}
        adj, _ = apply_feedback_adjustment(burst, sup)
        self.assertEqual(adj, 0, "FAILED: High-risk stage suppressed without exact rule match")

        # Burst: exact match
        burst_exact = {"image": "mimi.exe", "kill_chain_stage": "Credential Access", "rule_id": "RULE-1"}
        adj_ok, _ = apply_feedback_adjustment(burst_exact, sup)
        self.assertEqual(adj_ok, -20, "FAILED: High-risk stage failed to suppress with exact rule match")

    # --- STATE MACHINE TESTS (10/10 Lock) ---
    def test_state_transitions(self):
        """Test 6: SOC State Machine Transitions"""
        # Valid moves
        self.assertTrue(validate_transition("New", "Triage")[0])
        self.assertTrue(validate_transition("Triage", "Investigating")[0])
        
        # Invalid moves
        self.assertFalse(validate_transition("New", "Escalated")[0], "FAILED: Security bypassed - New directly to Escalated")
        self.assertFalse(validate_transition("Triage", "Closed - True Positive")[0], "FAILED: Triage closed as TP without investigation")

if __name__ == "__main__":
    unittest.main()
