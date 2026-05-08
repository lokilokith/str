import unittest
import pandas as pd
from dashboard.baseline_engine import EntityProfile, BaselineEngine

class TestLogicFixes(unittest.TestCase):
    def test_score_unification(self):
        # Verify behavior_score >= deviation_score * 0.8
        engine = BaselineEngine()
        # Mock a profile
        profile = EntityProfile()
        profile.exec_stats.n = 50
        profile.exec_stats.mean = 10
        profile.exec_stats.m2 = 100 # variance = 100/49 ~= 2, std ~= 1.4
        
        # event with high deviation but low behavioral signal (manually mocked)
        event = {
            "computer": "host-01", "user": "SYSTEM", "image": "cmd.exe",
            "exec_count": 50, # z-score = (50-10)/1.4 = 28 -> score 1.0
            "cmd_entropy": 1.0, # Low entropy
            "is_known_benign": True
        }
        engine._profiles[("host-01", "system", "cmd.exe")] = profile
        
        res = engine.score_event(event)
        dev = res["deviation_score"]
        beh = res["behavior_score"]
        
        print(f"DEBUG: deviation={dev}, behavior={beh}")
        self.assertGreaterEqual(beh, dev * 0.8 - 0.001)

    def test_learning_hardening(self):
        engine = BaselineEngine()
        event = {"risk_score": 20, "image": "calc.exe"}
        
        # Test deviation threshold (0.25)
        self.assertFalse(engine.should_learn(event, 0.30))
        self.assertTrue(engine.should_learn(event, 0.10))
        
        # Test behavior threshold (0.5)
        event["behavior_score"] = 0.6
        self.assertFalse(engine.should_learn(event, 0.10))
        event["behavior_score"] = 0.1
        self.assertTrue(engine.should_learn(event, 0.10))

    def test_slow_attack_penalty(self):
        engine = BaselineEngine()
        profile = EntityProfile()
        profile.exec_stats.n = 100
        profile.exec_stats.mean = 100
        # low frequency (1 exec), but high other signals
        event = {
            "computer": "host-01", "image": "powershell.exe",
            "exec_count": 1,
            "cmd_entropy": 6.0, # high entropy
            "has_persistence": True,
            "has_injection": True, # Ensure high_signals_count >= 2
            "is_known_benign": False
        }
        engine._profiles[("host-01", "interactive", "powershell.exe")] = profile
        
        res = engine.score_event(event)
        # Should have slow_attack_penalty applied
        anomalies = " ".join(res["anomalies"])
        self.assertIn("Slow/stealthy attack", anomalies)
        
        # Test is_known_benign gate
        event["is_known_benign"] = True
        res_benign = engine.score_event(event)
        anomalies_benign = " ".join(res_benign["anomalies"])
        self.assertNotIn("Slow/stealthy attack", anomalies_benign)

if __name__ == "__main__":
    unittest.main()
