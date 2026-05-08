
import unittest
import sys
import os
import json
import time
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath('.'))

from dashboard.analysis_cache import set_analysis_snapshot, get_analysis_snapshot, _ANALYSIS_STORE
from dashboard.scoring_engine import get_scoring_engine
from dashboard.analysis_engine import run_full_analysis
import pandas as pd

class TestSentinelHardening(unittest.TestCase):
    
    def setUp(self):
        _ANALYSIS_STORE.clear()

    def test_cache_mutation_safety(self):
        """Verify that get_analysis_snapshot returns a deep copy (9.6/10 requirement)."""
        run_id = "test_mutation"
        original = {
            "timeline": [{"id": 1}],
            "attack_narrative": {"summary": "Original"}
        }
        set_analysis_snapshot(run_id, original)
        
        # Get first copy
        snap1 = get_analysis_snapshot(run_id)
        # Mutate it
        snap1["timeline"].append({"id": 2})
        snap1["attack_narrative"]["summary"] = "Mutated"
        
        # Get second copy
        snap2 = get_analysis_snapshot(run_id)
        
        # Verify snap2 is still original
        self.assertEqual(len(snap2["timeline"]), 1)
        self.assertEqual(snap2["attack_narrative"]["summary"], "Original")
        print("✅ Cache mutation safety verified.")

    def test_scoring_zero_signal(self):
        """Verify clean zero-signal return in scoring engine."""
        engine = get_scoring_engine()
        # Empty signals (detections=[], sequence_detections=[], behavior_score=0.0)
        res = engine.score_burst({}, [], [], behavior_score=0.0)
        self.assertEqual(res.score, 0.0)
        self.assertEqual(res.primary_driver, "benign")
        print("✅ Scoring zero-signal integrity verified.")

    def test_engine_empty_data_fallback(self):
        """Verify engine handles empty event data gracefully."""
        run_id = "test_empty"
        # Mock DB job claiming
        import pandas as pd
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = {"status": "ANALYZING", "analysis_version": 1}
        
        with patch('dashboard.analysis_engine.get_db_connection', return_value=mock_conn):
            with patch('dashboard.analysis_engine.get_cursor', return_value=MagicMock(__enter__=lambda x: mock_cur)):
                with patch('dashboard.analysis_engine.load_events', return_value=pd.DataFrame(columns=['event_time'])):
                    with patch('dashboard.analysis_engine._transition_state'):
                        with patch('dashboard.analysis_engine.set_analysis_snapshot'):
                            with patch('dashboard.analysis_engine.checked_insert'):
                                res = run_full_analysis(run_id)
                                print(f"DEBUG: empty_data_fallback result keys: {list(res.keys())}")
                                self.assertEqual(res.get("status"), "complete")
                                self.assertEqual(res["attack_narrative"]["summary"], "No data available")
        print("✅ Engine empty data fallback verified.")

    def test_engine_global_failsafe(self):
        """Verify engine preserves partial context on fatal crash."""
        run_id = "test_crash"
        # Force crash in the middle (e.g. at _build_bursts or scoring)
        # Mock DB job claiming
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = {"status": "ANALYZING", "analysis_version": 1}

        with patch('dashboard.analysis_engine.get_db_connection', return_value=mock_conn):
            with patch('dashboard.analysis_engine.get_cursor', return_value=MagicMock(__enter__=lambda x: mock_cur)):
                with patch('dashboard.analysis_engine.load_events', return_value=pd.DataFrame({'a': [1]})):
                     with patch('dashboard.analysis_engine._transition_state'):
                         with patch('dashboard.analysis_engine._build_bursts', side_effect=Exception("FATAL CRASH")):
                            res = run_full_analysis(run_id)
                            print(f"DEBUG: global_failsafe result keys: {list(res.keys())}")
                            self.assertEqual(res.get("status"), "failed")
                            self.assertEqual(res["attack_narrative"]["summary"], "Analysis partially failed")
        print("✅ Engine global failsafe verified.")

if __name__ == "__main__":
    unittest.main()
