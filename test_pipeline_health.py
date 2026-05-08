import unittest
from decimal import Decimal
from dashboard.pipeline import run_full_pipeline
import pandas as pd

class TestPipelineHealth(unittest.TestCase):
    def test_system_health_dampening(self):
        # Mock context and bursts
        ctx = {
            "burst_aggregates": [
                {"system_health": 50, "peak_score": 80, "behavior_score": 0.8}, # Low health
                {"system_health": 100, "peak_score": 80, "behavior_score": 0.8} # Good health
            ],
            "detections": [{"confidence": 100, "type": "rule"}],
            "analysis_integrity": {"rule": "OK", "sequence": "OK", "correlation": "OK"},
            "baseline_execution_context": [i for i in range(200)] # Maturity boost
        }
        
        # Run pipeline
        # Note: run_full_pipeline expects events_df and detections_df
        # We can bypass expensive parts by providing empty DFs if we mock enough of ctx
        res = run_full_pipeline(pd.DataFrame(), pd.DataFrame(), "test_run", ctx)
        
        conf = res.get("confidence_score")
        print(f"DEBUG: confidence_score={conf}")
        
        # Without health issues, confidence would be ~100.
        # With 1/2 bursts at low health, ratio = 0.5.
        # penalty = 0.9 - (0.1 * 0.5) = 0.85
        # Expected confidence around 85 (or slightly less depending on other factors)
        self.assertLess(conf, 95)
        self.assertGreater(conf, 50)

if __name__ == "__main__":
    unittest.main()
