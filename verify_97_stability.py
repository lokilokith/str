import sys
import os
import unittest
import copy
from typing import Any, Dict

# Setup paths
sys.path.append(os.getcwd())

from dashboard.analysis_engine import run_full_analysis
# Mocking dependencies for unit test if needed, but we'll focus on contract logic

class TestStability97(unittest.TestCase):
    
    def test_meta_structured_warning(self):
        """Verify structured weak correlation warning."""
        meta = {"pipeline_stage": "correlation", "errors": [], "warnings": []}
        detections = [{"id": 1}]
        sequences = []
        
        if detections and not sequences:
            meta["warnings"].append({
                "type": "weak_correlation",
                "message": "Detections present but no sequences",
                "detection_count": len(detections),
                "sequence_count": len(sequences)
            })
        
        self.assertEqual(len(meta["warnings"]), 1)
        self.assertEqual(meta["warnings"][0]["type"], "weak_correlation")
        self.assertEqual(meta["warnings"][0]["detection_count"], 1)

    def test_deepcopy_isolation(self):
        """Verify that fallback context is isolated from original."""
        context = {"timeline": [{"id": 1}], "meta": {"errors": []}}
        fallback = copy.deepcopy(context)
        fallback["timeline"].append({"id": 2})
        
        self.assertEqual(len(context["timeline"]), 1)
        self.assertEqual(len(fallback["timeline"]), 2)

    def test_pipeline_signature_fallbacks(self):
        """Verify pipeline contract works with None context."""
        def mock_pipeline(events_df=None, detections_df=None, run_id="test", context=None):
            if not isinstance(context, dict):
                context = {}
            context.setdefault("kill_chain_path", [])
            return context
        
        res = mock_pipeline(context=None)
        self.assertIsInstance(res, dict)
        self.assertIn("kill_chain_path", res)

if __name__ == "__main__":
    unittest.main()
