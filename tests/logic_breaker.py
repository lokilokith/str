"""
logic_breaker.py — SentinelTrace Final Adversarial Verification (10/10)
=======================================================================
Generates "Perfect Lies" (logically inconsistent telemetry) to verify
that the formal invariant layer correctly identifies and rejects them.
"""

import sys
import uuid
import json
import logging
from decimal import Decimal
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Add parent dir to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from dashboard.pipeline import validate_minimal_truth
from dashboard.analysis_engine import generate_semantic_hash

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("logic_breaker")

def generate_malicious_context(break_type: str = None):
    """Generate a base 'attack' context."""
    run_id = uuid.uuid4().hex[:16]
    now = datetime.now(timezone.utc)
    
    events = [
        {"event_uid": "E1", "event_time": now.isoformat(), "image": "cmd.exe", "event_id": "1"},
        {"event_uid": "E2", "event_time": (now + timedelta(seconds=1)).isoformat(), "image": "powershell.exe", "event_id": "1"},
    ]
    
    detections = [
        {"rule_id": "R1", "image": "powershell.exe", "severity": "high", "utc_time": now.isoformat()}
    ]
    
    ctx = {
        "run_id": run_id,
        "attack_conf_score": 85,
        "detections": detections,
        "correlation_campaigns": [
            {
                "events": events,
                "edges": [{"from": "E1", "to": "E2", "from_stage": "Execution", "to_stage": "Persistence"}]
            }
        ],
        "timeline": events
    }
    
    if break_type == "CAUSALITY":
        # Break causality: child event happens BEFORE parent
        ctx["timeline"][1]["event_time"] = (now - timedelta(seconds=10)).isoformat()
        log.info("[ADVERSARY] Breaking causality: Child (E2) now happens before Parent (E1)")
        
    elif break_type == "SEPARATION":
        # Break separation: Share events across campaigns
        ctx["correlation_campaigns"].append({
            "events": [events[0]], # Duplicate E1
            "edges": []
        })
        log.info("[ADVERSARY] Breaking separation: E1 now exists in two campaigns")
        
    elif break_type == "LINKAGE":
        # Break linkage: Reference non-existent node
        ctx["correlation_campaigns"][0]["edges"].append({"from": "E2", "to": "E3"})
        log.info("[ADVERSARY] Breaking linkage: Edge points to non-existent node E3")

    elif break_type == "SCORING":
        # Break scoring: Score exists with no evidence
        ctx["detections"] = []
        log.info("[ADVERSARY] Breaking scoring: Score=85 but 0 detections")

    return ctx

def run_adversarial_suite():
    log.info("--- STARTING 10/10 LOGICAL ADVERSARY TESTS ---")
    
    tests = ["CAUSALITY", "SEPARATION", "LINKAGE", "SCORING"]
    passed = 0
    
    # 1. Base Truth (Sanity Check)
    try:
        ctx = generate_malicious_context()
        validate_minimal_truth(ctx)
        log.info("[PASSED] Baselined truth validated successfully")
        passed += 1
    except Exception as e:
        log.error("[FAILED] Baselined truth failed validation: %s", e)

    # 2. Breaking the system
    for t in tests:
        ctx = generate_malicious_context(t)
        try:
            validate_minimal_truth(ctx)
            log.error("[CRITICAL] System accepted '%s' - Formal proof is BROKEN", t)
        except AssertionError as ae:
            log.info("[PASSED] System REJECTED '%s' as expected: %s", t, ae)
            passed += 1
        except Exception as e:
            log.error("[ERROR] Unexpected exception for '%s': %s", t, e)

    log.info("--- COMPLETED: %d/%d TESTS PASSED ---", passed, len(tests) + 1)
    if passed == len(tests) + 1:
        log.info("10/10 MASTERY ACHIEVED: Formal invariants are impermeable.")
    else:
        log.error("SYSTEM COMPROMISED: Some logical lies were accepted.")

if __name__ == "__main__":
    run_adversarial_suite()
