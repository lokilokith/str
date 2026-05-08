import math
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
import datetime


log = logging.getLogger(__name__)

# --- SOC-Grade Configuration (v2.8) ---
# Absolute hierarchy: Burst -> Campaign -> Global NO FEEDBACK
TRUSTED_PARENTS = {
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "wininit.exe",
    "lsass.exe",
    "smss.exe",
    "csrss.exe",
    "winlogon.exe"
}

@dataclass
class LedgerEntry:
    label: str
    delta: float
    explanation: str
    category: str = "general"

    def to_dict(self):
        return {
            "label": self.label,
            "delta": round(self.delta, 2),
            "reason": self.explanation,
            "category": self.category
        }

@dataclass
class ScoreResult:
    score: float
    ledger: List[LedgerEntry] = field(default_factory=list)
    confidence_modifier: float = 1.0
    primary_driver: str = "rule"
    severity: str = "low"
    
    def __post_init__(self):
        # SOC-Grade Severity Mapping (relaxed thresholds for real-world attack elevation)
        if self.score >= 70.0: self.severity = "high"
        elif self.score >= 40.0: self.severity = "medium"
        elif self.score > 0: self.severity = "low"
        else: self.severity = "informational"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "primary_driver": self.primary_driver,
            "confidence_modifier": self.confidence_modifier,
            "ledger": [e.to_dict() for e in self.ledger],
            "why": [f"• {e.label}: {e.explanation}" for e in self.ledger if abs(e.delta) > 0.1]
        }

class ScoringEngine:
    """
    Production-grade Unified Risk Engine (v2.8).
    Implements contribution-based labeling, stability-locking, and adversarial resilience.
    """
    def __init__(self):
        # Local state-based tracking for accumulation (ephemeral per session)
        self.history = {} # host -> {image: [timestamps]}
        self.last_seen = {} # host -> {image: last_time}
        self.global_user_history = {} # user -> {computers}

    def score_burst(self, burst: Dict[str, Any], detections: List[Dict[str, Any]], 
                    sequence_detections: List[Dict[str, Any]] = None,
                    behavior_score: float = None,
                    chain_depth: int = 1,
                    now: datetime.datetime = None) -> ScoreResult:
        """
        Calculates a SOC-grade risk score (0-100) using multi-signal fusion.
        """
        if now is None:
            now = datetime.datetime.now(datetime.timezone.utc)
            
        ledger = []
        image = str(burst.get("image") or "unknown").lower()
        computer = str(burst.get("computer") or "unknown").lower()
        user = str(burst.get("user") or "unknown").lower()
        parent_image = str(burst.get("parent_image") or "").lower()
        
        # ── 1. BASE SIGNALS (Static Rule Weights) ──
        rule_score = 0.0
        for det in (detections or []):
            conf = float(det.get("confidence") or det.get("confidence_score") or 50)
            sev = str(det.get("severity") or "medium").lower()
            
            # Graded severity weight
            sev_weight = 1.0
            if sev == "critical": sev_weight = 1.8
            elif sev == "high": sev_weight = 1.5
            elif sev == "medium": sev_weight = 1.0
            elif sev == "low": sev_weight = 0.6
            
            delta = (conf / 2.0) * sev_weight
            rule_score += delta
            ledger.append(LedgerEntry(f"Rule: {det.get('rule_name')}", delta, f"Static detection {det.get('rule_id', 'N/A')}", "rule"))

        # ── 2. SEQUENCE SIGNALS (DOMINANT — strongest SOC signal) ──
        sequence_score = 0.0
        for seq in (sequence_detections or []):
            s_conf = float(seq.get("confidence", 50))
            delta = s_conf * 0.8
            sequence_score += delta
            ledger.append(LedgerEntry(f"Sequence: {seq.get('sequence_type')}", delta, "Attack pattern match", "sequence"))

            if s_conf >= 80:
                ledger.append(LedgerEntry(
                    "High-confidence attack chain",
                    20.0,
                    "Strong sequence detection override",
                    "sequence"
                ))
                sequence_score += 20.0

        # ── 3. BEHAVIORAL INTELLIGENCE (BASELINE ENGINE) ──
        if behavior_score is None:
            behavior_score = float(burst.get("behavior_score", 0.0))
        
        samples = int(burst.get("baseline_maturity", 0))
        
        # Direct behavior boost (no stability dependency — consistent across environments)
        behavior_boost = behavior_score * 40.0
        if behavior_score > 0.8:
            behavior_boost += 5.0
            
        if behavior_boost > 0.1:
            label = "Behavioral anomaly"
            if behavior_score > 0.7: label += " (HIGH)"
            ledger.append(LedgerEntry(label, behavior_boost, f"Anomalous execution profile (deviance {behavior_score:.2f})", "behavior"))

        # ── [9.6/10 Locked] Zero-Signal Integrity ───────────────────────────
        if rule_score == 0 and sequence_score == 0 and behavior_score == 0:
            return ScoreResult(
                score=0.0,
                ledger=[LedgerEntry("No detection signals", 0.0, "Baseline activity", "fallback")],
                primary_driver="benign"
            )

        # ── 4. RARITY & FIRST-SEEN (CONTEXTUAL) ──
        baseline_stats = burst.get("baseline_stats", {})
        host_stats = baseline_stats.get(computer, {})
        image_freq = int(host_stats.get(image, {}).get("count", 1))
        
        # Smooth Logarithmic Rarity Weight
        rarity_weight = 1.5 - (math.log10(max(1, image_freq) + 1) * 0.3)
        rarity_weight = max(0.6, min(1.5, rarity_weight))
        
        rarity_boost = 0.0
        if image_freq <= 3:
            rarity_boost = 10.0 * (1.5 - (image_freq * 0.1))
            ledger.append(LedgerEntry("Rare process context", rarity_boost, f"{image} seen {image_freq} times on host", "rarity"))
        elif image_freq > 100:
            ledger.append(LedgerEntry("Common process dampener", -5.0, f"{image} very common ({image_freq} executions)", "rarity"))

        # Conditional First-Seen execution (v2.8)
        first_seen_boost = 0.0
        if image_freq == 1 and behavior_score > 0.4:
            first_seen_boost = 10.0
            ledger.append(LedgerEntry("First-seen execution", 10.0, f"{image} executed for first time on host in suspicious context", "rarity"))

        # ── 5. CORRELATION AMPLIFICATION (CAMPAIGNS) ──
        corr_strength = max(0, float(burst.get("correlation_strength", 0.0)))
        corr_size = max(1, int(burst.get("correlation_size", 1)))
        
        # Nonlinear Capped Correlation (v3.0 — doubled weight for campaign visibility)
        corr_boost = (math.sqrt(corr_strength) * 4.0) * min(1.5, math.log2(corr_size + 1))
        corr_boost = min(35.0, corr_boost)
        
        if corr_boost > 5.0:
            ledger.append(LedgerEntry("Campaign correlation", corr_boost, f"Linked to {corr_size} events (strength {corr_strength:.0f})", "correlation"))

        # ── 6. ADVERSARIAL RESILIENCE (STEALTH RULE) ──
        parent_trust = 0.9 if parent_image in TRUSTED_PARENTS else 0.1
        stealth_boost = 0.0
        
        # Micro-Lock: Gated by behavior + count + entropy + maturity + trust
        if (behavior_score > 0.75 and 
            int(burst.get("event_count", 0)) <= 5 and 
            (float(burst.get("cmd_entropy", 0)) > 4.0 or burst.get("has_encoded_flag") or float(burst.get("sequence_anomaly", 0)) > 0.7) and
            samples > 5 and 
            parent_trust < 0.5):
            
            stealth_boost = 15.0
            ledger.append(LedgerEntry("Stealth (Slow-Drip) Detection", 15.0, "Multi-dimensional stealth pattern match", "stealth"))

        # ── 7. ENVIRONMENT DRIFT ──
        drift = float(burst.get("host_baseline_drift", 0.0))
        drift_boost = 0.0
        if drift > 0.3:
            drift_boost = 10.0
            ledger.append(LedgerEntry("Environment drift", 10.0, "Host baseline behavior significantly changed recently", "behavior"))

        # ── 8. COMPOSITE INTEGRATION (Non-multiplicative Rarity v3.0) ──

        # Early LOLBin suspicious-context boost (MUST be before base_signals)
        image_name = image.split("\\")[-1]
        if image_name in ["powershell.exe", "cmd.exe", "wscript.exe"]:
            if burst.get("has_encoded_flag") or chain_depth >= 2:
                sequence_score += 10.0
                ledger.append(LedgerEntry(
                    "Suspicious LOLBin usage",
                    10.0,
                    f"{image_name} used in suspicious context",
                    "rule"
                ))

        base_signals = rule_score + sequence_score + behavior_boost + corr_boost + stealth_boost + drift_boost
        
        event_count = int(burst.get("event_count") or 1)
        chain_factor = 1.0 + min(0.35, max(1, chain_depth) * 0.1)
        
        core_score = base_signals * chain_factor + (event_count * 0.5)
        rarity_component = (rarity_boost + first_seen_boost) * rarity_weight
        
        final = core_score + rarity_component

        # ── CHAIN DEPTH BOOST (multi-stage attack amplifier) ──
        if chain_depth >= 3:
            final += 15.0
            ledger.append(LedgerEntry(
                "Multi-stage attack",
                15.0,
                f"Attack chain depth = {chain_depth}",
                "sequence"
            ))
        
        # ── 9. MATURITY & SOFT-START (v2.8) ──
        conf_mod = 1.0
        if samples < 5:
            penalty = 0.85
            conf_mod = 0.8  # Uncertainty flag for new hosts
            ledger.append(LedgerEntry("Confidence Dampener", 0.0, "Low host maturity (<5 samples) — reducing detection confidence", "baseline"))
        else:
            penalty = 1.0 - (0.015 * max(0, 20 - samples))
            
        final *= max(0.75, penalty)

        # ── 10. OVERRIDES & FLOORS (LOLBIN GUARD) ──
        final = min(99.0, final)

        lolbin_floor = 0.0
        if image_name in ["powershell.exe", "pwsh.exe"]: lolbin_floor = 45.0
        elif image_name in ["cmd.exe", "wscript.exe", "cscript.exe"]: lolbin_floor = 40.0
        
        if lolbin_floor > 0 and final < lolbin_floor:
            # Only floor if there is genuine suspicion context
            if burst.get("has_encoded_flag") or behavior_score > 0.5 or chain_depth >= 2:
                final = max(final, lolbin_floor)
                burst["floor_applied"] = True
                ledger.append(LedgerEntry("LOLBin floor", 0.0, f"Baseline visibility floor for suspicious {image}", "rule"))

        # ── CRITICAL: ATTACK OVERRIDE ──
        # Trigger on strong sequence OR multiple partial chains
        if sequence_score >= 50 or len(sequence_detections or []) >= 2:
            final = max(final, 75.0)
            ledger.append(LedgerEntry(
                "Attack override",
                0.0,
                "Sequence detection indicates confirmed attack",
                "sequence"
            ))

        # ── 11. CONTRIBUTION-BASED PRIMARY DRIVER (v2.8) ──
        driver_scores = {
            "rule": max(0, rule_score),
            "sequence": max(0, sequence_score),
            "behavior": max(0, behavior_boost + stealth_boost + drift_boost),
            "rarity": max(0, rarity_boost + first_seen_boost),
            "correlation": max(0, corr_boost)
        }
        
        total_delta = sum(driver_scores.values()) or 1.0
        normalized = {k: v / total_delta for k, v in driver_scores.items()}
        primary_driver = max(normalized, key=normalized.get)
        
        # Mixed signal fallback
        if normalized.get(primary_driver, 0) < 0.4:
            primary_driver = "mixed"

        # \ud83d\udd12 Hard clamp: score MUST be in [0, 100] — no exceptions
        final = max(0.0, min(100.0, final))

        return ScoreResult(
            score=round(float(final), 1),
            ledger=ledger,
            confidence_modifier=conf_mod,
            primary_driver=primary_driver
        )

    def classify(self, score: float, kill_chain_stage: str = "Execution") -> str:
        """Compatibility method for legacy pipeline."""
        if score >= 70: return "attack_candidate"
        if score >= 30: return "suspicious"
        if kill_chain_stage not in ("Execution", "Background"): return "suspicious"
        return "benign"

    def validate_context(self, burst: Dict[str, Any]) -> bool:
        """
        Syntactic and causal validation of context records.
        """
        try:
            mandatory = ["image", "computer", "user"]
            for m in mandatory:
                if m not in burst: return False
                
            if "start_time" in burst:
                import pandas as pd
                pd.to_datetime(burst["start_time"])
                
            return True
        except Exception:
            return False

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scoring_engine: Optional[ScoringEngine] = None

def get_scoring_engine() -> ScoringEngine:
    global _scoring_engine
    if _scoring_engine is None:
        _scoring_engine = ScoringEngine()
    return _scoring_engine

def validate_context(burst: Dict[str, Any]) -> bool:
    """Module-level wrapper for context validation."""
    return get_scoring_engine().validate_context(burst)
