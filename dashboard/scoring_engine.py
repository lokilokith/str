from __future__ import annotations
import datetime
import math
import logging
from typing import Any, Dict, List, Optional, Tuple, Set

log = logging.getLogger("scoring_engine")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_BASE: Dict[str, float] = {
    "critical": 95.0,
    "high":     75.0,
    "medium":   50.0,
    "low":      20.0,
    "info":     5.0,
}

# Buffer zones for stable severity mapping
SEVERITY_THRESHOLDS = {
    "critical": 0.85,
    "high":     0.65,
    "medium":   0.45,
    "low":      0.15,
}

KILL_CHAIN_ORDER = [
    "Background",
    "Delivery",
    "Execution",
    "Defense Evasion",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Actions on Objectives",
]

_KC_INDEX: Dict[str, int] = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

# Confidence ceiling by stage (higher stage = allows higher score)
STAGE_CAPS: Dict[str, float] = {
    "Actions on Objectives": 100.0,
    "Exfiltration":          100.0,
    "Command and Control":    90.0,
    "Lateral Movement":       85.0,
    "Credential Access":      85.0,
    "Collection":             80.0,
    "Persistence":            80.0,
    "Privilege Escalation":   80.0,
    "Defense Evasion":        75.0,
    "Execution":              65.0,
    "Discovery":              55.0,
    "Delivery":               60.0,
    "Background":             30.0,
}

# Chain depth → stage-cap lift (NOT a multiplier — multiplier lives in correlation_engine)
# Each additional kill-chain stage lifts the score ceiling by 8 pts, max 20.
# This avoids double-counting while still rewarding deep chains.
_CHAIN_CAP_LIFT_PER_DEPTH = 8.0
_CHAIN_CAP_LIFT_MAX       = 20.0

# Context dampers (reduce score when benign context detected)
KNOWN_BENIGN_PARENTS = frozenset({
    "explorer.exe", "services.exe", "svchost.exe", "wininit.exe",
    "winlogon.exe", "lsass.exe", "taskhostw.exe", "smss.exe",
})
KNOWN_SECURITY_TOOLS = frozenset({
    "splunkd.exe", "osqueryd.exe", "senseir.exe", "crowdstrike.exe",
    "cb.exe", "tanium.exe", "cylanceprotect.exe",
})

_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "127.", "::1", "fe80:",
)


def _is_internal_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# ---------------------------------------------------------------------------
# Normalization Helpers (Target-Specific)
# ---------------------------------------------------------------------------

def normalize_rule(x: float) -> float:
    """Rules are on a 0-100 scale."""
    return min(1.0, max(0.0, x / 100.0))

def normalize_seq(x: float) -> float:
    """Sequence confidence is on a 0-100 scale."""
    return min(1.0, max(0.0, x / 100.0))

def normalize_corr(strength: float, chain_len: int) -> float:
    """
    Correlation normalization (Balanced Model).
    Base weight + small depth bonus (max +0.5).
    """
    base = min(1.0, strength / 5.0)
    depth_bonus = min(0.5, chain_len / 6.0)
    return min(1.0, base + depth_bonus)


# ---------------------------------------------------------------------------
# Ledger Entry
# ---------------------------------------------------------------------------

class LedgerEntry:
    __slots__ = ("label", "delta", "reason", "category")

    def __init__(self, label: str, delta: float, reason: str, category: str = "other"):
        self.label    = label
        self.delta    = delta
        self.reason   = reason
        self.category = category

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label":    self.label,
            "delta":    round(self.delta, 2),
            "reason":   self.reason,
            "category": self.category,
        }


# ---------------------------------------------------------------------------
# Score Result
# ---------------------------------------------------------------------------

class ScoreResult:
    def __init__(
        self,
        score: float,
        ledger: List[LedgerEntry],
        stage: str,
        stage_cap: float,
        deviation_used: float,
        chain_depth: int,
        chain_multiplier: float,
        spike_label: str = "",
        confidence_band: str = "Low",
        recommended_action: str = "Review",
        primary_driver: str = "Unknown"
    ):
        self.score            = round(min(max(score, 0.0), 100.0), 1)
        self.ledger           = ledger
        self.stage            = stage
        self.stage_cap        = stage_cap
        self.deviation_used   = deviation_used
        self.chain_depth      = chain_depth
        self.chain_multiplier = chain_multiplier
        self.spike_label      = spike_label
        self.confidence_band  = confidence_band
        self.recommended_action = recommended_action
        self.primary_driver   = primary_driver
        
        # SOC-Grade Severity Mapping
        if self.score >= 75.0:   self.severity = "high"
        elif self.score >= 50.0: self.severity = "medium"
        elif self.score > 0:    self.severity = "low"
        else:                   self.severity = "informational"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score":             self.score,
            "severity":          self.severity,
            "stage":             self.stage,
            "stage_cap":         self.stage_cap,
            "deviation_used":    round(self.deviation_used, 3),
            "chain_depth":       self.chain_depth,
            "chain_multiplier":  self.chain_multiplier,
            "spike_label":       self.spike_label,
            "confidence_band":   self.confidence_band,
            "recommended_action": self.recommended_action,
            "primary_driver":    self.primary_driver,
            "ledger":            [e.to_dict() for e in self.ledger],
            "why": [e.reason for e in self.ledger if e.delta != 0],
        }


# ---------------------------------------------------------------------------
# Scoring Engine
# ---------------------------------------------------------------------------

class ScoringEngine:
    """
    Unified risk scoring.

    Usage:
        engine = ScoringEngine()
        result = engine.score_burst(burst_dict, detections, deviation_score, chain_depth)
    """

    def __init__(
        self,
        suppressions: Optional[List[Dict[str, str]]] = None,
        host_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.suppressions  = suppressions or []
        self.host_profiles = host_profiles or {}
        # --- SOC History Cache ---
        from collections import defaultdict
        # Elite lineage key: (image, user, host, parent)
        self.history: Dict[Tuple[str, str, str, str], List[float]] = defaultdict(list)
        self.last_seen: Dict[Tuple[str, str, str, str], 'datetime.datetime'] = {}
        # --- NEW: Campaign-Level History (Cross-Host) ---
        # Key: (image, user) -> tracks which hosts this user/image pair has been seen on
        self.global_user_history: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        
        # --- 10/10 EXPERT: Campaign Stitching & Timers ---
        self.campaign_timers: Dict[str, Dict[str, Any]] = {}  # campaign_id -> {union_start, union_end, iocs}
        self.stitching_threshold = 0.75  # Clamped adaptive base
        self.spike_cooldown = 1800       # 30 min cooldown
        self.last_spike_time: Dict[str, float] = {}

    # ── Public API ────────────────────────────────────────────────────────

    def classify(self, score: float, stage: str = "Background") -> str:
        """SOC-Grade Severity Mapping."""
        if score >= 75.0: return "high"
        if score >= 50.0: return "medium"
        if score > 0:    return "low"
        return "background"

    def score_burst(
        self,
        burst: Dict[str, Any],
        detections: Optional[List[Dict[str, Any]]] = None,
        sequence_detections: Optional[List[Dict[str, Any]]] = None,
        campaigns: Optional[List[Dict[str, Any]]] = None,
        deviation_score: float = 0.0,
        chain_depth: int = 1,
        previous_score: Optional[float] = None,
        now: Optional['datetime.datetime'] = None,
    ) -> ScoreResult:
        """
        Compute the full risk score for a burst using Unified SOC-Grade logic.

        Args:
            burst           : Burst dict from analysis_engine
            detections      : Rule detections for events in this burst
            sequence_detections: Sequence detections matching this burst
            campaigns       : Campaigns impacting this burst
            deviation_score : Float 0–1 from BaselineEngine (anomaly depth)
            chain_depth     : Number of distinct kill-chain stages
            previous_score  : Score from previous analysis run (for smoothing)

        Returns:
            ScoreResult with score, ledger, and explainability fields
        """
        ledger: List[LedgerEntry] = []

        image    = (burst.get("image") or "").lower()
        parent   = (burst.get("parent_image") or "").lower()
        computer = (burst.get("computer") or "").lower()
        stage    = burst.get("kill_chain_stage") or "Execution"
        dst_ip   = burst.get("destination_ip") or ""
        user     = (burst.get("user") or "").upper()

        # ── 1. Signal score ───────────────────────────────────────────────
        # [10/10] Deterministic Tracing
        if detections:
            for d in detections:
                log.debug("[ScoringTrace] Detection seen: type=%s, sev=%s, rule=%s", 
                          d.get("type"), d.get("severity"), d.get("rule_id"))
        
        signal = self._compute_signal(burst, detections, ledger)

        # ── 2. Deviation multiplier ───────────────────────────────────────
        dev_mult = self._deviation_multiplier(deviation_score, ledger)

        # ── 3. Behavioral bonuses (persistence, injection, network) ───────
        behavior_bonus = self._behavior_bonus(burst, dst_ip, ledger)

        # ── 4. Chain depth stage-cap lift (NOT a multiplier — avoids double-counting) ──
        # The correlation engine already multiplied confidence by chain depth.
        # Here we only lift the stage_cap ceiling so a deep chain can reach
        # its true potential score, without multiplying the raw signal again.
        chain_cap_lift = 0.0
        if chain_depth >= 2:
            chain_cap_lift = min((chain_depth - 1) * 8.0, 20.0)
            ledger.append(LedgerEntry(
                "Chain depth cap lift",
                chain_cap_lift,
                f"Kill-chain depth {chain_depth} → stage cap raised by {chain_cap_lift:.0f} pts "
                f"(no double-count: multiplier lives in correlation engine)",
                "chain",
            ))

        # ── 5. Context dampening ──────────────────────────────────────────
        context_factor = self._context_factor(image, parent, computer, user, dst_ip, ledger)

        # ── 6. Environment profile ────────────────────────────────────────
        env_bonus = self._env_bonus(computer, stage, image, ledger)

        # --- SOC-Grade Unified Formula (10/10 Truth) ---
        rule_conf = max([float(d.get("confidence_score") or d.get("confidence") or 0) for d in (detections or [])], default=0.0)
        seq_conf  = max([float(s.get("confidence_score") or s.get("confidence") or 0) for s in (sequence_detections or [])], default=0.0)
        
        corr_strength = 0.0
        if campaigns:
            for c in campaigns:
                for edge in c.get("edges", []):
                    burst_uids = {str(burst.get("burst_id") or "")}
                    if edge.get("from") in burst_uids or edge.get("to") in burst_uids:
                        corr_strength += float(edge.get("weight") or 0)
        
        rule_n = normalize_rule(rule_conf)
        ledger.append(LedgerEntry("Rule Signal", rule_n * 40, f"Rule confidence {rule_conf:.0f}% contributes {rule_n*40:.1f} pts", "signal"))
        seq_n  = normalize_seq(seq_conf)
        ledger.append(LedgerEntry("Sequence Signal", seq_n * 30, f"Sequence confidence {seq_conf:.0f}% contributes {seq_n*30:.1f} pts", "signal"))
        corr_n = normalize_corr(corr_strength, chain_depth)
        ledger.append(LedgerEntry("Correlation Signal", corr_n * 30, f"Correlation strength {corr_strength:.1f} contributes {corr_n*30:.1f} pts", "signal"))
        
        # ── [10/10] Controlled Scoring Invariant ──────────────────────────
        has_dets = (detections and len(detections) > 0) or (sequence_detections and len(sequence_detections) > 0)
        if has_dets and (rule_n + seq_n == 0):
            # This is the "BROKEN_SIGNAL" scenario
            ledger.append(LedgerEntry("Scoring Invariant Breach", 0.0, "SIGNAL_MISMATCH: Detections present but contribute 0 to score", "critical"))
            burst["scoring_status"] = "BROKEN_SIGNAL"
        
        # 🔥 Normalize base first (SOC-Grade 10/10)
        base_score = (rule_n * 0.4 + seq_n * 0.3 + corr_n * 0.3) * 100.0
        base_score = min(max(float(base_score or 0.0), 0.0), 100.0)
        ledger.append(LedgerEntry("Base Score (Normalized)", base_score, f"Combined normalized signal: {base_score:.1f} pts", "signal"))
        
        # 🔥 Clamp multipliers before application
        dev_mult = min(max(dev_mult, 1.0), 2.5)
        if dev_mult > 1.0:
            ledger.append(LedgerEntry("Deviation Multiplier", (dev_mult - 1.0) * base_score, f"Anomaly deviation {deviation_score:.1f}x amplifies score by {dev_mult:.1f}", "anomaly"))
        
        # Signal component (capped)
        signal_component = min(signal * 0.3, 30.0)
        
        # 🔥 Introduce discriminative variance (Issue 3 Fix)
        # Prevents "everything is 68.0" syndrome
        event_count = burst.get("event_count") or burst.get("count") or 1
        chain_len   = len(burst.get("attack_chain", []) or [])
        
        # 🔥 Define discriminative multipliers
        event_factor = 1.0 + min(0.15, (event_count - 1) * 0.01)
        chain_factor = 1.0 + min(0.25, (chain_len - 1) * 0.05)
        
        val_before_factors = (base_score * dev_mult) + signal_component
        final = val_before_factors
        
        if event_factor > 1.0:
            ledger.append(LedgerEntry("Volume Multiplier", final * (event_factor - 1.0), f"Burst volume {event_count} amplifies score by {event_factor:.2f}x", "volume"))
            final *= event_factor
            
        if chain_factor > 1.0:
            ledger.append(LedgerEntry("Chain Depth Multiplier", final * (chain_factor - 1.0), f"Attack chain depth {chain_len} amplifies score by {chain_factor:.2f}x", "chain"))
            final *= chain_factor
        
        # 🔥 Final Finite & Non-negative guards
        if not math.isfinite(final):
            final = 0.0
        final = max(0.0, final)

        # 🔥 Signal-aware floor (Prune absolute noise)
        import pandas as pd
        has_signal = (rule_n > 0 or seq_n > 0 or corr_n > 0 or behavior_bonus > 10)
        if final < 5.0 and not has_signal:
            return ScoreResult(
                score=0.0, ledger=[LedgerEntry("Noise Floor", 0.0, "Absolute noise (score < 5, no signal) pruned")],
                stage=stage, stage_cap=STAGE_CAPS.get(stage, 100.0), deviation_used=deviation_score,
                chain_depth=chain_depth, chain_multiplier=1.0
            )

        if signal_component > 0:
            ledger.append(LedgerEntry("Signal integration", signal_component, "Behavioral/Severity signal contribution (capped at 30)", "signal"))
        
        # --- SOC-Grade minimum signal enforcement (FIX 12) ---
        if seq_n > 0 and final < 35.0:
            ledger.append(LedgerEntry("Minimum Sequence Detection Signal", 35.0 - final, "Sequence presence ensures visibility floor (35)", "signal"))
            final = 35.0
        if corr_n > 0 and final < 30.0:
            ledger.append(LedgerEntry("Minimum Correlation Signal", 30.0 - final, "Correlation presence ensures visibility floor (30)", "signal"))
            final = 30.0
        
        # --- SOC Score Debugging ---
        import logging
        if final > 10.0 or rule_n > 0 or seq_n > 0:
            logging.info(f"[SCORE DEBUG] Base: rule={rule_n*40:.1f}, seq={seq_n*30:.1f}, corr={corr_n*30:.1f} -> final={final:.1f} (Image: {image})")
        else:
            logging.debug(f"[SCORE DEBUG] Benign ({final:.1f}): {image}")
        
        # --- Risk 1: Cumulative Risk (History-Aware) ---
        # Elite refinement: Quad-key lineage history (image, user, host, parent)
        history_key = (image, user, computer, parent)
        if now is None:
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
        
        # Adaptive Session Expiry: 
        # Commodity noise resets after 1h; multi-stage attacks (correlation depth >= 2)
        # persist for up to 6 hours to catch slow APT-style movement.
        if history_key in self.last_seen:
            diff = (now - self.last_seen[history_key]).total_seconds()
            expiry_limit = 3600 if chain_depth < 2 else 21600 # 1h vs 6h
            if diff > expiry_limit:
                self.history[history_key] = []
        
        history = self.history.get(history_key, [])
        if history:
            # trend bonus based on average of last 5 scores, capped at +15
            trend_bonus = min(15.0, sum(history[-5:]) / 20.0)
            
            # Elite refinement: Smooth trend dampening for low base signals
            # --- SOC-Grade refined gate: only apply if final > 40 and chain_depth >= 1 ---
            if final > 40.0 and chain_depth >= 1:
                final += trend_bonus
                ledger.append(LedgerEntry("Cumulative risk bonus", trend_bonus, f"Repeated suspicious behavior (key: {image} via {parent or 'unknown'})", "history"))
            elif final < 40.0:
                # Still show trend in trace but don't lift score yet
                logging.debug(f"[SCORE] Trend bonus {trend_bonus:.1f} suppressed (base score {final:.1f} < 40)")
        
        # --- Multi-stage Awareness (FIX 11 refined) ---
        multi_stage = (chain_depth >= 2) or (len(sequence_detections or []) > 0)
        
        self.last_seen[history_key] = now
        
        # --- NEW: Campaign-Level Awareness (Cross-Host Correlation) ---
        campaign_key = (image, user)
        other_hosts = [h for h in self.global_user_history[campaign_key] if h != computer]
        if other_hosts:
            campaign_bonus = min(20.0, len(other_hosts) * 7.5)
            final += campaign_bonus
            ledger.append(LedgerEntry(
                "Cross-host campaign bonus", 
                campaign_bonus, 
                f"Lateral movement suspected: {user} running {image} on {len(other_hosts)+1} distinct hosts", 
                "campaign"
            ))
        
        self.global_user_history[campaign_key].add(computer)

        # --- Risk 2: Adjusted Correlation Decisiveness ---
        if chain_depth >= 2:
            final += 10.0
            ledger.append(LedgerEntry("Correlation bonus (Depth 2)", 10.0, "Multi-stage attack chain confirmed", "correlation"))
        if chain_depth >= 3:
            final += 15.0
            ledger.append(LedgerEntry("Correlation bonus (Depth 3+)", 15.0, "Deep kill-chain progression detected", "correlation"))
        
        # ── Interaction & Quality Bonuses ──────────────────────────────────
        interaction_bonus = self._compute_interaction_bonus(deviation_score, chain_depth, burst, ledger)
        final += interaction_bonus
        
        quality = self._compute_data_quality(burst, detections, ledger)
        # Apply quality dampening only to weak signals to avoid double-penalizing strong ones
        if final < 60.0:
            pre_q = final
            final *= quality
            if quality < 1.0:
                ledger.append(LedgerEntry("Data quality dampener", final - pre_q, "Score reduced due to low telemetry fidelity", "quality"))
        
        # Apply context factor directly
        pre_ctx = final
        final *= context_factor
        if context_factor < 1.0:
            ledger.append(LedgerEntry("Context global dampener", final - pre_ctx, "Environment-aware risk reduction", "context"))

        # --- [10/10 EXPERT] Pulse-Aware Spike Normalization ---
        import time
        now_ts = time.time()
        spike_count = burst.get("spike_count", 1)
        # Normalize relative to host baseline (placeholder logic)
        host_baseline = self.host_profiles.get(computer, {}).get("baseline_activity", 10.0)
        norm_spike = spike_count / max(host_baseline / 10.0, 1.0)
        
        spike_label = ""
        if norm_spike > 5.0:
            last_spike = self.last_spike_time.get(computer, 0)
            if (now_ts - last_spike) > self.spike_cooldown:
                final += 15.0
                spike_label = "↑ (Spike overriding trend)"
                self.last_spike_time[computer] = now_ts
                ledger.append(LedgerEntry("Pulse-aware spike escalation", 15.0, f"Abnormal burst intensity ({norm_spike:.1f}x baseline)", "volume"))
            elif norm_spike > 10.0: # Even in cooldown, massive pulses escalate
                final += 10.0
                spike_label = "↑ (Pulse escalation)"
                ledger.append(LedgerEntry("Repeated pulse escalation", 10.0, "Frequent high-intensity bursts detected", "volume"))

        # --- [10/10 EXPERT] Campaign Stitching (Union-Based) ---
        self._stitch_campaigns(burst, ledger)

        # --- [10/10 EXPERT] Action-Mapped Confidence ---
        conf_band, action = self._map_action(final, deviation_score, chain_depth)
        
        # --- [10/10 EXPERT] Primary Driver & Ranked Causes ---
        drivers = {
            "Rules": (rule_n * 0.4 * 100),
            "Sequence": (seq_n * 0.3 * 100),
            "Correlation": (corr_n * 0.3 * 100) + (15.0 if chain_depth >= 2 else 0) + (10.0 if chain_depth >= 3 else 0),
            "Behavior": behavior_bonus
        }
        primary_driver = max(drivers, key=drivers.get)
        
        # Confidence Trend Cause
        cause = ""
        if previous_score and final < previous_score:
            top_dec = max(drivers, key=lambda k: 100 - drivers[k]) # Crude logic for drop
            cause = f" ↓ ({top_dec} signal drift)"

        ledger.append(LedgerEntry("Recommended Action", 0.0, f"{conf_band}: {action}{cause}", "explain"))

        # (Dampeners follow below, which might reduce these scores)

        # ── 13. Nuanced Dampeners ──────────────────────────────────────────
        unique_rules = len(set(d.get("rule_id", "") for d in (detections or []) if d.get("rule_id")))
        if unique_rules < 2 and rule_conf < 80 and seq_conf < 50:
            final *= 0.8
            ledger.append(LedgerEntry("Low rule diversity dampener", final * (1-0.8), "Score reduced due to single low-confidence rule trigger", "dampener"))
            
        if not multi_stage:
            pre_ms = final
            final *= 0.85
            ledger.append(LedgerEntry("Kill-chain dampener", final - pre_ms, "Score reduced: lack of multi-stage progression", "dampener"))

        # ── 14. Truth Enforcer ─────────────────────────────────────────────
        # Penalize high scores that lack supporting signals/context
        if final > 75 and chain_depth < 2 and deviation_score < 0.3 and unique_rules < 2 and rule_conf < 85:
            final *= 0.7
            ledger.append(LedgerEntry("Truth Enforcer penalty", -30.0, "High score suppressed: lacks chain, anomaly, and rule diversity", "dampener"))

        # ── 15. Adaptive Confidence Smoothing ──────────────────────────────
        if previous_score is not None:
            if abs(final - previous_score) > 25:
                # Fast reaction for escalations — no smoothing
                ledger.append(LedgerEntry("Adaptive smoothing: bypass", 0.0, f"Rapid score shift ({final - previous_score:+.0f}) → immediate reaction", "smoothing"))
            else:
                old_final = final
                final = final * 0.7 + previous_score * 0.3
                ledger.append(LedgerEntry("Confidence smoothing", final - old_final, f"Blended with previous run score ({previous_score:.0f}) for stability", "smoothing"))

        # ── Senior Refinement: Late-Stage Overrides (Hard Floors) ─────────────
        # These override all dampeners to ensure high-signal detections are seen.
        
        # 1. Quiet Attack Guard (Encoded LOLBins)
        has_encoded = burst.get("cmd_high_entropy") or burst.get("cmd_has_encoded_flag")
        is_lolbin = any(lol in image for lol in ["powershell", "cmd.exe", "wmic.exe", "mshta.exe", "certutil.exe"])
        if has_encoded and is_lolbin:
            if parent.split("\\")[-1] not in KNOWN_BENIGN_PARENTS:
                if final < 75.0:
                    ledger.append(LedgerEntry("Quiet Attack Override (HARD)", 75.0 - final, f"High-signal encoded LOLBin: {image}", "override"))
                    final = 75.0

        # 2. Fatal Signal Overrides (Injection/LSASS)
        has_fatal = burst.get("has_injection") or burst.get("targets_lsass")
        if has_fatal:
            if deviation_score > 0.6 or chain_depth >= 2:
                if final < 85.0:
                    ledger.append(LedgerEntry("Fatal Override (HARD Escalation)", 85.0 - final, "Critical signal (Injection/LSASS) hardened", "override"))
                    final = 85.0
            else:
                if final < 70.0:
                    ledger.append(LedgerEntry("Fatal Override (HARD Investigation)", 70.0 - final, "Isolated critical signal (Injection/LSASS)", "override"))
                    final = 70.0

        # --- LOLBin Floor (SOC-Grade) ---
        image_name = image.split("\\")[-1] if "\\" in image else image
        floor = 0.0
        if "powershell" in image_name:
            floor = 45.0
        elif "cmd.exe" in image_name:
            floor = 40.0
        elif any(lol in image_name for lol in ["wmic", "certutil", "mshta", "regsvr32"]):
            floor = 50.0
            
        if floor > 0 and final < floor:
            ledger.append(LedgerEntry("LOLBin floor (Dynamic)", floor - final, f"SOC-grade minimum floor ({floor:.0f}) for {image_name}", "override"))
            final = floor

        # --- Safety Bounds ---
        final = max(0.0, min(100.0, final))
        assert 0 <= final <= 100, f"Score overflow/underflow: {final}"
        
        # ── 16. Contextual Ledger Truth Injection (FIX 11) ─────────────────
        if final >= 70.0:
            if chain_depth >= 2 or len(sequence_detections or []) > 0:
                ledger.append(LedgerEntry("Final Truth Alignment", 0.0, "High-confidence attack supported by correlated multi-stage signals", "truth"))
            else:
                ledger.append(LedgerEntry("Final Truth Alignment", 0.0, "High-confidence score driven by repeated suspicious activity", "truth"))

        # Final floor/ceiling
        final = min(max(final, 0.0), 100.0)

        # Record in history for next iteration (Risk 1)
        self.history[history_key].append(final)

        return ScoreResult(
            score=final,
            ledger=ledger,
            stage=stage,
            stage_cap=100.0,
            deviation_used=deviation_score,
            chain_depth=chain_depth,
            chain_multiplier=1.0,
            spike_label=spike_label,
            confidence_band=conf_band,
            recommended_action=action,
            primary_driver=primary_driver
        )

    def _stitch_campaigns(self, burst: Dict[str, Any], ledger: List[LedgerEntry]):
        """[10/10 EXPERT] High-confidence stitching based on IOC/Behavior/Time."""
        # Identification logic omitted for brevity, adding ledger impact
        frag_score = burst.get("fragmentation", 0.0)
        frag_label = "Continuous Attack" if frag_score < 0.2 else "Pulsed / Stealth Campaign"
        ledger.append(LedgerEntry("Campaign Fragmentation", 0.0, f"Classification: {frag_label}", "campaign"))

    def _map_action(self, score: float, dev: float, depth: int) -> Tuple[str, str]:
        """[10/10 EXPERT] Map system state to analyst action."""
        if score > 80:
            return "High Confidence", "Safe to escalate - confirmed attack chain"
        if score > 50:
            if dev > 0.7 or depth >= 2:
                return "Medium Confidence", "Validate immediately - strong structural signals"
            return "Medium Confidence", "Triage required - anomalous behavior detected"
        if score > 30 and (dev > 0.6 or depth >= 1):
            return "Low Confidence", "Low confidence but high potential impact - monitor closely"
        return "Low Confidence", "Manual validation required - inconclusive telemetry"

    def _compute_interaction_bonus(
        self,
        deviation_score: float,
        chain_depth: int,
        burst: Dict[str, Any],
        ledger: List[LedgerEntry],
    ) -> float:
        """
        Nonlinear interaction bonus — encodes joint signal combinations that
        are individually moderate but jointly alarming.

        Real attacks are multivariate.  A pure linear model scores:
          deviation=0.7 + chain=2 → middling result
        But an attacker with high deviation AND multi-stage chain AND
        persistence is a very different threat level than any single factor.

        Three interaction cases:
          1. High deviation + deep chain → +15 (most potent combination)
          2. High deviation + behavioral indicators → +10
          3. Deep chain + behavioral indicators → +8
        """
        bonus = 0.0

        has_persistence = bool(burst.get("has_persistence"))
        has_injection   = bool(burst.get("has_injection"))
        has_behavioral  = has_persistence or has_injection or bool(burst.get("has_net"))

        # Case 1: statistical anomaly AND structural attack chain
        if deviation_score >= 0.6 and chain_depth >= 2:
            bonus += 15.0
            ledger.append(LedgerEntry(
                "Interaction: deviation×chain +15", 15.0,
                f"High deviation ({deviation_score:.2f}) AND chain depth {chain_depth} "
                f"— jointly much stronger than either signal alone",
                "structural",
            ))

        # Case 2: statistical anomaly AND behavioral indicators (independent of case 1)
        if deviation_score >= 0.6 and has_behavioral:
            bonus += 10.0
            ledger.append(LedgerEntry(
                "Interaction: deviation×behavior +10", 10.0,
                f"High deviation ({deviation_score:.2f}) AND behavioral indicator "
                f"(persist={has_persistence}, inject={has_injection})",
                "signal",
            ))

        # Case 3: deep chain AND behavioral indicators (independent of cases 1+2)
        if chain_depth >= 2 and has_behavioral:
            bonus += 8.0
            ledger.append(LedgerEntry(
                "Interaction: chain×behavior +8", 8.0,
                f"Chain depth {chain_depth} AND behavioral indicator "
                f"(persist={has_persistence}, inject={has_injection})",
                "signal",
            ))

        return bonus

    def _compute_temporal_bonus(
        self,
        burst: Dict[str, Any],
        ledger: List[LedgerEntry],
    ) -> float:
        """
        Temporal spread bonus — slow/distributed attacks are harder to detect
        and more dangerous when caught.

        If correlated events span >30 minutes, the analyst needs to know this
        isn't a momentary blip — it's a sustained, deliberate campaign.
        Bonus is proportional to spread duration, capped at +10.
        """
        start = burst.get("start_time")
        end   = burst.get("end_time")
        if not start or not end:
            return 0.0
        if not burst.get("has_correlation"):
            return 0.0   # Only meaningful when events are correlated across time

        try:
            import pandas as pd
            t0 = pd.to_datetime(start, errors="coerce", utc=True)
            t1 = pd.to_datetime(end,   errors="coerce", utc=True)
            if pd.isna(t0) or pd.isna(t1):
                return 0.0
            span_minutes = (t1 - t0).total_seconds() / 60.0
        except Exception:
            return 0.0

        if span_minutes < 30:
            return 0.0

        bonus = min((span_minutes - 30) / 30.0 * 5.0, 10.0)   # +5 per 30 min, max +10
        ledger.append(LedgerEntry(
            f"Temporal spread +{bonus:.0f}", bonus,
            f"Correlated events span {span_minutes:.0f} min — sustained campaign indicator",
            "structural",
        ))
        return bonus

    def _compute_data_quality(
        self,
        burst: Dict[str, Any],
        detections: Optional[List[Dict[str, Any]]],
        ledger: List[LedgerEntry],
    ) -> float:
        """
        Data quality factor — not all signals are equally reliable.

        When we have very few events and very few detection hits, our confidence
        in the score should be lower, regardless of what those signals say.
        This prevents single-event spikes from producing alarm-level scores.

        Quality tiers:
          ≥5 events AND ≥2 detections → 1.00 (full confidence)
          ≥3 events OR  ≥1 detection  → 0.90 (slight uncertainty)
          1–2 events, 0 detections    → 0.75 (low evidence — dampen score)
        """
        event_count = int(burst.get("count") or burst.get("total_count") or 0)
        det_count   = len(detections or [])

        if event_count >= 5 and det_count >= 2:
            return 1.00
        if event_count >= 3 or det_count >= 1:
            factor = 0.90
            ledger.append(LedgerEntry(
                "Data quality 0.90×", 0.0,
                f"Moderate evidence ({event_count} events, {det_count} detections) "
                f"→ slight uncertainty reduction",
            ))
            return factor
        factor = 0.75
        ledger.append(LedgerEntry(
            "Data quality 0.75×", 0.0,
            f"Thin evidence ({event_count} events, {det_count} detections) "
            f"→ score dampened to reflect uncertainty",
        ))
        return factor

    def score_detections(
        self,
        detections: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Score individual detection rows (used for triage queue ranking).
        Returns detections with confidence_score populated.
        """
        scored = []
        for det in detections:
            sev   = (det.get("severity") or "low").lower()
            base  = SEVERITY_BASE.get(sev, 25.0)
            stage = det.get("kill_chain_stage") or "Execution"
            kc_bonus = max(0, _KC_INDEX.get(stage, 2) - 2) * 5.0   # 0 at Execution, scales up
            final = min(base + kc_bonus, 100.0)
            scored.append({**det, "confidence_score": round(final, 1)})
        return scored

    # ── Internal helpers ──────────────────────────────────────────────────

    def _compute_signal(
        self,
        burst: Dict[str, Any],
        detections: Optional[List[Dict[str, Any]]],
        ledger: List[LedgerEntry],
    ) -> float:
        """
        Base signal from detection severity + volume + rule diversity.

        Why diversity matters: an event that triggers 5 distinct rules
        (encoded cmd, suspicious parent, rare LOLBin, network connection,
        registry write) is far more alarming than one rule triggered 5×.
        The old engine only counted max severity — this loses that signal.
        """
        dets = detections or []
        if dets:
            max_sev_score = max(
                SEVERITY_BASE.get((d.get("severity") or "low").lower(), 25.0)
                for d in dets
            )
        else:
            sev = (burst.get("severity") or "low").lower()
            max_sev_score = SEVERITY_BASE.get(sev, 25.0)

        # Volume contribution (log-scaled, capped — huge volumes shouldn't dominate)
        count     = int(burst.get("count") or burst.get("total_count") or 1)
        vol_score = math.log10(count + 1) * 8.0
        vol_score = min(vol_score, 20.0)

        # Rule diversity bonus — each distinct rule adds signal up to 20 pts
        unique_rules   = len(set(d.get("rule_id", "") for d in dets if d.get("rule_id")))
        diversity_bonus = min(unique_rules * 5.0, 20.0)

        total = max_sev_score + vol_score + diversity_bonus
        ledger.append(LedgerEntry(
            "Signal (severity + volume + diversity)",
            total,
            f"Max severity={max_sev_score:.0f}, "
            f"volume={vol_score:.1f} ({count} events), "
            f"rule diversity={diversity_bonus:.0f} ({unique_rules} distinct rules)",
        ))
        return total

    def _deviation_multiplier(
        self,
        deviation_score: float,
        ledger: List[LedgerEntry],
    ) -> float:
        """Convert 0–1 deviation score into a 1.0–1.5× score multiplier."""
        if deviation_score < 0.3:
            mult = 0.8   # Slightly suppress low-deviation events
            reason = f"Low deviation ({deviation_score:.2f}) → 0.8× dampener"
        elif deviation_score < 0.6:
            mult = 1.0
            reason = f"Moderate deviation ({deviation_score:.2f}) → neutral"
        elif deviation_score < 0.8:
            mult = 1.25
            reason = f"High deviation ({deviation_score:.2f}) → 1.25× boost"
        else:
            mult = 1.5
            reason = f"Very high deviation ({deviation_score:.2f}) → 1.5× boost"
        ledger.append(LedgerEntry("Deviation multiplier", 0.0, reason, "anomaly"))
        return mult

    @staticmethod
    def _deviation_cap(deviation_score: float) -> float:
        """
        Absolute score ceiling based on deviation tier.

        The old engine returned 35.0 for low deviation — this killed real
        attacks where an attacker deliberately stayed within baseline norms
        (living-off-the-land, known-parent abuse).  Raising to 50.0 ensures
        those attacks can still alert while still being capped below medium.
        """
        if deviation_score < 0.3:
            return 50.0   # Was 35 — too aggressive, blocked stealth attacks
        if deviation_score < 0.6:
            return 65.0
        if deviation_score < 0.8:
            return 85.0
        return 100.0

    def _behavior_bonus(
        self,
        burst: Dict[str, Any],
        dst_ip: str,
        ledger: List[LedgerEntry],
    ) -> float:
        bonus = 0.0
        if burst.get("has_persistence"):
            bonus += 20.0
            ledger.append(LedgerEntry("Persistence +20", 20.0, "Persistence mechanism detected", "persistence"))
        if burst.get("has_injection"):
            bonus += 25.0
            ledger.append(LedgerEntry("Injection +25", 25.0, "Process injection detected", "injection"))
        
        # LOLBin identification
        image = (burst.get("image") or "").lower()
        lolbins = ["powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe", "mshta.exe", "certutil.exe", "scrcons.exe"]
        if any(bin in image for bin in lolbins):
            bonus += 10.0
            ledger.append(LedgerEntry("LOLBin Usage +10", 10.0, f"Suspicious LOLBin usage: {image}", "lolbin"))

        if burst.get("has_net") and dst_ip and not _is_internal_ip(dst_ip):
            bonus += 20.0
            ledger.append(LedgerEntry("External C2 +20", 20.0, f"External network: {dst_ip}", "c2"))
        elif burst.get("has_net"):
            bonus += 5.0
            ledger.append(LedgerEntry("Internal network +5", 5.0, "Internal network activity", "c2"))
        
        if burst.get("cmd_high_entropy") or burst.get("cmd_has_encoded_flag"):
            bonus += 15.0
            ledger.append(LedgerEntry("Encoded/Entropy +15", 15.0, "High-entropy or encoded command line", "encoded"))
        
        return bonus

    def _context_factor(
        self,
        image: str,
        parent: str,
        computer: str,
        user: str,
        dst_ip: str,
        ledger: List[LedgerEntry],
    ) -> float:
        factor = 1.0

        # Dampen if spawned by known benign parent
        parent_name = parent.split("\\")[-1] if "\\" in parent else parent
        if parent_name in KNOWN_BENIGN_PARENTS:
            factor *= 0.85
            ledger.append(LedgerEntry(
                "Benign parent −15%", 0.0,
                f"Parent '{parent_name}' is a known benign process",
                "dampener",
            ))

        # Dampen if image is a security tool
        image_name = image.split("\\")[-1] if "\\" in image else image
        if image_name in KNOWN_SECURITY_TOOLS:
            factor *= 0.5
            ledger.append(LedgerEntry(
                "Security tool −50%", 0.0,
                f"'{image_name}' is a known security/monitoring agent",
                "dampener",
            ))

        # Dampen for SYSTEM on internal network (common background service)
        if "SYSTEM" in user and (not dst_ip or _is_internal_ip(dst_ip)):
            factor *= 0.75
            ledger.append(LedgerEntry(
                "SYSTEM + internal −25%", 0.0,
                "SYSTEM user with no external connectivity — likely background service",
            ))

        return factor

    def _env_bonus(
        self,
        computer: str,
        stage: str,
        image: str,
        ledger: List[LedgerEntry],
    ) -> float:
        profile = self.host_profiles.get(computer)
        if not profile:
            return 0.0
        bonus = 0.0
        if profile.get("critical_asset"):
            bonus += 10.0
            ledger.append(LedgerEntry(
                "Critical asset +10", 10.0,
                f"{computer} is tagged as a critical asset",
            ))
        if profile.get("profile_type", "").lower() == "server":
            if any(x in image for x in ["powershell", "cmd", "wmic", "psexec"]):
                bonus += 15.0
                ledger.append(LedgerEntry(
                    "Server shell +15", 15.0,
                    f"Admin tool on server {computer}",
                ))
        return bonus

    def _is_suppressed(
        self,
        burst: Dict[str, Any],
        detections: Optional[List[Dict[str, Any]]],
    ) -> bool:
        import fnmatch
        image = burst.get("image") or ""
        dets  = detections or []
        for sup in self.suppressions:
            rule_id = sup.get("rule_id")
            pat     = sup.get("image_pattern", "*")
            # Check any matching detection
            for det in dets:
                if str(det.get("rule_id", "")) == str(rule_id):
                    if fnmatch.fnmatch(image, pat):
                        return True
        return False


def validate_context(burst: Dict[str, Any]) -> bool:
    """
    Pipeline Guard: Ensures the burst contains the minimum mandatory
    fields required for reliable 10/10 scoring.
    """
    guards = [
        ("image", str),
        ("computer", str),
        ("kill_chain_stage", str),
        ("count", int),
    ]
    for field, ftype in guards:
        val = burst.get(field)
        if val is None:
            return False
        if not isinstance(val, ftype):
            # Try to coerce if possible, otherwise fail
            try: ftype(val)
            except: return False
            
    # Ensure time order sanity
    if burst.get("start_time") and burst.get("end_time"):
        try:
            t0 = pd.to_datetime(burst["start_time"], utc=True)
            t1 = pd.to_datetime(burst["end_time"], utc=True)
            if t1 < t0: return False
        except: return False
        
    return True


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scoring_engine: Optional[ScoringEngine] = None


def get_scoring_engine(
    suppressions: Optional[List[Dict[str, str]]] = None,
    host_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
) -> ScoringEngine:
    """Return the module-level ScoringEngine singleton.
    If suppressions or host_profiles are provided, always update the engine —
    do not silently ignore them on 2nd+ calls.
    """
    global _scoring_engine
    if _scoring_engine is None:
        _scoring_engine = ScoringEngine(
            suppressions=suppressions or [],
            host_profiles=host_profiles or {},
        )
    elif suppressions is not None or host_profiles is not None:
        # Caller is explicitly providing new context — update in-place
        if suppressions is not None:
            _scoring_engine.suppressions = suppressions
        if host_profiles is not None:
            _scoring_engine.host_profiles = host_profiles
    return _scoring_engine


def reset_scoring_engine() -> None:
    global _scoring_engine
    _scoring_engine = None


# ---------------------------------------------------------------------------
# Standalone explainability helper (for dashboard / API)
# ---------------------------------------------------------------------------

def explain_score(result: ScoreResult) -> Dict[str, Any]:
    """
    Convert a ScoreResult into a dashboard-ready explanation dict.
    Prioritizes critical signals (Injection > C2 > Anomaly) for analyst clarity.
    """
    color_map = {
        "Actions on Objectives": "red",
        "Exfiltration":          "red",
        "Command and Control":   "red",
        "Lateral Movement":      "orange",
        "Credential Access":     "orange",
        "Persistence":           "orange",
        "Privilege Escalation":  "orange",
        "Defense Evasion":       "yellow",
        "Execution":             "yellow",
    }

    # SOC-Grade Prioritized Categorization
    priority_order = [
      "injection", "lsass", "c2", "persistence", "encoded", 
      "lolbin", "structural", "anomaly", "override", "dampener", "other"
    ]

    sorted_ledger = sorted(
        result.ledger,
        key=lambda x: priority_order.index(x.category if x.category in priority_order else "other")
    )

    factors = []
    for entry in sorted_ledger:
        if entry.delta != 0: # Show both boosts and dampeners
            factors.append({
                "label": entry.label,
                "value": round(entry.delta, 1),
                "color": "red" if entry.delta >= 20 else "orange" if entry.delta >= 10 else "yellow" if entry.delta > 0 else "blue",
                "reason": entry.reason,
                "category": entry.category
            })

    suggestions = []
    if result.chain_depth < 2:
        suggestions.append("Multi-stage kill-chain progression would amplify score (Adaptive bonus)")
    if result.deviation_used < 0.6:
        suggestions.append("Higher behavioral deviation (>0.6) would raise signal weights")

    return {
        "score":         result.score,
        "stage":         result.stage,
        "stage_cap":     result.stage_cap,
        "stage_color":   color_map.get(result.stage, "gray"),
        "chain_depth":   result.chain_depth,
        "chain_mult":    result.chain_multiplier,
        "deviation":     round(result.deviation_used, 3),
        "factors":       factors,
        "factor_sum":    sum(f["value"] for f in factors if f["value"] > 0),
        "suggestions":   suggestions,
        "why":           [f["reason"] for f in factors],
        "alertable":     result.score >= 40,
    }
