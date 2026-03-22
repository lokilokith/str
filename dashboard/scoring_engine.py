"""
scoring_engine.py — SentinelTrace v2 Unified Risk Scoring Engine
=================================================================
Multi-layer risk model:
  1. Signal score  — detections × severity weights
  2. Baseline boost — deviation multiplier (statistical anomaly depth)
  3. Correlation boost — kill-chain chain depth multiplier
  4. Context dampening — known parent / known user / internal IP
  5. Explainability — structured "why this score" output

Every score decision is recorded in a ledger for audit trail.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_BASE: Dict[str, float] = {
    "critical": 90.0,
    "high":     70.0,
    "medium":   50.0,
    "low":      25.0,
    "info":     10.0,
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
    ):
        self.score            = round(min(max(score, 0.0), 100.0), 1)
        self.ledger           = ledger
        self.stage            = stage
        self.stage_cap        = stage_cap
        self.deviation_used   = deviation_used
        self.chain_depth      = chain_depth
        self.chain_multiplier = chain_multiplier

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score":             self.score,
            "stage":             self.stage,
            "stage_cap":         self.stage_cap,
            "deviation_used":    round(self.deviation_used, 3),
            "chain_depth":       self.chain_depth,
            "chain_multiplier":  self.chain_multiplier,
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

    # ── Public API ────────────────────────────────────────────────────────

    def score_burst(
        self,
        burst: Dict[str, Any],
        detections: Optional[List[Dict[str, Any]]] = None,
        deviation_score: float = 0.0,
        chain_depth: int = 1,
    ) -> ScoreResult:
        """
        Compute the full risk score for a burst.

        Args:
            burst           : Burst dict from analysis_engine
            detections      : Detection hits for events in this burst
            deviation_score : Float 0–1 from BaselineEngine
            chain_depth     : Number of distinct kill-chain stages in correlation

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

        # ── 7. Suppression check ──────────────────────────────────────────
        if self._is_suppressed(burst, detections):
            ledger.append(LedgerEntry("Suppression", -200.0, "Analyst-suppressed rule/image"))
            return ScoreResult(
                score=0.0, ledger=ledger, stage=stage,
                stage_cap=0.0, deviation_used=deviation_score,
                chain_depth=chain_depth, chain_multiplier=1.0,
            )

        # ── 8. Nonlinear interaction bonus ────────────────────────────────
        # Linear models (A + B + C) miss cases where two moderate signals
        # together are far more alarming than either alone.
        # Real attacks are multivariate — encode that interaction explicitly.
        interaction_bonus = self._compute_interaction_bonus(
            deviation_score, chain_depth, burst, ledger
        )

        # ── 9. Temporal spread bonus ──────────────────────────────────────
        # Events that are correlated across a long time window (slow attack)
        # get a score boost — slow, distributed attacks are harder to detect
        # and therefore more dangerous when finally caught.
        temporal_bonus = self._compute_temporal_bonus(burst, ledger)

        # ── 10. Data quality factor ───────────────────────────────────────
        # Not all signals are equally reliable. Fewer events = more uncertainty.
        # Reduce score when we have very little evidence, regardless of
        # what that evidence says.
        data_quality = self._compute_data_quality(burst, detections, ledger)

        # ── 11. Assemble — NO chain multiplier here (it's in correlation) ─
        pre_cap = (
            (signal * dev_mult + behavior_bonus + env_bonus + interaction_bonus + temporal_bonus)
            * context_factor
            * data_quality
        )
        pre_cap = max(pre_cap, 0.0)

        # Stage cap (lifted by chain depth, but not doubled)
        stage_cap = min(STAGE_CAPS.get(stage, 65.0) + chain_cap_lift, 100.0)

        # Deviation cap (low deviation limits score regardless of other factors)
        dev_cap = self._deviation_cap(deviation_score)

        final = min(pre_cap, stage_cap, dev_cap)

        if pre_cap > final:
            ledger.append(LedgerEntry(
                "Cap applied",
                final - pre_cap,
                f"Stage cap ({stage_cap:.0f}) or deviation cap ({dev_cap:.0f}) applied",
            ))

        return ScoreResult(
            score=final,
            ledger=ledger,
            stage=stage,
            stage_cap=stage_cap,
            deviation_used=deviation_score,
            chain_depth=chain_depth,
            chain_multiplier=1.0,   # Multiplier is owned by correlation engine
        )

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
        ledger.append(LedgerEntry("Deviation multiplier", 0.0, reason))
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
            bonus += 15.0
            ledger.append(LedgerEntry("Persistence +15", 15.0, "Persistence mechanism detected"))
        if burst.get("has_injection"):
            bonus += 25.0
            ledger.append(LedgerEntry("Injection +25", 25.0, "Process injection detected"))
        if burst.get("has_net") and dst_ip and not _is_internal_ip(dst_ip):
            bonus += 20.0
            ledger.append(LedgerEntry("External C2 +20", 20.0, f"External network: {dst_ip}"))
        elif burst.get("has_net"):
            bonus += 5.0
            ledger.append(LedgerEntry("Internal network +5", 5.0, "Internal network activity"))
        if burst.get("cmd_high_entropy") or burst.get("cmd_has_encoded_flag"):
            bonus += 10.0
            ledger.append(LedgerEntry("Encoded cmd +10", 10.0, "High-entropy or encoded command line"))
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
            ))

        # Dampen if image is a security tool
        image_name = image.split("\\")[-1] if "\\" in image else image
        if image_name in KNOWN_SECURITY_TOOLS:
            factor *= 0.5
            ledger.append(LedgerEntry(
                "Security tool −50%", 0.0,
                f"'{image_name}' is a known security/monitoring agent",
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

    factors = []
    for entry in result.ledger:
        if entry.delta > 0:
            factors.append({
                "label": entry.label,
                "value": round(entry.delta, 1),
                "color": "red" if entry.delta >= 20 else "orange" if entry.delta >= 10 else "yellow",
            })

    suggestions = []
    if not result.chain_depth or result.chain_depth < 2:
        suggestions.append("Multi-stage kill-chain progression would amplify score (1.5–4.0×)")
    if result.deviation_used < 0.6:
        suggestions.append("Higher behavioral deviation (>0.6) would raise deviation cap")

    return {
        "score":         result.score,
        "stage":         result.stage,
        "stage_cap":     result.stage_cap,
        "stage_color":   color_map.get(result.stage, "gray"),
        "chain_depth":   result.chain_depth,
        "chain_mult":    result.chain_multiplier,
        "deviation":     round(result.deviation_used, 3),
        "factors":       factors,
        "factor_sum":    sum(f["value"] for f in factors),
        "suggestions":   suggestions,
        "why":           result.to_dict()["why"],
        "alertable":     result.score >= 40,
    }
