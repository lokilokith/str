"""
scoring_engine.py — SentinelTrace v2.2
=======================================
Multi-signal fusion scoring engine.

v2.2 upgrades over v2.0:
  - compute_final_score(): true weighted fusion of rule_score, baseline
    deviation, sequence anomaly, YARA score, and kill-chain stage multipliers.
    Credential Access gets 1.5×, Lateral Movement 1.3×, C2 1.2×.
  - Rule stacking: aggregate_rule_hits() rewards rule diversity (3+ distinct
    rules = 1.3× multiplier) and adds contextual boosts for encoded flags,
    LOLBins, external IPs, and suspicious parent chains.
  - Noise gate: no detections + deviation < 0.30 = score 0 immediately.
  - Stage caps respected; deviation cap raised from 35 → 50 for <0.3 tier.
  - LedgerEntry gains a `category` field for structured dashboard display.
  - _context_factor gains high-volume process dampening.
  - Interaction bonus cases changed from elif → if (all can stack).
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

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
    "Background", "Delivery", "Execution", "Defense Evasion",
    "Persistence", "Privilege Escalation", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Actions on Objectives",
]

_KC_INDEX: Dict[str, int] = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

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

# Kill-chain stage score multipliers — high-value stages get a risk boost
STAGE_MULTIPLIERS: Dict[str, float] = {
    "Credential Access":    1.50,
    "Lateral Movement":     1.30,
    "Command and Control":  1.20,
    "Exfiltration":         1.40,
    "Actions on Objectives":1.50,
    "Privilege Escalation": 1.15,
    "Persistence":          1.10,
}

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
        cats: Dict[str, List[str]] = {}
        for e in self.ledger:
            cats.setdefault(e.category, []).append(e.reason)
        return {
            "score":            self.score,
            "stage":            self.stage,
            "stage_cap":        self.stage_cap,
            "deviation_used":   round(self.deviation_used, 3),
            "chain_depth":      self.chain_depth,
            "chain_multiplier": self.chain_multiplier,
            "ledger":           [e.to_dict() for e in self.ledger],
            "why":              [e.reason for e in self.ledger if e.delta != 0],
            "explanation":      cats,
        }


# ---------------------------------------------------------------------------
# Rule stacking helper  ← NEW
# ---------------------------------------------------------------------------

def aggregate_rule_hits(
    event: Dict[str, Any],
    matched_rules: List[Dict[str, Any]],
) -> float:
    """
    Aggregate multiple rule hits into a single rule score.

    Scoring:
      - Base = sum of individual rule confidences (not max, not average)
      - Rule diversity bonus: ≥3 distinct rule_ids → 1.3× multiplier
      - Contextual boosts for strong signals present on the event
      - Result capped at 100

    This replaces single-rule-trigger = single confidence value.
    """
    if not matched_rules:
        return 0.0

    base = sum(float(r.get("confidence_score") or r.get("confidence") or 50) for r in matched_rules)

    # Diversity bonus — multi-technique attack is more alarming
    diversity = len(set(r.get("rule_id", "") for r in matched_rules))
    if diversity >= 3:
        base *= 1.3
    elif diversity == 2:
        base *= 1.15

    # Contextual boosts from parser-enriched event signals
    if event.get("has_encoded_flag") or event.get("cmd_has_encoded_flag"):
        base += 10
    if event.get("is_lolbin"):
        lw = float(event.get("lolbin_weight") or 0.5)
        base += 5 + (lw * 10)   # 5–15 pts based on LOLBin risk
    if event.get("is_external_ip"):
        base += 10
    if event.get("is_suspicious_chain"):
        base += 5
    if event.get("b64_detected") or event.get("cmd_b64_detected"):
        base += 8
    if event.get("is_high_entropy") or event.get("cmd_high_entropy"):
        base += 7

    return float(min(base, 100.0))


def compute_final_score(event: Dict[str, Any]) -> int:
    """
    True multi-signal fusion scoring.

    Weights:
      35% rule score        (YAML / YARA rule hits aggregated)
      25% sequence score    (n-gram chain anomaly from baseline)
      25% behavior score    (Welford deviation × 100)
      10% YARA score        (YARA match count × 20, capped at 60)
       5% feedback adj      (analyst verdict reinforcement signal)

    Then applies kill-chain stage multipliers for high-value stages.
    """
    rule_score     = float(event.get("rule_score") or 0)
    seq_score      = float(event.get("sequence_score") or 0)
    behavior_score = float(event.get("behavior_score") or event.get("deviation_score") or 0) * 100
    yara_score     = float(event.get("yara_score") or 0)
    feedback_adj   = float(event.get("feedback_adj") or 0)

    score = (
        0.35 * rule_score +
        0.25 * seq_score +
        0.25 * behavior_score +
        0.10 * yara_score +
        0.05 * feedback_adj
    )

    # Kill-chain stage risk multiplier
    stage = event.get("kill_chain_stage") or "Execution"
    mult  = STAGE_MULTIPLIERS.get(stage, 1.0)
    score *= mult

    return int(min(score, 100))


# ---------------------------------------------------------------------------
# Scoring Engine
# ---------------------------------------------------------------------------

class ScoringEngine:
    def __init__(
        self,
        suppressions: Optional[List[Dict[str, str]]] = None,
        host_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.suppressions  = suppressions or []
        self.host_profiles = host_profiles or {}

    def score_burst(
        self,
        burst: Dict[str, Any],
        detections: Optional[List[Dict[str, Any]]] = None,
        deviation_score: float = 0.0,
        chain_depth: int = 1,
    ) -> ScoreResult:
        ledger: List[LedgerEntry] = []
        dets = detections or []

        image    = (burst.get("image") or "").lower()
        parent   = (burst.get("parent_image") or "").lower()
        computer = (burst.get("computer") or "").lower()
        stage    = burst.get("kill_chain_stage") or "Execution"
        dst_ip   = burst.get("destination_ip") or ""
        user     = (burst.get("user") or "").upper()

        # ── Noise gate ────────────────────────────────────────────────────
        if not dets and deviation_score < 0.30:
            ledger.append(LedgerEntry(
                "Noise gate", 0.0,
                "No detections and deviation < 0.30 — background noise",
                "other",
            ))
            return ScoreResult(
                score=0.0, ledger=ledger, stage=stage,
                stage_cap=STAGE_CAPS.get(stage, 65.0),
                deviation_used=deviation_score,
                chain_depth=chain_depth, chain_multiplier=1.0,
            )

        # ── 1. Rule signal (stacked) ──────────────────────────────────────
        signal = self._compute_signal(burst, dets, ledger)

        # ── 2. Deviation multiplier ───────────────────────────────────────
        dev_mult = self._deviation_multiplier(deviation_score, ledger)

        # ── 3. Behavioral bonuses ─────────────────────────────────────────
        behavior_bonus = self._behavior_bonus(burst, dst_ip, ledger)

        # ── 4. Chain depth cap lift ───────────────────────────────────────
        chain_cap_lift = 0.0
        if chain_depth >= 2:
            chain_cap_lift = min((chain_depth - 1) * 8.0, 20.0)
            ledger.append(LedgerEntry(
                "Chain depth cap lift", chain_cap_lift,
                f"Kill-chain depth {chain_depth} → cap +{chain_cap_lift:.0f}",
                "chain",
            ))

        # ── 5. Context dampening ──────────────────────────────────────────
        context_factor = self._context_factor(image, parent, computer, user, dst_ip, burst, ledger)

        # ── 6. Environment profile ────────────────────────────────────────
        env_bonus = self._env_bonus(computer, stage, image, ledger)

        # ── 7. Suppression check ──────────────────────────────────────────
        if self._is_suppressed(burst, dets):
            ledger.append(LedgerEntry("Suppression", -200.0, "Analyst-suppressed", "other"))
            return ScoreResult(
                score=0.0, ledger=ledger, stage=stage,
                stage_cap=0.0, deviation_used=deviation_score,
                chain_depth=chain_depth, chain_multiplier=1.0,
            )

        # ── 8. Nonlinear interaction bonuses (all cases independent) ──────
        interaction_bonus = self._compute_interaction_bonus(deviation_score, chain_depth, burst, ledger)

        # ── 9. Temporal spread bonus ──────────────────────────────────────
        temporal_bonus = self._compute_temporal_bonus(burst, ledger)

        # ── 10. Data quality factor ───────────────────────────────────────
        data_quality = self._compute_data_quality(burst, dets, ledger)

        # ── 11. Kill-chain stage risk multiplier ──────────────────────────
        stage_mult = STAGE_MULTIPLIERS.get(stage, 1.0)
        if stage_mult > 1.0:
            ledger.append(LedgerEntry(
                f"Stage multiplier ×{stage_mult}", 0.0,
                f"{stage} stage carries {stage_mult}× risk weight",
                "signal",
            ))

        # ── 12. Assemble ──────────────────────────────────────────────────
        pre_cap = (
            (signal * dev_mult + behavior_bonus + env_bonus + interaction_bonus + temporal_bonus)
            * context_factor
            * data_quality
            * stage_mult
        )
        pre_cap = max(pre_cap, 0.0)

        stage_cap = min(STAGE_CAPS.get(stage, 65.0) + chain_cap_lift, 100.0)
        dev_cap   = self._deviation_cap(deviation_score)
        final     = min(pre_cap, stage_cap, dev_cap)

        if pre_cap > final:
            ledger.append(LedgerEntry(
                "Cap applied", final - pre_cap,
                f"Stage cap ({stage_cap:.0f}) or deviation cap ({dev_cap:.0f})",
                "other",
            ))

        return ScoreResult(
            score=final, ledger=ledger, stage=stage, stage_cap=stage_cap,
            deviation_used=deviation_score, chain_depth=chain_depth, chain_multiplier=1.0,
        )

    # ── Internal helpers ──────────────────────────────────────────────────

    def _compute_signal(self, burst, detections, ledger):
        dets = detections or []
        if dets:
            # Use aggregate_rule_hits for proper stacking
            rule_agg = aggregate_rule_hits(burst, dets)
            max_sev  = max(
                SEVERITY_BASE.get((d.get("severity") or "low").lower(), 25.0)
                for d in dets
            )
            # Take higher of aggregated rule score or raw severity signal
            max_sev_score = max(rule_agg, max_sev)
        else:
            sev = (burst.get("severity") or "low").lower()
            max_sev_score = SEVERITY_BASE.get(sev, 25.0)

        count         = int(burst.get("count") or burst.get("total_count") or 1)
        vol_score     = min(math.log10(count + 1) * 8.0, 20.0)
        unique_rules  = len(set(d.get("rule_id", "") for d in dets if d.get("rule_id")))
        diversity_bonus = min(unique_rules * 5.0, 20.0)

        total = max_sev_score + vol_score + diversity_bonus
        ledger.append(LedgerEntry(
            "Signal (rules + volume + diversity)", total,
            f"rule_agg={max_sev_score:.0f} vol={vol_score:.1f} diversity={diversity_bonus:.0f} ({unique_rules} rules)",
            "signal",
        ))
        return total

    def _deviation_multiplier(self, deviation_score, ledger):
        if deviation_score < 0.3:
            mult, reason = 0.8,  f"Low deviation ({deviation_score:.2f}) → 0.8×"
        elif deviation_score < 0.6:
            mult, reason = 1.0,  f"Moderate deviation ({deviation_score:.2f}) → neutral"
        elif deviation_score < 0.8:
            mult, reason = 1.25, f"High deviation ({deviation_score:.2f}) → 1.25×"
        else:
            mult, reason = 1.5,  f"Very high deviation ({deviation_score:.2f}) → 1.5×"
        ledger.append(LedgerEntry("Deviation multiplier", 0.0, reason, "baseline"))
        return mult

    @staticmethod
    def _deviation_cap(deviation_score: float) -> float:
        if deviation_score < 0.3:  return 50.0
        if deviation_score < 0.6:  return 65.0
        if deviation_score < 0.8:  return 85.0
        return 100.0

    def _behavior_bonus(self, burst, dst_ip, ledger):
        bonus = 0.0
        if burst.get("has_persistence"):
            bonus += 15.0
            ledger.append(LedgerEntry("Persistence +15", 15.0, "Persistence mechanism", "behavior"))
        if burst.get("has_injection"):
            bonus += 25.0
            ledger.append(LedgerEntry("Injection +25", 25.0, "Process injection", "behavior"))
        if burst.get("has_net") and dst_ip and not _is_internal_ip(dst_ip):
            bonus += 20.0
            ledger.append(LedgerEntry("External C2 +20", 20.0, f"External IP: {dst_ip}", "behavior"))
        elif burst.get("has_net"):
            bonus += 5.0
            ledger.append(LedgerEntry("Internal net +5", 5.0, "Internal network", "behavior"))
        if burst.get("cmd_high_entropy") or burst.get("has_encoded_flag") or burst.get("cmd_has_encoded_flag"):
            bonus += 10.0
            ledger.append(LedgerEntry("Encoded cmd +10", 10.0, "High-entropy/encoded command", "behavior"))
        if burst.get("is_lolbin"):
            lw = float(burst.get("lolbin_weight") or 0.5)
            lb = round(lw * 8, 1)
            bonus += lb
            ledger.append(LedgerEntry(f"LOLBin +{lb}", lb, f"LOLBin weight={lw:.1f}", "behavior"))
        return bonus

    def _context_factor(self, image, parent, computer, user, dst_ip, burst, ledger):
        factor = 1.0
        parent_name = parent.split("\\")[-1] if "\\" in parent else parent
        if parent_name in KNOWN_BENIGN_PARENTS:
            factor *= 0.85
            ledger.append(LedgerEntry("Benign parent -15%", 0.0, f"Parent '{parent_name}'", "context"))
        image_name = image.split("\\")[-1] if "\\" in image else image
        if image_name in KNOWN_SECURITY_TOOLS:
            factor *= 0.5
            ledger.append(LedgerEntry("Security tool -50%", 0.0, f"'{image_name}' is monitoring agent", "context"))
        if "SYSTEM" in user and (not dst_ip or _is_internal_ip(dst_ip)):
            factor *= 0.75
            ledger.append(LedgerEntry("SYSTEM+internal -25%", 0.0, "SYSTEM background service", "context"))
        total_count = int(burst.get("count") or burst.get("total_count") or 0)
        if total_count > 500 and factor > 0.5:
            factor *= 0.85
            ledger.append(LedgerEntry("High-volume -15%", 0.0, f"{total_count} events — noisy process", "context"))
        return factor

    def _env_bonus(self, computer, stage, image, ledger):
        profile = self.host_profiles.get(computer)
        if not profile:
            return 0.0
        bonus = 0.0
        if profile.get("critical_asset"):
            bonus += 10.0
            ledger.append(LedgerEntry("Critical asset +10", 10.0, f"{computer} is critical", "other"))
        if profile.get("profile_type", "").lower() == "server":
            if any(x in image for x in ["powershell", "cmd", "wmic", "psexec"]):
                bonus += 15.0
                ledger.append(LedgerEntry("Server shell +15", 15.0, f"Admin tool on server {computer}", "other"))
        return bonus

    def _compute_interaction_bonus(self, deviation_score, chain_depth, burst, ledger):
        """All three cases are independent and can stack."""
        bonus = 0.0
        has_persistence = bool(burst.get("has_persistence"))
        has_injection   = bool(burst.get("has_injection"))
        has_behavioral  = has_persistence or has_injection or bool(burst.get("has_net"))

        # Case 1: statistical anomaly + structural chain
        if deviation_score >= 0.6 and chain_depth >= 2:
            bonus += 15.0
            ledger.append(LedgerEntry("deviation×chain +15", 15.0, f"deviation={deviation_score:.2f} chain={chain_depth}", "other"))

        # Case 2: statistical anomaly + behavioral indicator (independent)
        if deviation_score >= 0.6 and has_behavioral:
            bonus += 10.0
            ledger.append(LedgerEntry("deviation×behavior +10", 10.0, f"deviation={deviation_score:.2f} persist={has_persistence} inject={has_injection}", "other"))

        # Case 3: deep chain + behavioral indicator (independent)
        if chain_depth >= 2 and has_behavioral:
            bonus += 8.0
            ledger.append(LedgerEntry("chain×behavior +8", 8.0, f"chain={chain_depth} persist={has_persistence} inject={has_injection}", "other"))

        return bonus

    def _compute_temporal_bonus(self, burst, ledger):
        if not burst.get("has_correlation"):
            return 0.0
        start, end = burst.get("start_time"), burst.get("end_time")
        if not start or not end:
            return 0.0
        try:
            t0 = pd.to_datetime(start, errors="coerce", utc=True)
            t1 = pd.to_datetime(end,   errors="coerce", utc=True)
            if pd.isna(t0) or pd.isna(t1):
                return 0.0
            span = (t1 - t0).total_seconds() / 60.0
        except Exception:
            return 0.0
        if span < 30:
            return 0.0
        bonus = min((span - 30) / 30.0 * 5.0, 10.0)
        ledger.append(LedgerEntry(f"Temporal +{bonus:.0f}", bonus, f"Sustained campaign {span:.0f}min", "other"))
        return bonus

    def _compute_data_quality(self, burst, detections, ledger):
        event_count = int(burst.get("count") or burst.get("total_count") or 0)
        det_count   = len(detections or [])
        if event_count >= 5 and det_count >= 2:
            return 1.00
        if event_count >= 3 or det_count >= 1:
            ledger.append(LedgerEntry("Quality 0.90×", 0.0, f"{event_count} events, {det_count} dets", "other"))
            return 0.90
        ledger.append(LedgerEntry("Quality 0.75×", 0.0, f"Thin: {event_count} events, {det_count} dets", "other"))
        return 0.75

    def score_detections(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        scored = []
        for det in detections:
            sev      = (det.get("severity") or "low").lower()
            base     = SEVERITY_BASE.get(sev, 25.0)
            stage    = det.get("kill_chain_stage") or "Execution"
            kc_bonus = max(0, _KC_INDEX.get(stage, 2) - 2) * 5.0
            final    = min(base + kc_bonus, 100.0)
            scored.append({**det, "confidence_score": round(final, 1)})
        return scored

    def _is_suppressed(self, burst, detections):
        if not self.suppressions:
            return False
        import fnmatch
        image = burst.get("image") or ""
        for sup in self.suppressions:
            rule_id = sup.get("rule_id")
            pat     = sup.get("image_pattern", "*")
            for det in (detections or []):
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
    global _scoring_engine
    if _scoring_engine is None:
        _scoring_engine = ScoringEngine(
            suppressions=suppressions or [],
            host_profiles=host_profiles or {},
        )
    return _scoring_engine


def reset_scoring_engine() -> None:
    global _scoring_engine
    _scoring_engine = None


def explain_score(result: ScoreResult) -> Dict[str, Any]:
    color_map = {
        "Actions on Objectives": "red", "Exfiltration": "red",
        "Command and Control": "red", "Lateral Movement": "orange",
        "Credential Access": "orange", "Persistence": "orange",
        "Privilege Escalation": "orange", "Defense Evasion": "yellow",
        "Execution": "yellow",
    }
    factors = [
        {"label": e.label, "value": round(e.delta, 1),
         "color": "red" if e.delta >= 20 else "orange" if e.delta >= 10 else "yellow",
         "category": e.category}
        for e in result.ledger if e.delta > 0
    ]
    suggestions = []
    if result.chain_depth < 2:
        suggestions.append("Multi-stage kill-chain would amplify score (1.5–4.0×)")
    if result.deviation_used < 0.6:
        suggestions.append("Higher baseline deviation (>0.6) lifts the deviation cap")
    return {
        "score":       result.score,
        "stage":       result.stage,
        "stage_cap":   result.stage_cap,
        "stage_color": color_map.get(result.stage, "gray"),
        "chain_depth": result.chain_depth,
        "chain_mult":  result.chain_multiplier,
        "deviation":   round(result.deviation_used, 3),
        "factors":     factors,
        "factor_sum":  sum(f["value"] for f in factors),
        "suggestions": suggestions,
        "why":         result.to_dict()["why"],
        "explanation": result.to_dict()["explanation"],
        "alertable":   result.score >= 40,
    }
