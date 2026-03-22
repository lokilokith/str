"""
correlation_engine.py — SentinelTrace v2 Graph-Based Correlation Engine
=========================================================================
Real correlation:
  - Graph of events linked by (host, parent-child, time proximity)
  - Kill chain stage multipliers for chain depth
  - Temporal decay for distant events
  - Automatic campaign persistence
  - Human-readable campaign narratives
"""

from __future__ import annotations

import datetime
import math
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd


# ---------------------------------------------------------------------------
# Kill Chain Ordering
# ---------------------------------------------------------------------------

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

# Chain depth → confidence multiplier
# 1 stage = 1.0×, 2 stages = 1.5×, 3 stages = 2.5×, 4+ = 4.0×
_CHAIN_MULTIPLIERS = [1.0, 1.0, 1.5, 2.5, 4.0]


def _kc_index(stage: Optional[str]) -> int:
    return _KC_INDEX.get(stage or "Background", 0)


def _higher_stage(a: Optional[str], b: Optional[str]) -> str:
    return a if _kc_index(a) >= _kc_index(b) else (b or a or "Background")


# ---------------------------------------------------------------------------
# Temporal decay
# ---------------------------------------------------------------------------

DECAY_TAU_SECONDS    = 1800   # Half-life ≈ 30 minutes
EDGE_WEIGHT_THRESHOLD = 0.50  # Raised from 0.30 → tighter clustering.
                               # At 0.30 a single temporal coincidence 29 minutes
                               # apart could merge unrelated clusters.
                               # At 0.50 we only link events within ~20 minutes
                               # that also share structural or cross-signal evidence.
FORWARD_KC_BONUS     = 0.20   # Weight boost for edges that advance kill-chain stage
BACKWARD_KC_PENALTY  = 0.30   # Weight penalty for edges that go backward (anomalous)


def _temporal_weight(delta_seconds: float) -> float:
    """Exponential decay: weight → 0 as events grow apart."""
    return math.exp(-abs(delta_seconds) / DECAY_TAU_SECONDS)


# ---------------------------------------------------------------------------
# Event Node
# ---------------------------------------------------------------------------

class EventNode:
    """Lightweight wrapper around a parsed event dict for graph operations."""

    __slots__ = (
        "uid", "image", "parent_image", "computer", "user",
        "kill_chain_stage", "confidence", "ts", "event_id",
        "has_network", "has_persistence", "has_injection",
    )

    def __init__(self, event: Dict[str, Any]):
        self.uid             = event.get("event_uid") or event.get("burst_id") or str(uuid.uuid4().hex[:8])
        self.image           = (event.get("image") or "unknown").lower()
        self.parent_image    = (event.get("parent_image") or "").lower()
        self.computer        = (event.get("computer") or "unknown_host").lower()
        self.user            = (event.get("user") or "").upper()
        self.kill_chain_stage = event.get("kill_chain_stage") or "Background"
        self.confidence      = float(event.get("confidence_score") or event.get("risk_score") or 0.0)
        self.has_network     = bool(event.get("has_net") or event.get("destination_ip"))
        self.has_persistence = bool(event.get("has_persistence"))
        self.has_injection   = bool(event.get("has_injection"))
        self.event_id        = int(event.get("event_id") or 0)

        ts_raw = event.get("start_time") or event.get("utc_time") or event.get("event_time")
        try:
            self.ts = pd.to_datetime(ts_raw, errors="coerce", utc=True)
        except Exception:
            self.ts = pd.NaT


# ---------------------------------------------------------------------------
# Correlation Graph
# ---------------------------------------------------------------------------

class CorrelationGraph:
    """
    Directed graph of event nodes linked by relationship edges.

    Edge types:
      - parent_child  : same host, parent→child image relationship
      - temporal      : same host, same image, within time window
      - host_lateral  : different hosts, same user, close in time
    """

    def __init__(self, time_window_seconds: int = 900):
        self.nodes: Dict[str, EventNode] = {}
        self.edges: List[Dict[str, Any]] = []
        self.time_window = time_window_seconds

    def add_node(self, event: Dict[str, Any]) -> EventNode:
        node = EventNode(event)
        self.nodes[node.uid] = node
        return node

    def add_nodes_bulk(self, events: List[Dict[str, Any]]) -> None:
        for ev in events:
            self.add_node(ev)

    def build_edges(self) -> None:
        """
        Compute all edges with three improvements over v1:
          1. Edge weight threshold — prune weak links before clustering
          2. reason field — every edge carries a human-readable explanation
          3. Cross-signal amplification — shared suspicious properties
             (high entropy + external IP + injection) multiply edge weight
        """
        self.edges.clear()
        node_list = sorted(
            self.nodes.values(),
            key=lambda n: n.ts if pd.notna(n.ts) else pd.Timestamp.min.tz_localize("UTC"),
        )

        for i, a in enumerate(node_list):
            for j in range(i + 1, len(node_list)):
                b = node_list[j]
                if pd.isna(a.ts) or pd.isna(b.ts):
                    continue
                delta = (b.ts - a.ts).total_seconds()
                if delta > self.time_window * 4:
                    break   # Sorted by time → safe early exit

                # ── Cross-host lateral movement edge ─────────────────────
                if a.computer != b.computer:
                    if a.user and a.user == b.user and abs(delta) <= self.time_window:
                        w = _temporal_weight(delta) * 0.6
                        w = self._cross_signal_amplify(w, a, b)
                        if w >= EDGE_WEIGHT_THRESHOLD:
                            self.edges.append({
                                "from": a.uid, "to": b.uid,
                                "type": "host_lateral",
                                "weight": w,
                                "delta_sec": delta,
                                "reason": (
                                    f"Same user '{a.user}' on different hosts "
                                    f"({a.computer} → {b.computer}) within "
                                    f"{int(abs(delta))}s"
                                ),
                                "confidence_type": "behavioral",
                            })
                    continue

                # ── Parent → Child structural edge ───────────────────────
                if a.image == b.parent_image and abs(delta) <= self.time_window:
                    w = _temporal_weight(delta)
                    w = self._cross_signal_amplify(w, a, b)
                    # Directional kill-chain flow scoring
                    w = self._apply_direction_score(w, a, b)
                    if w >= EDGE_WEIGHT_THRESHOLD:
                        self.edges.append({
                            "from": a.uid, "to": b.uid,
                            "type": "parent_child",
                            "weight": w,
                            "delta_sec": delta,
                            "reason": (
                                f"'{a.image}' spawned '{b.image}' "
                                f"{int(abs(delta))}s later (parent-child)"
                            ),
                            "confidence_type": "structural",
                            "direction": "forward" if _kc_index(b.kill_chain_stage) >= _kc_index(a.kill_chain_stage) else "backward",
                        })

                # ── Temporal co-occurrence edge (same image, same host) ───
                elif a.image == b.image and abs(delta) <= self.time_window:
                    w = _temporal_weight(delta) * 0.5
                    w = self._cross_signal_amplify(w, a, b)
                    w = self._apply_direction_score(w, a, b)
                    if w >= EDGE_WEIGHT_THRESHOLD:
                        self.edges.append({
                            "from": a.uid, "to": b.uid,
                            "type": "temporal",
                            "weight": w,
                            "delta_sec": delta,
                            "reason": (
                                f"'{a.image}' active twice within "
                                f"{int(abs(delta))}s on {a.computer}"
                            ),
                            "confidence_type": "temporal",
                            "direction": "forward" if _kc_index(b.kill_chain_stage) >= _kc_index(a.kill_chain_stage) else "backward",
                        })

    @staticmethod
    def _apply_direction_score(weight: float, a: "EventNode", b: "EventNode") -> float:
        """
        Real attacks are directional — they advance through the kill chain.
        Reward forward progression; penalize backward links.

        forward: b's stage index ≥ a's stage index  (Execution → Persistence → C2)
        backward: b's stage index < a's stage index  (suspicious — possibly noise)

        A backward link (e.g. C2 → Execution in time) is structurally odd;
        it slightly reduces the edge weight to prevent weak backward chains
        from merging unrelated clusters.
        """
        a_idx = _kc_index(a.kill_chain_stage)
        b_idx = _kc_index(b.kill_chain_stage)
        if b_idx > a_idx:
            return weight * (1.0 + FORWARD_KC_BONUS)    # Kill-chain advance → boost
        elif b_idx < a_idx:
            return weight * (1.0 - BACKWARD_KC_PENALTY)  # Backward → slight penalty
        return weight   # Same stage → neutral
        """
        Boost edge weight when both nodes share suspicious properties.
        This is the cross-signal correlation the v1 engine lacked entirely:
        injection + external network + high stage together means much more
        than each does alone.
        """
        shared_signals = sum([
            a.has_injection and b.has_injection,
            a.has_network   and b.has_network,
            a.has_persistence and b.has_persistence,
            # High kill-chain stage on both ends
            _kc_index(a.kill_chain_stage) >= 5 and _kc_index(b.kill_chain_stage) >= 5,
        ])
        if shared_signals >= 3:
            return weight * 2.0   # Very strong shared signal → double weight
        if shared_signals == 2:
            return weight * 1.5
        if shared_signals == 1:
            return weight * 1.2
        return weight

    def connected_components(self) -> List[Set[str]]:
        """Union-Find connected components with path compression + union-by-rank."""
        parent: Dict[str, str] = {uid: uid for uid in self.nodes}
        rank:   Dict[str, int] = {uid: 0   for uid in self.nodes}

        def find(x: str) -> str:
            # Path halving — points every other node directly at root
            # Amortized O(α(n)) — practically constant for any realistic dataset
            while parent[x] != x:
                parent[x] = parent[parent[x]]   # grandparent hop
                x = parent[x]
            return x

        def union(x: str, y: str) -> None:
            # Union by rank — attach shorter tree under taller to keep trees flat
            rx, ry = find(x), find(y)
            if rx == ry:
                return
            if rank[rx] < rank[ry]:
                rx, ry = ry, rx          # ensure rx has higher rank
            parent[ry] = rx              # attach ry under rx
            if rank[rx] == rank[ry]:
                rank[rx] += 1            # only increment when ranks were equal

        for edge in self.edges:
            if edge["from"] in parent and edge["to"] in parent:
                union(edge["from"], edge["to"])

        groups: Dict[str, Set[str]] = defaultdict(set)
        for uid in self.nodes:
            groups[find(uid)].add(uid)

        return [g for g in groups.values() if len(g) >= 2]


# ---------------------------------------------------------------------------
# Campaign Builder
# ---------------------------------------------------------------------------

class CampaignBuilder:
    """
    Converts connected components into scored, annotated campaigns.
    """

    def build_campaigns(
        self,
        graph: CorrelationGraph,
        run_id: str,
    ) -> List[Dict[str, Any]]:
        components = graph.connected_components()
        campaigns  = []

        for component_uids in components:
            nodes = [graph.nodes[uid] for uid in component_uids if uid in graph.nodes]
            if not nodes:
                continue

            campaign = self._score_component(nodes, graph, run_id)
            if campaign:
                campaigns.append(campaign)

        return sorted(campaigns, key=lambda c: -c["confidence"])

    def _score_component(
        self,
        nodes: List[EventNode],
        graph: CorrelationGraph,
        run_id: str,
    ) -> Optional[Dict[str, Any]]:
        if not nodes:
            return None

        # ── Kill chain analysis ───────────────────────────────────────────
        stages = list({n.kill_chain_stage for n in nodes})
        stage_indices = sorted([_kc_index(s) for s in stages], reverse=True)
        highest_stage = KILL_CHAIN_ORDER[stage_indices[0]] if stage_indices else "Execution"
        chain_depth   = len(set(stage_indices))
        multiplier    = _CHAIN_MULTIPLIERS[min(chain_depth, len(_CHAIN_MULTIPLIERS) - 1)]

        # ── Base confidence ───────────────────────────────────────────────
        base = max((n.confidence for n in nodes), default=0.0)
        if base == 0:
            base = 30.0   # Structural correlation even without prior score

        # ── Behavioral bonuses ────────────────────────────────────────────
        bonus = 0.0
        if any(n.has_persistence for n in nodes):
            bonus += 15.0
        if any(n.has_injection for n in nodes):
            bonus += 25.0
        if any(n.has_network for n in nodes):
            bonus += 10.0
        if any(n.event_id in {8, 9, 25} for n in nodes):   # Critical EIDs
            bonus += 20.0

        # ── Edge weight sum + directional flow bonus ──────────────────────
        node_uids = {n.uid for n in nodes}
        forward_count  = 0
        backward_count = 0
        edge_weight    = 0.0
        for e in graph.edges:
            if e["from"] in node_uids and e["to"] in node_uids:
                edge_weight += e["weight"]
                if e.get("direction") == "forward":
                    forward_count += 1
                elif e.get("direction") == "backward":
                    backward_count += 1

        edge_bonus = min(edge_weight * 5.0, 20.0)

        # Pure forward kill-chain flow → additional confidence bonus
        direction_bonus = 0.0
        if forward_count > 0 and backward_count == 0:
            direction_bonus = min(forward_count * 5.0, 15.0)
            # Perfect forward chain is a very strong attack indicator

        # ── Final score ───────────────────────────────────────────────────
        final = min((base + bonus + edge_bonus + direction_bonus) * multiplier, 100.0)

        # ── Temporal metadata ─────────────────────────────────────────────
        valid_ts = [n.ts for n in nodes if pd.notna(n.ts)]
        first_seen = min(valid_ts).isoformat() if valid_ts else None
        last_seen  = max(valid_ts).isoformat() if valid_ts else None

        # ── Computers / users ─────────────────────────────────────────────
        computers = sorted({n.computer for n in nodes})
        users     = sorted({n.user for n in nodes if n.user})
        images    = sorted({n.image for n in nodes})

        # ── Narrative ─────────────────────────────────────────────────────
        narrative = self._build_narrative(nodes, highest_stage, chain_depth, multiplier)

        # ── Correlation ID ────────────────────────────────────────────────
        import re as _re
        day = datetime.datetime.utcnow().strftime("%Y%m%d")
        base_image = nodes[0].image
        # Sanitize: strip everything except alphanumeric and underscore
        _safe_img  = _re.sub(r"[^a-z0-9]", "_", base_image[:12].lower())
        _safe_host = _re.sub(r"[^a-z0-9]", "_", computers[0][:8].lower())
        corr_id    = f"CAMP-{_safe_img}-{_safe_host}-{day}"

        return {
            "corr_id":           corr_id,
            "run_id":            run_id,
            "base_image":        base_image,
            "images":            images,
            "computers":         computers,
            "users":             users,
            "first_seen":        first_seen,
            "last_seen":         last_seen,
            "event_count":       len(nodes),
            "chain_depth":       chain_depth,
            "chain_multiplier":  multiplier,
            "kill_chain_stages": stages,
            "highest_stage":     highest_stage,
            "confidence":        round(final, 1),
            "has_persistence":   any(n.has_persistence for n in nodes),
            "has_injection":     any(n.has_injection for n in nodes),
            "has_network":       any(n.has_network for n in nodes),
            "narrative":         narrative,
            "node_uids":         [n.uid for n in nodes],
            "status":            "active",
        }

    @staticmethod
    def _build_narrative(
        nodes: List[EventNode],
        highest_stage: str,
        chain_depth: int,
        multiplier: float,
    ) -> str:
        images  = sorted({n.image for n in nodes})
        stages  = sorted({n.kill_chain_stage for n in nodes}, key=_kc_index)
        host    = nodes[0].computer

        parts = [
            f"Multi-event correlation on {host} involving {len(images)} process(es): "
            f"{', '.join(images[:3])}{'...' if len(images) > 3 else ''}.",
            f"Kill-chain stages detected: {' → '.join(stages)}.",
        ]
        if chain_depth >= 3:
            parts.append(
                f"Chain depth {chain_depth} with {multiplier:.1f}× confidence amplification — "
                f"strong multi-stage attack indicator."
            )
        elif chain_depth == 2:
            parts.append("Two-stage kill chain observed — investigation warranted.")
        if any(n.has_injection for n in nodes):
            parts.append("Process injection detected — likely privilege escalation or evasion.")
        if any(n.has_persistence for n in nodes):
            parts.append("Persistence mechanism observed — attacker likely establishing foothold.")
        if any(n.has_network for n in nodes):
            parts.append("Network activity present — possible C2 or data staging.")

        return " ".join(parts)


# ---------------------------------------------------------------------------
# DB Persistence
# ---------------------------------------------------------------------------

def _decay_stale_campaigns(conn: Any, mode: str, run_id: str) -> None:
    """
    Reduce confidence of campaigns not seen in 24 hours (lifecycle decay).
    Campaigns that persist but don't re-trigger gradually lose confidence —
    this prevents stale detections from looking as urgent as fresh ones.
    Campaigns below a minimum confidence floor are marked dormant.
    """
    try:
        from dashboard.db import get_cursor, sql_now_minus
        DECAY_PCT     = 0.90   # Each decay cycle reduces confidence by 10%
        MIN_CONFIDENCE = 20    # Below this → mark dormant
        with get_cursor(conn) as cur:
            # Use FLOOR() not CAST AS UNSIGNED — UNSIGNED wraps negative values
            # to enormous numbers, corrupting confidence scores on edge cases.
            cur.execute(
                f"UPDATE correlation_campaigns "
                f"SET max_confidence = GREATEST("
                f"  FLOOR(max_confidence * {DECAY_PCT}), {MIN_CONFIDENCE}"
                f"), "
                f"status = CASE "
                f"  WHEN FLOOR(max_confidence * {DECAY_PCT}) <= {MIN_CONFIDENCE} "
                f"  THEN 'dormant' ELSE status END "
                f"WHERE run_id = %s "
                f"AND status = 'active' "
                f"AND last_seen < {sql_now_minus(24, 'HOUR')}",
                (run_id,),
            )
    except Exception as e:
        print(f"[CorrelationEngine] decay failed: {e}")


def persist_campaigns(campaigns: List[Dict[str, Any]]) -> None:
    """Write / update campaigns in sentinel_live (or sentinel_cases for uploads)."""
    if not campaigns:
        return

    try:
        from dashboard.db import get_db_connection, get_cursor, checked_insert, now_utc, sanitize_datetime

        run_id = campaigns[0].get("run_id", "live")
        mode   = "live" if run_id == "live" else "cases"
        now    = now_utc()

        with get_db_connection(mode) as conn:
            # Lifecycle decay: stale campaigns lose confidence gradually
            _decay_stale_campaigns(conn, mode, run_id)
            with get_cursor(conn) as cur:
                for camp in campaigns:
                    cid = camp["corr_id"]
                    cur.execute(
                        "SELECT burst_count, max_confidence, highest_kill_chain "
                        "FROM correlation_campaigns WHERE corr_id = %s AND run_id = %s",
                        (cid, run_id),
                    )
                    row = cur.fetchone()
                    new_conf  = int(camp["confidence"])
                    new_stage = camp["highest_stage"]

                    if row:
                        final_stage = _higher_stage(row["highest_kill_chain"], new_stage)
                        cur.execute(
                            "UPDATE correlation_campaigns SET "
                            "burst_count=%s, last_seen=%s, max_confidence=%s, "
                            "highest_kill_chain=%s, status='active', description=%s "
                            "WHERE corr_id=%s AND run_id=%s",
                            (
                                row["burst_count"] + 1,
                                now,
                                max(row["max_confidence"], new_conf),
                                final_stage,
                                camp.get("narrative", ""),
                                cid, run_id,
                            ),
                        )
                    else:
                        checked_insert(
                            cur, "correlation_campaigns",
                            ["corr_id", "run_id", "base_image", "computer",
                             "first_seen", "last_seen", "burst_count",
                             "max_confidence", "highest_kill_chain", "status", "description"],
                            (
                                cid, run_id,
                                camp.get("base_image"),
                                camp.get("computers", ["unknown"])[0],
                                sanitize_datetime(camp.get("first_seen")),
                                sanitize_datetime(camp.get("last_seen")),
                                1, new_conf, new_stage, "active",
                                camp.get("narrative", ""),
                            ),
                            identity_hint=f"corr_id={cid}",
                        )

                    # Detail row in correlations table
                    cur.execute(
                        "INSERT INTO `correlations` "
                        "(`corr_id`,`run_id`,`base_image`,`start_time`,`end_time`,"
                        "`description`,`event_ids`,`computer`,`kill_chain_stage`,"
                        "`severity`,`confidence`) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            cid, run_id,
                            camp.get("base_image"),
                            sanitize_datetime(camp.get("first_seen")),
                            sanitize_datetime(camp.get("last_seen")),
                            camp.get("narrative", ""),
                            ",".join(camp.get("node_uids", [])[:20]),
                            camp.get("computers", ["unknown"])[0],
                            new_stage,
                            "high" if new_conf >= 70 else "medium" if new_conf >= 40 else "low",
                            new_conf,
                        ),
                    )
            conn.commit()
    except Exception as e:
        import traceback
        print(f"[CorrelationEngine] persist_campaigns failed: {e}")
        traceback.print_exc()


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------

def correlate_events(
    events: List[Dict[str, Any]],
    run_id: str,
    time_window_seconds: int = 900,
    persist: bool = True,
) -> List[Dict[str, Any]]:
    """
    Full correlation pipeline.

    Args:
        events            : List of event/burst dicts (must have event_uid, image, etc.)
        run_id            : Analysis run identifier
        time_window_seconds : Max time gap to consider two events correlated
        persist           : Whether to write campaigns to DB

    Returns:
        List of campaign dicts sorted by confidence descending.
    """
    if not events:
        return []

    # Filter out events with no meaningful identity — they produce orphan nodes
    # that inflate component counts without adding real correlation signal.
    valid_events = [e for e in events if e.get("image") or e.get("event_uid")]
    if not valid_events:
        return []

    graph = CorrelationGraph(time_window_seconds=time_window_seconds)
    graph.add_nodes_bulk(valid_events)
    graph.build_edges()

    builder   = CampaignBuilder()
    campaigns = builder.build_campaigns(graph, run_id)

    # Tag source events with their campaign id
    uid_to_camp: Dict[str, str] = {}
    for camp in campaigns:
        for uid in camp.get("node_uids", []):
            uid_to_camp[uid] = camp["corr_id"]

    for ev in events:
        uid = ev.get("event_uid") or ev.get("burst_id")
        if uid and uid in uid_to_camp:
            ev["correlation_id"]    = uid_to_camp[uid]
            ev["has_correlation"]   = True
            ev["correlation_score"] = next(
                (c["confidence"] for c in campaigns if c["corr_id"] == uid_to_camp[uid]),
                0,
            )

    if persist and campaigns:
        persist_campaigns(campaigns)

    return campaigns


def correlate_bursts(
    bursts: List[Dict[str, Any]],
    run_id: str,
    time_window_seconds: int = 900,
    persist: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Wrapper for burst-level correlation (used by analysis_engine).
    Maps burst dicts → event dicts, runs correlation, returns
    (updated_bursts, campaigns).
    """
    # Ensure burst dicts have the fields EventNode expects
    mapped = []
    for b in bursts:
        mapped.append({
            "event_uid":        b.get("burst_id") or b.get("correlation_id") or uuid.uuid4().hex[:12],
            "image":            b.get("image"),
            "parent_image":     b.get("parent_image"),
            "computer":         b.get("computer"),
            "user":             b.get("user"),
            "kill_chain_stage": b.get("kill_chain_stage") or "Execution",
            "confidence_score": b.get("risk_score") or 0,
            "has_net":          b.get("has_net"),
            "has_persistence":  b.get("has_persistence"),
            "has_injection":    b.get("has_injection"),
            "event_id":         (b.get("event_ids") or [0])[0] if b.get("event_ids") else 0,
            "start_time":       b.get("start_time"),
            "utc_time":         b.get("start_time"),
            "destination_ip":   b.get("destination_ip"),
            "_burst_ref":       b,   # back-reference so we can mutate original
        })

    campaigns = correlate_events(mapped, run_id, time_window_seconds, persist)

    # Propagate correlation metadata back to original bursts
    for m in mapped:
        original = m.get("_burst_ref")
        if original is not None:
            original["correlation_id"]    = m.get("correlation_id")
            original["has_correlation"]   = m.get("has_correlation", False)
            original["correlation_score"] = m.get("correlation_score", 0)

    return bursts, campaigns
