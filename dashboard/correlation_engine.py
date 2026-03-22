"""
correlation_engine.py — SentinelTrace v2 Graph-Based Correlation Engine
=========================================================================
Real correlation:
  - Graph of events linked by (host, parent-child, time proximity)
  - Kill chain stage multipliers for chain depth
  - Temporal decay for distant events
  - Automatic campaign persistence
  - Human-readable campaign narratives

FIXES applied (v2.1):
  1. _cross_signal_amplify was dead code trapped after the return in
     _apply_direction_score. Separated into its own static method and
     called correctly in build_edges().
  2. is_anchor added to EventNode — anchors require confidence>=70,
     injection, persistence, network, OR high-risk EIDs. Used to
     strengthen cross-signal amplification for anchor-anchor edges.
  3. process_reuse edge type added — catches same-image reuse by same
     user (e.g. powershell.exe called multiple times in campaign).
  4. _cross_signal_amplify now counts 4 shared signals (injection,
     network, persistence, high-stage) and scales up to 2.0×.
  5. Adaptive threshold: scales with node count (30-45) instead of flat 0.50.
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

_CHAIN_MULTIPLIERS = [1.0, 1.0, 1.5, 2.5, 4.0]


def _kc_index(stage: Optional[str]) -> int:
    return _KC_INDEX.get(stage or "Background", 0)


def _higher_stage(a: Optional[str], b: Optional[str]) -> str:
    return a if _kc_index(a) >= _kc_index(b) else (b or a or "Background")


# ---------------------------------------------------------------------------
# Temporal decay
# ---------------------------------------------------------------------------

DECAY_TAU_SECONDS = 1800
FORWARD_KC_BONUS  = 0.20
BACKWARD_KC_PENALTY = 0.30


def _temporal_weight(delta_seconds: float) -> float:
    return math.exp(-abs(delta_seconds) / DECAY_TAU_SECONDS)


def _adaptive_threshold(node_count: int) -> float:
    """
    FIX: adaptive threshold scales with dataset size instead of flat 0.50.
    Small datasets (few nodes) get a lower threshold so legitimate short
    campaigns still get linked. Large datasets get a higher threshold to
    prevent noise clusters.
    """
    if node_count < 20:
        return 0.30
    elif node_count < 100:
        return 0.35
    elif node_count < 500:
        return 0.40
    return 0.45


# ---------------------------------------------------------------------------
# Event Node
# ---------------------------------------------------------------------------

class EventNode:
    __slots__ = (
        "uid", "image", "parent_image", "computer", "user",
        "kill_chain_stage", "confidence", "ts", "event_id",
        "has_network", "has_persistence", "has_injection", "is_anchor",
    )

    def __init__(self, event: Dict[str, Any]):
        self.uid              = event.get("event_uid") or event.get("burst_id") or str(uuid.uuid4().hex[:8])
        self.image            = (event.get("image") or "unknown").lower()
        self.parent_image     = (event.get("parent_image") or "").lower()
        self.computer         = (event.get("computer") or "unknown_host").lower()
        self.user             = (event.get("user") or "").upper()
        self.kill_chain_stage = event.get("kill_chain_stage") or "Background"
        self.confidence       = float(event.get("confidence_score") or event.get("risk_score") or 0.0)
        self.has_network      = bool(event.get("has_net") or event.get("destination_ip"))
        self.has_persistence  = bool(event.get("has_persistence"))
        self.has_injection    = bool(event.get("has_injection"))
        self.event_id         = int(event.get("event_id") or 0)

        # FIX: is_anchor captures high-value events that should strongly
        # attract correlation edges. Broader than just confidence score.
        self.is_anchor = any([
            self.confidence >= 70,
            self.has_injection,
            self.has_persistence,
            self.has_network,
            self.event_id in {8, 9, 10, 25},
            self.image in {"powershell.exe", "cmd.exe", "wscript.exe",
                           "cscript.exe", "mshta.exe", "regsvr32.exe"},
        ])

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
      - parent_child   : same host, parent->child image relationship
      - temporal       : same host, same image, within time window
      - host_lateral   : different hosts, same user, close in time
      - process_reuse  : same image + same user (FIX: new edge type)
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
        Compute all edges.

        FIX: _cross_signal_amplify is now correctly called as a static method
        on EVERY edge type (was dead code before — trapped after return).
        FIX: process_reuse edge type added.
        FIX: adaptive threshold based on node count.
        """
        self.edges.clear()
        node_list = sorted(
            self.nodes.values(),
            key=lambda n: n.ts if pd.notna(n.ts) else pd.Timestamp.min.tz_localize("UTC"),
        )

        # FIX: compute threshold based on graph size
        threshold = _adaptive_threshold(len(node_list))

        for i, a in enumerate(node_list):
            for j in range(i + 1, len(node_list)):
                b = node_list[j]
                if pd.isna(a.ts) or pd.isna(b.ts):
                    continue
                delta = (b.ts - a.ts).total_seconds()
                if delta > self.time_window * 4:
                    break   # sorted by time — safe early exit

                # ── Cross-host lateral movement edge ─────────────────────
                if a.computer != b.computer:
                    if a.user and a.user == b.user and abs(delta) <= self.time_window:
                        w = _temporal_weight(delta) * 0.6
                        # FIX: _cross_signal_amplify now properly called
                        w = CorrelationGraph._cross_signal_amplify(w, a, b)
                        if w >= threshold:
                            self.edges.append({
                                "from": a.uid, "to": b.uid,
                                "type": "host_lateral",
                                "weight": w,
                                "delta_sec": delta,
                                "reason": (
                                    f"Same user '{a.user}' on different hosts "
                                    f"({a.computer} → {b.computer}) within {int(abs(delta))}s"
                                ),
                                "confidence_type": "behavioral",
                            })
                    continue

                # ── Parent → Child structural edge ───────────────────────
                if a.image == b.parent_image and abs(delta) <= self.time_window:
                    w = _temporal_weight(delta)
                    # FIX: both methods called correctly in order
                    w = CorrelationGraph._cross_signal_amplify(w, a, b)
                    w = CorrelationGraph._apply_direction_score(w, a, b)
                    if w >= threshold:
                        direction = "forward" if _kc_index(b.kill_chain_stage) >= _kc_index(a.kill_chain_stage) else "backward"
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
                            "direction": direction,
                        })

                # ── Temporal co-occurrence edge (same image, same host) ───
                elif a.image == b.image and abs(delta) <= self.time_window:
                    w = _temporal_weight(delta) * 0.5
                    w = CorrelationGraph._cross_signal_amplify(w, a, b)
                    w = CorrelationGraph._apply_direction_score(w, a, b)
                    if w >= threshold:
                        direction = "forward" if _kc_index(b.kill_chain_stage) >= _kc_index(a.kill_chain_stage) else "backward"
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
                            "direction": direction,
                        })

                # FIX: process_reuse edge — same image, same user, different PID
                # Catches attackers reusing tools (powershell, cmd) across campaign
                elif (a.image == b.image and a.user and a.user == b.user
                      and abs(delta) <= self.time_window):
                    w = _temporal_weight(delta) * 0.7
                    w = CorrelationGraph._cross_signal_amplify(w, a, b)
                    if w >= threshold:
                        self.edges.append({
                            "from": a.uid, "to": b.uid,
                            "type": "process_reuse",
                            "weight": w,
                            "delta_sec": delta,
                            "reason": (
                                f"Same process '{a.image}' reused by '{a.user}' "
                                f"within {int(abs(delta))}s"
                            ),
                            "confidence_type": "behavioral",
                            "direction": "forward",
                        })

    @staticmethod
    def _apply_direction_score(weight: float, a: "EventNode", b: "EventNode") -> float:
        """
        Reward forward kill-chain progression; penalize backward links.
        FIX: this is now a clean standalone method — _cross_signal_amplify
        no longer hides inside it as dead code.
        """
        a_idx = _kc_index(a.kill_chain_stage)
        b_idx = _kc_index(b.kill_chain_stage)
        if b_idx > a_idx:
            return weight * (1.0 + FORWARD_KC_BONUS)
        elif b_idx < a_idx:
            return weight * (1.0 - BACKWARD_KC_PENALTY)
        return weight

    @staticmethod
    def _cross_signal_amplify(weight: float, a: "EventNode", b: "EventNode") -> float:
        """
        FIX: This was previously dead code trapped inside _apply_direction_score
        after its return statement. Now a proper static method called explicitly
        in build_edges() for every edge type.

        Boost edge weight when both nodes share suspicious properties.
        Anchor-to-anchor edges get an extra 1.5× multiplier.
        """
        shared_signals = sum([
            a.has_injection and b.has_injection,
            a.has_network   and b.has_network,
            a.has_persistence and b.has_persistence,
            _kc_index(a.kill_chain_stage) >= 5 and _kc_index(b.kill_chain_stage) >= 5,
        ])

        if shared_signals >= 3:
            w = weight * 2.0
        elif shared_signals == 2:
            w = weight * 1.5
        elif shared_signals == 1:
            w = weight * 1.2
        else:
            w = weight

        # Anchor-to-anchor bonus — both nodes are high-value signals
        if a.is_anchor and b.is_anchor:
            w *= 1.5

        return w

    def connected_components(self) -> List[Set[str]]:
        parent: Dict[str, str] = {uid: uid for uid in self.nodes}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: str, y: str) -> None:
            parent[find(x)] = find(y)

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

        stages        = list({n.kill_chain_stage for n in nodes})
        stage_indices = sorted([_kc_index(s) for s in stages], reverse=True)
        highest_stage = KILL_CHAIN_ORDER[stage_indices[0]] if stage_indices else "Execution"
        chain_depth   = len(set(stage_indices))
        multiplier    = _CHAIN_MULTIPLIERS[min(chain_depth, len(_CHAIN_MULTIPLIERS) - 1)]

        base = max((n.confidence for n in nodes), default=0.0)
        if base == 0:
            base = 30.0

        bonus = 0.0
        if any(n.has_persistence for n in nodes): bonus += 15.0
        if any(n.has_injection for n in nodes):   bonus += 25.0
        if any(n.has_network for n in nodes):     bonus += 10.0
        if any(n.event_id in {8, 9, 25} for n in nodes): bonus += 20.0

        node_uids = {n.uid for n in nodes}
        forward_count = backward_count = 0
        edge_weight   = 0.0
        for e in graph.edges:
            if e["from"] in node_uids and e["to"] in node_uids:
                edge_weight += e["weight"]
                if e.get("direction") == "forward":
                    forward_count += 1
                elif e.get("direction") == "backward":
                    backward_count += 1

        edge_bonus      = min(edge_weight * 5.0, 20.0)
        direction_bonus = 0.0
        if forward_count > 0 and backward_count == 0:
            direction_bonus = min(forward_count * 5.0, 15.0)

        final = min((base + bonus + edge_bonus + direction_bonus) * multiplier, 100.0)

        valid_ts   = [n.ts for n in nodes if pd.notna(n.ts)]
        first_seen = min(valid_ts).isoformat() if valid_ts else None
        last_seen  = max(valid_ts).isoformat() if valid_ts else None

        computers = sorted({n.computer for n in nodes})
        users     = sorted({n.user for n in nodes if n.user})
        images    = sorted({n.image for n in nodes})

        narrative = self._build_narrative(nodes, highest_stage, chain_depth, multiplier)

        day      = datetime.datetime.utcnow().strftime("%Y%m%d")
        base_img = nodes[0].image
        corr_id  = f"CAMP-{base_img[:12]}-{computers[0][:8]}-{day}".replace(" ", "_").lower()

        return {
            "corr_id":            corr_id,
            "run_id":             run_id,
            "base_image":         base_img,
            "images":             images,
            "computers":          computers,
            "users":              users,
            "first_seen":         first_seen,
            "last_seen":          last_seen,
            "event_count":        len(nodes),
            "chain_depth":        chain_depth,
            "chain_multiplier":   multiplier,
            "kill_chain_stages":  stages,
            "highest_stage":      highest_stage,
            "confidence":         round(final, 1),
            "has_persistence":    any(n.has_persistence for n in nodes),
            "has_injection":      any(n.has_injection for n in nodes),
            "has_network":        any(n.has_network for n in nodes),
            "narrative":          narrative,
            "node_uids":          [n.uid for n in nodes],
            "status":             "active",
            "forward_edge_count": forward_count,
            "direction_bonus":    int(direction_bonus),
        }

    @staticmethod
    def _build_narrative(
        nodes: List[EventNode],
        highest_stage: str,
        chain_depth: int,
        multiplier: float,
    ) -> str:
        images = sorted({n.image for n in nodes})
        stages = sorted({n.kill_chain_stage for n in nodes}, key=_kc_index)
        host   = nodes[0].computer

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
    try:
        from dashboard.db import get_cursor, sql_now_minus
        DECAY_PCT      = 0.90
        MIN_CONFIDENCE = 20
        with get_cursor(conn) as cur:
            cur.execute(
                f"UPDATE correlation_campaigns "
                f"SET max_confidence = GREATEST("
                f"  CAST(max_confidence * {DECAY_PCT} AS UNSIGNED), {MIN_CONFIDENCE}"
                f"), "
                f"status = CASE "
                f"  WHEN CAST(max_confidence * {DECAY_PCT} AS UNSIGNED) <= {MIN_CONFIDENCE} "
                f"  THEN 'dormant' ELSE status END "
                f"WHERE run_id = %s "
                f"AND status = 'active' "
                f"AND last_seen < {sql_now_minus(24, 'HOUR')}",
                (run_id,),
            )
    except Exception as e:
        print(f"[CorrelationEngine] decay failed: {e}")


def persist_campaigns(campaigns: List[Dict[str, Any]]) -> None:
    if not campaigns:
        return

    try:
        from dashboard.db import get_db_connection, get_cursor, checked_insert, now_utc, sanitize_datetime

        run_id = campaigns[0].get("run_id", "live")
        mode   = "live" if run_id == "live" else "cases"
        now    = now_utc()

        with get_db_connection(mode) as conn:
            _decay_stale_campaigns(conn, mode, run_id)
            with get_cursor(conn) as cur:
                for camp in campaigns:
                    cid       = camp["corr_id"]
                    new_conf  = int(camp["confidence"])
                    new_stage = camp["highest_stage"]

                    cur.execute(
                        "SELECT burst_count, max_confidence, highest_kill_chain "
                        "FROM correlation_campaigns WHERE corr_id = %s AND run_id = %s",
                        (cid, run_id),
                    )
                    row = cur.fetchone()
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
    if not events:
        return []

    graph = CorrelationGraph(time_window_seconds=time_window_seconds)
    graph.add_nodes_bulk(events)
    graph.build_edges()

    builder   = CampaignBuilder()
    campaigns = builder.build_campaigns(graph, run_id)

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
            "_burst_ref":       b,
        })

    campaigns = correlate_events(mapped, run_id, time_window_seconds, persist)

    for m in mapped:
        original = m.get("_burst_ref")
        if original is not None:
            original["correlation_id"]    = m.get("correlation_id")
            original["has_correlation"]   = m.get("has_correlation", False)
            original["correlation_score"] = m.get("correlation_score", 0)

    return bursts, campaigns
