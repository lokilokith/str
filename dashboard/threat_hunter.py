"""
threat_hunter.py — SentinelTrace v2 Phase 2
============================================
Threat hunting engine:
  - Beaconing detection (interval regularity scoring)
  - Process tree reconstruction (pid→ppid graph)
  - Ad-hoc hunt query parser (field:value AND/OR/NOT)
  - Behavioral anomaly scoring (Welford online variance)
"""
from __future__ import annotations
import math, re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# 1. BEACONING DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_beaconing(
    df: 'pd.DataFrame',
    min_hits: int = 6,
    max_jitter_pct: float = 0.20,
    min_interval_sec: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Detect beaconing — regular outbound connections to the same destination.
    ...
    Returns list of beacon candidates sorted by confidence descending.
    """
    import pandas as pd
    results = []

    ip_col   = next((c for c in ("destination_ip","dst_ip") if c in df.columns), None)
    port_col = next((c for c in ("destination_port","dst_port") if c in df.columns), None)
    time_col = next((c for c in ("event_time","utc_time") if c in df.columns), None)

    if not ip_col or not time_col or "image" not in df.columns:
        return results

    # Filter to network events with external IPs
    net_df = df[df[ip_col].notna() & (df[ip_col] != "")].copy()
    if net_df.empty:
        return results

    net_df["_ts"] = pd.to_datetime(net_df[time_col], errors="coerce", utc=True)
    net_df = net_df.dropna(subset=["_ts"])

    group_cols = ["image", ip_col]
    if port_col:
        group_cols.append(port_col)

    for keys, grp in net_df.groupby(group_cols, dropna=False):
        if len(grp) < min_hits:
            continue

        times = sorted(grp["_ts"].tolist())
        intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]

        if not intervals:
            continue

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < min_interval_sec:
            continue  # too frequent — likely burst, not beacon

        # Coefficient of variation (std/mean) — low CV = regular = beacon
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        std_dev  = math.sqrt(variance)
        cv       = std_dev / mean_interval if mean_interval > 0 else 1.0

        if cv > max_jitter_pct:
            continue

        # Confidence: lower jitter → higher confidence
        confidence = int(min(95, 60 + (1.0 - cv / max_jitter_pct) * 35))

        image = keys[0] if isinstance(keys, tuple) else keys
        dst_ip = keys[1] if isinstance(keys, tuple) and len(keys) > 1 else None
        dst_port = keys[2] if isinstance(keys, tuple) and len(keys) > 2 else None

        results.append({
            "image":           image,
            "destination_ip":  dst_ip,
            "destination_port": dst_port,
            "hit_count":       len(grp),
            "mean_interval_sec": round(mean_interval, 1),
            "jitter_pct":      round(cv * 100, 1),
            "confidence":      confidence,
            "first_seen":      str(times[0]),
            "last_seen":       str(times[-1]),
            "computer":        grp["computer"].iloc[0] if "computer" in grp.columns else None,
            "mitre_id":        "T1071",
            "mitre_tactic":    "Command and Control",
            "description":     (
                f"{image} beaconed to {dst_ip}:{dst_port} "
                f"{len(grp)}x every ~{round(mean_interval,0):.0f}s "
                f"(jitter {round(cv*100,1):.1f}%)"
            ),
        })

    return sorted(results, key=lambda x: x["confidence"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PROCESS TREE RECONSTRUCTION
# ─────────────────────────────────────────────────────────────────────────────

def build_process_tree(df: 'pd.DataFrame') -> List[Dict[str, Any]]:
    """
    Build a forest of process trees from event data.
    ...
    Returns list of root nodes (processes with no parent in the dataset).
    """
    import pandas as pd
    if df.empty:
        return []

    time_col = next((c for c in ("event_time","utc_time") if c in df.columns), None)

    # Only EID=1 (process create) events
    proc_df = df[df["event_id"] == 1].copy() if "event_id" in df.columns else df.copy()

    if proc_df.empty:
        return []

    if time_col:
        proc_df[time_col] = pd.to_datetime(proc_df[time_col], errors="coerce", utc=True)
        proc_df = proc_df.sort_values(time_col)

    # Build node map: (computer, pid) → node
    nodes: Dict[Tuple, Dict] = {}
    for _, row in proc_df.iterrows():
        computer = str(row.get("computer") or "unknown")
        pid      = str(row.get("pid") or row.get("process_id") or "")
        if not pid:
            continue
        key = (computer, pid)
        ts = row.get(time_col) if time_col else None
        nodes[key] = {
            "pid":          pid,
            "ppid":         str(row.get("ppid") or row.get("parent_process_id") or ""),
            "image":        row.get("image") or "unknown",
            "parent_image": row.get("parent_image") or "",
            "command_line": row.get("command_line") or "",
            "event_time":   str(ts) if ts else str(row.get(time_col, "")),
            "computer":     computer,
            "user":         str(row.get("user") or ""),
            "event_id":     row.get("event_id"),
            "severity":     row.get("severity") or "low",
            "cmd_high_entropy": bool(row.get("cmd_high_entropy", False)),
            "is_lolbin":    bool(row.get("is_lolbin", False)),
            "depth":        0,
            "children":     [],
        }

    # Link children to parents
    roots = []
    for key, node in nodes.items():
        computer = key[0]
        ppid     = node["ppid"]
        parent_key = (computer, ppid)
        if parent_key in nodes and parent_key != key:
            nodes[parent_key]["children"].append(node)
        else:
            roots.append(node)

    # Set depth recursively
    def _set_depth(node, depth=0):
        node["depth"] = depth
        for child in node["children"]:
            _set_depth(child, depth + 1)

    for root in roots:
        _set_depth(root)

    return roots


def flatten_process_tree(roots: List[Dict]) -> List[Dict]:
    """Flatten process tree into a list preserving depth for indented display."""
    flat = []

    def _walk(node):
        flat.append(node)
        for child in sorted(node["children"], key=lambda x: x.get("event_time", "")):
            _walk(child)

    for root in sorted(roots, key=lambda x: x.get("event_time", "")):
        _walk(root)

    return flat


# ─────────────────────────────────────────────────────────────────────────────
# 3. HUNT QUERY PARSER
# ─────────────────────────────────────────────────────────────────────────────

_FIELD_ALIASES = {
    "proc":    "image",
    "process": "image",
    "img":     "image",
    "ip":      "destination_ip",
    "dst":     "destination_ip",
    "src":     "source_ip",
    "host":    "computer",
    "user":    "user",
    "eid":     "event_id",
    "eventid": "event_id",
    "cmd":     "command_line",
    "sev":     "severity",
    "port":    "destination_port",
    "tactic":  "mitre_tactic",
    "mitre":   "mitre_id",
    "stage":   "kill_chain_stage",
    "parent":  "parent_image",
    "rule":    "rule_name",
}


def parse_hunt_query(query: str) -> List[Dict[str, Any]]:
    """
    Parse a hunt query string into a list of filter conditions.

    Syntax:
        field:value            exact/contains match
        field:"exact value"    exact match with spaces
        NOT field:value        negation
        Multiple terms         implicit AND

    Examples:
        image:powershell.exe AND NOT computer:DC01
        event_id:3 destination_ip:185.220
        cmd:"-enc " severity:high

    Returns list of dicts: {field, value, negate, operator}
    """
    if not query or not query.strip():
        return []

    # Tokenise: handle quoted values
    token_re = re.compile(
        r'(NOT\s+)?(\w+):"([^"]+)"|'   # field:"quoted value"
        r'(NOT\s+)?(\w+):(\S+)|'        # field:value
        r'(AND|OR|NOT)',                 # boolean operators
        re.IGNORECASE,
    )

    conditions = []
    for m in token_re.finditer(query):
        if m.group(7):  # AND / OR / NOT (bare)
            continue

        negate = bool(m.group(1) or m.group(4))

        if m.group(2):  # field:"quoted"
            raw_field = m.group(2).lower()
            value     = m.group(3)
        else:           # field:value
            raw_field = m.group(5).lower()
            value     = m.group(6)

        field = _FIELD_ALIASES.get(raw_field, raw_field)
        conditions.append({
            "field":    field,
            "value":    value,
            "negate":   negate,
            "operator": "contains",
        })

    return conditions


def apply_hunt_query(df: 'pd.DataFrame', conditions: List[Dict]) -> 'pd.DataFrame':
    """
    Apply parsed hunt conditions to a DataFrame.
    AND conditions narrow the result; OR conditions widen it.
    """
    import pandas as pd
    if not conditions or df.empty:
        return df

    # Start with all-True mask; OR conditions are accumulated separately then OR-merged
    and_mask = pd.Series([True]  * len(df), index=df.index)
    or_mask  = pd.Series([False] * len(df), index=df.index)
    has_or   = any(c.get("operator") == "OR" for c in conditions)

    for cond in conditions:
        field    = cond["field"]
        value    = str(cond["value"]).lower()
        negate   = cond["negate"]
        operator = cond.get("operator", "AND")

        resolved_field = field
        if field not in df.columns:
            matches = [c for c in df.columns if field in c.lower()]
            if not matches:
                continue
            resolved_field = matches[0]

        col = df[resolved_field].astype(str).str.lower()

        # Numeric equality for event_id
        if resolved_field == "event_id" and value.isdigit():
            col_match = df[resolved_field].astype(str) == value
        else:
            col_match = col.str.contains(re.escape(value), na=False)

        if negate:
            col_match = ~col_match

        if operator == "OR":
            or_mask |= col_match
        else:
            and_mask &= col_match

    # Combine: AND-conditions AND (OR-conditions if any OR present)
    if has_or:
        final_mask = and_mask & or_mask
    else:
        final_mask = and_mask

    return df[final_mask].copy()


def hunt(df: pd.DataFrame, query: str) -> pd.DataFrame:
    """Convenience: parse query and apply to DataFrame."""
    conditions = parse_hunt_query(query)
    return apply_hunt_query(df, conditions)


# ─────────────────────────────────────────────────────────────────────────────
# 4. BEHAVIORAL ANOMALY (Welford variance fix)
# ─────────────────────────────────────────────────────────────────────────────

def compute_deviation_score(
    exec_count: float,
    cmd_length: float,
    followup_events: float,
    network_strength: int,
    baseline: Optional[Dict[str, Any]],
) -> float:
    """
    Compute a 0–1 deviation score comparing observed behavior to baseline.

    Uses Welford online variance (stored as m2_exec / count_samples-1).
    Returns 0.15 when baseline is absent (unknown = slightly suspicious).
    """
    if not baseline:
        return 0.40   # Unknown process = moderately suspicious; 0.15 was too low

    n = int(baseline.get("count_samples", 0) or 0)
    if n < 5:
        return 0.25   # not enough samples to be confident

    mean_val = float(baseline.get("mean_exec", 0.0) or 0.0)

    # Noise floor: don't penalise low-frequency processes
    host_noise_floor = max(5.0, mean_val)
    if exec_count < host_noise_floor:
        return 0.10

    # Welford variance → std
    m2  = float(baseline.get("m2_exec", 0.0) or 0.0)
    var = m2 / max(n - 1, 1) if n > 1 else 0.0
    std = max(math.sqrt(var), 1.0)

    freq_dev = min(abs(exec_count - mean_val) / std, 3.0)

    avg_cmd  = float(baseline.get("avg_cmd_len", 1.0) or 1.0)
    cmd_dev  = min(abs(cmd_length - avg_cmd) / max(avg_cmd, 1.0), 3.0)

    avg_fol   = float(baseline.get("avg_followup", 0.0) or 0.0)
    chain_dev = 1.0 if followup_events >= avg_fol + 2.0 else 0.0

    net_dev = 1.0 if network_strength >= 2 else (0.5 if network_strength == 1 else 0.0)

    raw = 0.30 * freq_dev + 0.25 * cmd_dev + 0.20 * chain_dev + 0.15 * net_dev

    # Immature baseline: cap at 0.40 to avoid false positives
    if n < 30:
        return float(min(raw / 3.0, 0.40))

    return float(min(raw / 3.0, 1.0))
