"""
threat_hunter.py — SentinelTrace v2  (FIXED)
=============================================
Blueprint fixes:
  FIX-1: Distributed beaconing detection (IP-rotating C2)
  FIX-2: Risk score on beacon output aligned with scoring engine
  FIX-3: Suspicious chain detection (office→shell, deep LOLBin, high-entropy)
  FIX-4: OR logic in hunt query parser
  FIX-5: Hunt result prioritization (scored + ranked)
  FIX-6: Deviation score corrected (unknown = 0.40, not 0.15)
  FIX-7: Multi-signal fusion (beaconing + lolbin + entropy)
  FIX-8: Entity correlation (host/user/process grouping)
  FIX-9: Attack narrative output (human-readable chain story)
  FIX-10: Pipeline integration via advanced_hunt()
"""
from __future__ import annotations
import math
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

_OFFICE_APPS = frozenset({"winword.exe","excel.exe","outlook.exe","powerpnt.exe","onenote.exe"})
_SHELL_BINS  = frozenset({"powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe"})
_LOLBINS     = frozenset({
    "mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe","bitsadmin.exe","wmic.exe",
    "installutil.exe","msbuild.exe","cmstp.exe","hh.exe","psexec.exe","psexec64.exe"
})


# ─────────────────────────────────────────────────────────────────────────────
# 1. BEACONING DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_beaconing(
    df: pd.DataFrame,
    min_hits: int = 6,
    max_jitter_pct: float = 0.20,
    min_interval_sec: float = 5.0,
) -> List[Dict[str, Any]]:
    """
    Detect regular outbound C2 beaconing.
    FIX-1: Also detects distributed beaconing (IP-rotating infrastructure).
    FIX-2: Returns risk_score aligned with scoring engine.
    """
    results = []
    ip_col   = next((c for c in ("destination_ip","dst_ip") if c in df.columns), None)
    port_col = next((c for c in ("destination_port","dst_port") if c in df.columns), None)
    time_col = next((c for c in ("event_time","utc_time") if c in df.columns), None)

    if not ip_col or not time_col or "image" not in df.columns:
        return results

    net_df = df[df[ip_col].notna() & (df[ip_col] != "")].copy()
    if net_df.empty:
        return results

    net_df["_ts"] = pd.to_datetime(net_df[time_col], errors="coerce", utc=True)
    net_df = net_df.dropna(subset=["_ts"])

    # Primary: exact (image, ip, port)
    group_cols = ["image", ip_col]
    if port_col:
        group_cols.append(port_col)

    for keys, grp in net_df.groupby(group_cols, dropna=False):
        if len(grp) < min_hits:
            continue
        times     = sorted(grp["_ts"].tolist())
        intervals = [(times[i+1]-times[i]).total_seconds() for i in range(len(times)-1)]
        if not intervals:
            continue
        mean_i = sum(intervals)/len(intervals)
        if mean_i < min_interval_sec:
            continue
        var = sum((x-mean_i)**2 for x in intervals)/len(intervals)
        cv  = math.sqrt(var)/mean_i if mean_i>0 else 1.0
        if cv > max_jitter_pct:
            continue
        confidence = int(min(95, 60 + (1.0 - cv/max_jitter_pct)*35))
        image    = keys[0] if isinstance(keys, tuple) else keys
        dst_ip   = keys[1] if isinstance(keys, tuple) and len(keys)>1 else None
        dst_port = keys[2] if isinstance(keys, tuple) and len(keys)>2 else None
        results.append({
            "type":             "beaconing",
            "image":            image,
            "destination_ip":   dst_ip,
            "destination_port": dst_port,
            "hit_count":        len(grp),
            "mean_interval_sec":round(mean_i,1),
            "jitter_pct":       round(cv*100,1),
            "confidence":       confidence,
            "risk_score":       min(100, confidence + len(grp)*2),  # FIX-2
            "first_seen":       str(times[0]),
            "last_seen":        str(times[-1]),
            "computer":         grp["computer"].iloc[0] if "computer" in grp.columns else None,
            "mitre_id":         "T1071",
            "mitre_tactic":     "Command and Control",
            "distributed":      False,
            "description":      (
                f"{image} beaconed to {dst_ip}:{dst_port} "
                f"{len(grp)}x every ~{round(mean_i,0):.0f}s "
                f"(jitter {round(cv*100,1):.1f}%)"
            ),
        })

    # FIX-1: Distributed — same image, many IPs, regular timing
    for image_val, img_grp in net_df.groupby("image", dropna=False):
        unique_ips = img_grp[ip_col].nunique()
        if unique_ips < 3 or len(img_grp) < min_hits:
            continue
        times     = sorted(img_grp["_ts"].tolist())
        intervals = [(times[i+1]-times[i]).total_seconds() for i in range(len(times)-1)]
        if not intervals:
            continue
        mean_i = sum(intervals)/len(intervals)
        if mean_i < min_interval_sec:
            continue
        var = sum((x-mean_i)**2 for x in intervals)/len(intervals)
        cv  = math.sqrt(var)/mean_i if mean_i>0 else 1.0
        if cv > max_jitter_pct:
            continue
        confidence = int(min(95, 70+(1.0-cv/max_jitter_pct)*25))
        results.append({
            "type":             "distributed_beaconing",
            "image":            image_val,
            "destination_ip":   f"{unique_ips} unique IPs",
            "destination_port": None,
            "hit_count":        len(img_grp),
            "mean_interval_sec":round(mean_i,1),
            "jitter_pct":       round(cv*100,1),
            "confidence":       confidence,
            "risk_score":       min(100, confidence+15),
            "first_seen":       str(times[0]),
            "last_seen":        str(times[-1]),
            "computer":         img_grp["computer"].iloc[0] if "computer" in img_grp.columns else None,
            "mitre_id":         "T1071",
            "mitre_tactic":     "Command and Control",
            "distributed":      True,
            "description":      (
                f"{image_val} DISTRIBUTED beaconing to {unique_ips} IPs — "
                f"IP-rotating C2 infrastructure suspected"
            ),
        })

    return sorted(results, key=lambda x: x["confidence"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# 2. PROCESS TREE + CHAIN DETECTION (FIX-3)
# ─────────────────────────────────────────────────────────────────────────────

def build_process_tree(df: pd.DataFrame) -> List[Dict[str, Any]]:
    if df.empty:
        return []
    time_col = next((c for c in ("event_time","utc_time") if c in df.columns), None)
    proc_df  = df[df["event_id"]==1].copy() if "event_id" in df.columns else df.copy()
    if proc_df.empty:
        return []
    if time_col:
        proc_df[time_col] = pd.to_datetime(proc_df[time_col], errors="coerce", utc=True)
        proc_df = proc_df.sort_values(time_col)

    nodes: Dict[Tuple, Dict] = {}
    for _, row in proc_df.iterrows():
        computer = str(row.get("computer") or "unknown")
        pid      = str(row.get("pid") or row.get("process_id") or "")
        if not pid:
            continue
        key = (computer, pid)
        ts  = row.get(time_col) if time_col else None
        nodes[key] = {
            "pid":               pid,
            "ppid":              str(row.get("ppid") or row.get("parent_process_id") or ""),
            "image":             row.get("image") or "unknown",
            "parent_image":      row.get("parent_image") or "",
            "command_line":      row.get("command_line") or "",
            "event_time":        str(ts) if ts else "",
            "computer":          computer,
            "user":              str(row.get("user") or ""),
            "event_id":          row.get("event_id"),
            "severity":          row.get("severity") or "low",
            "cmd_high_entropy":  bool(row.get("cmd_high_entropy", False)),
            "is_lolbin":         bool(row.get("is_lolbin", False)),
            "is_suspicious_lolbin": bool(row.get("is_suspicious_lolbin", False)),
            "network_strength":  int(row.get("network_strength", 0)),
            "tags":              row.get("tags") or [],
            "depth":             0,
            "children":          [],
        }

    roots = []
    for key, node in nodes.items():
        parent_key = (key[0], node["ppid"])
        if parent_key in nodes and parent_key != key:
            nodes[parent_key]["children"].append(node)
        else:
            roots.append(node)

    def _set_depth(node, depth=0):
        node["depth"] = depth
        for child in node["children"]:
            _set_depth(child, depth+1)

    for root in roots:
        _set_depth(root)
    return roots


def detect_suspicious_chains(roots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    FIX-3: Detect suspicious process chain patterns.
    Patterns: office→shell, deep LOLBin, suspicious LOLBin, high-entropy shell.
    """
    findings: List[Dict[str, Any]] = []

    def _walk(node: Dict, parent: Optional[Dict] = None):
        image  = (node.get("image") or "").lower()
        par    = (parent.get("image") or "").lower() if parent else ""
        depth  = node.get("depth", 0)

        # Office → shell (macro phishing)
        if par in _OFFICE_APPS and image in (_SHELL_BINS | _LOLBINS):
            findings.append({
                "type":"office_to_shell","image":image,"parent":par,"depth":depth,
                "confidence":90,"risk_score":90,"computer":node.get("computer"),
                "mitre_id":"T1566.001","mitre_tactic":"Initial Access",
                "description":f"MACRO PHISHING: {par} → {image}",
            })

        # Deep LOLBin chain
        if depth >= 3 and node.get("is_lolbin"):
            conf = min(95, 75 + depth*5)
            findings.append({
                "type":"deep_lolbin_chain","image":image,"parent":par,"depth":depth,
                "confidence":conf,"risk_score":conf,"computer":node.get("computer"),
                "mitre_id":"T1059","mitre_tactic":"Execution",
                "description":f"DEEP CHAIN (depth={depth}): {image} — multi-hop attack",
            })

        # Suspicious LOLBin
        if node.get("is_suspicious_lolbin"):
            findings.append({
                "type":"suspicious_lolbin","image":image,"parent":par,"depth":depth,
                "confidence":80,"risk_score":80,"computer":node.get("computer"),
                "mitre_id":"T1059","mitre_tactic":"Defense Evasion",
                "description":f"SUSPICIOUS LOLBin: {image} with encoded/download behavior",
            })

        # High entropy shell
        if node.get("cmd_high_entropy") and image in (_SHELL_BINS | _LOLBINS):
            findings.append({
                "type":"high_entropy_shell","image":image,"parent":par,"depth":depth,
                "confidence":70,"risk_score":70,"computer":node.get("computer"),
                "mitre_id":"T1059.001","mitre_tactic":"Execution",
                "description":f"HIGH ENTROPY: {image} with obfuscated command",
            })

        for child in node.get("children", []):
            _walk(child, node)

    for root in roots:
        _walk(root)
    return findings


def flatten_process_tree(roots: List[Dict]) -> List[Dict]:
    flat = []
    def _walk(node):
        flat.append(node)
        for child in sorted(node["children"], key=lambda x: x.get("event_time","")):
            _walk(child)
    for root in sorted(roots, key=lambda x: x.get("event_time","")):
        _walk(root)
    return flat


# ─────────────────────────────────────────────────────────────────────────────
# 3. HUNT QUERY PARSER (FIX-4: OR logic)
# ─────────────────────────────────────────────────────────────────────────────

_FIELD_ALIASES = {
    "proc":"image","process":"image","img":"image",
    "ip":"destination_ip","dst":"destination_ip","src":"source_ip",
    "host":"computer","user":"user","eid":"event_id","eventid":"event_id",
    "cmd":"command_line","sev":"severity","port":"destination_port",
    "tactic":"mitre_tactic","mitre":"mitre_id","stage":"kill_chain_stage",
    "parent":"parent_image","rule":"rule_name","tag":"tags",
}


def parse_hunt_query(query: str) -> List[Dict[str, Any]]:
    """Parse hunt query with AND/OR/NOT support. FIX-4: OR now works."""
    if not query or not query.strip():
        return []

    token_re = re.compile(
        r'(NOT\s+)?(\w+):"([^"]+)"|'
        r'(NOT\s+)?(\w+):(\S+)|'
        r'\b(AND|OR|NOT)\b',
        re.IGNORECASE,
    )
    conditions = []
    current_op = "AND"

    for m in token_re.finditer(query):
        if m.group(7):
            op = m.group(7).upper()
            if op in ("AND","OR"):
                current_op = op
            continue

        negate = bool(m.group(1) or m.group(4))
        if m.group(2):
            raw_field, value = m.group(2).lower(), m.group(3)
        else:
            raw_field, value = m.group(5).lower(), m.group(6)

        field = _FIELD_ALIASES.get(raw_field, raw_field)
        conditions.append({
            "field":    field,
            "value":    value,
            "negate":   negate,
            "operator": current_op,
        })
        current_op = "AND"   # reset

    return conditions


def apply_hunt_query(df: pd.DataFrame, conditions: List[Dict]) -> pd.DataFrame:
    """Apply parsed conditions. FIX-4: OR handled with bitwise mask OR."""
    if not conditions or df.empty:
        return df

    mask = pd.Series([True]*len(df), index=df.index)

    for cond in conditions:
        field    = cond["field"]
        value    = str(cond["value"]).lower()
        negate   = cond["negate"]
        operator = cond.get("operator","AND")

        if field not in df.columns:
            matches = [c for c in df.columns if field in c.lower()]
            if not matches:
                continue
            field = matches[0]

        col = df[field].astype(str).str.lower()
        col_match = (df[field].astype(str)==value) if field=="event_id" and value.isdigit() \
                    else col.str.contains(re.escape(value), na=False)

        if negate:
            col_match = ~col_match

        if operator == "OR":   # FIX-4
            mask = mask | col_match
        else:
            mask = mask & col_match

    return df[mask].copy()


def hunt(df: pd.DataFrame, query: str) -> pd.DataFrame:
    """Parse + apply + prioritize."""
    conditions = parse_hunt_query(query)
    result     = apply_hunt_query(df, conditions)
    return _prioritize_hunt_results(result)


# ─────────────────────────────────────────────────────────────────────────────
# FIX-5: Hunt result prioritization
# ─────────────────────────────────────────────────────────────────────────────

def _prioritize_hunt_results(df: pd.DataFrame) -> pd.DataFrame:
    """Score and rank so high-threat events surface first."""
    if df.empty:
        return df

    def _score(row) -> int:
        s = 0
        if row.get("cmd_high_entropy"):    s += 3
        if row.get("is_suspicious_lolbin") or row.get("is_lolbin"): s += 2
        try:
            eid = int(row.get("event_id") or 0)
            s += 4 if eid in {8,9,10,25} else 2 if eid in {3,12,13} else 0
        except Exception:
            pass
        if row.get("network_strength",0)==2: s += 3
        sev = str(row.get("severity") or "").lower()
        s += 2 if sev=="high" else 1 if sev=="medium" else 0
        return s

    df = df.copy()
    df["hunt_score"] = df.apply(_score, axis=1)
    return df.sort_values("hunt_score", ascending=False)


# ─────────────────────────────────────────────────────────────────────────────
# FIX-6: Deviation score
# ─────────────────────────────────────────────────────────────────────────────

def compute_deviation_score(
    exec_count: float,
    cmd_length: float,
    followup_events: float,
    network_strength: int,
    baseline: Optional[Dict[str, Any]],
) -> float:
    """FIX-6: Unknown behavior = 0.40 (not 0.15). Unknown ≠ safe."""
    if not baseline:
        return 0.40

    n = int(baseline.get("count_samples",0) or 0)
    if n < 5:
        return 0.30

    mean_val = float(baseline.get("mean_exec",0.0) or 0.0)
    if exec_count < max(5.0, mean_val):
        return 0.10

    m2  = float(baseline.get("m2_exec",0.0) or 0.0)
    var = m2/max(n-1,1) if n>1 else 0.0
    std = max(var**0.5, 1.0)

    freq_dev  = min(abs(exec_count-mean_val)/std, 3.0)
    avg_cmd   = float(baseline.get("avg_cmd_len",1.0) or 1.0)
    cmd_dev   = min(abs(cmd_length-avg_cmd)/max(avg_cmd,1.0), 3.0)
    avg_fol   = float(baseline.get("avg_followup",0.0) or 0.0)
    chain_dev = 1.0 if followup_events>=avg_fol+2.0 else 0.0
    net_dev   = 1.0 if network_strength>=2 else 0.5 if network_strength==1 else 0.0

    # FIX-6: divide by 2.0 (less signal flattening than original 3.0)
    raw = 0.30*freq_dev + 0.25*cmd_dev + 0.20*chain_dev + 0.15*net_dev
    return float(min(raw/2.0, 0.40)) if n<30 else float(min(raw/2.0, 1.0))


# ─────────────────────────────────────────────────────────────────────────────
# FIX-9: Attack narrative
# ─────────────────────────────────────────────────────────────────────────────

def _build_narrative(finding: Dict[str, Any], fusion_reasons: List[str]) -> str:
    parts: List[str] = []
    ftype  = finding.get("type","")
    image  = finding.get("image","unknown")
    parent = finding.get("parent","")

    if ftype == "office_to_shell":
        parts.append(f"MACRO PHISHING: {parent} → {image} — VBA macro dropper")
    elif ftype == "distributed_beaconing":
        parts.append(
            f"DISTRIBUTED C2: {image} → {finding.get('destination_ip','multiple IPs')} "
            f"every ~{finding.get('mean_interval_sec','?')}s — IP-rotating C2"
        )
    elif ftype == "beaconing":
        parts.append(
            f"C2 BEACON: {image} → {finding.get('destination_ip','?')}:"
            f"{finding.get('destination_port','?')} every ~{finding.get('mean_interval_sec','?')}s"
        )
    elif ftype == "deep_lolbin_chain":
        parts.append(
            f"DEEP ATTACK CHAIN: {image} at depth {finding.get('depth','?')} "
            f"(parent={parent or 'unknown'}) — multi-hop execution"
        )
    elif ftype == "suspicious_lolbin":
        parts.append(f"LOLBin ABUSE: {image} with encoded/download behavior")
    elif ftype == "high_entropy_shell":
        parts.append(f"OBFUSCATED COMMAND: {image} — likely encoded payload")
    else:
        parts.append(f"SUSPICIOUS: {image} — {finding.get('description','anomaly detected')}")

    if fusion_reasons:
        parts.append(f"Corroborated by: {'; '.join(fusion_reasons)}")

    conf = finding.get("confidence",0)
    if conf >= 80:
        parts.append("→ HIGH CONFIDENCE — immediate investigation")
    elif conf >= 60:
        parts.append("→ MEDIUM CONFIDENCE — review warranted")

    return " | ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# FIX-7: Multi-signal fusion
# ─────────────────────────────────────────────────────────────────────────────

def _fuse_signals(
    beacons: List[Dict],
    chains:  List[Dict],
    df:      pd.DataFrame,
) -> List[Dict[str, Any]]:
    """FIX-7: Combine beaconing + chain + entropy — combined evidence > individual signals."""
    fused: List[Dict] = []
    beacon_images = {b["image"] for b in beacons}

    for chain in chains:
        img       = chain.get("image","")
        base_conf = chain["confidence"]
        extra, reasons = 0, []

        if img in beacon_images:
            extra += 20; reasons.append("process also beaconing")

        if not df.empty and "image" in df.columns and "tags" in df.columns:
            img_tags: set = set()
            for t in df[df["image"]==img]["tags"]:
                if isinstance(t, list): img_tags.update(t)
                elif isinstance(t, str): img_tags.update(t.split(","))
            if "high_entropy"    in img_tags: extra += 10; reasons.append("high-entropy command")
            if "external_network"in img_tags: extra += 10; reasons.append("external network")
            if "lolbin_abuse"    in img_tags: extra +=  5; reasons.append("LOLBin abuse confirmed")

        fused_entry = dict(chain)
        if extra:
            fused_entry["confidence"] = min(100, base_conf+extra)
            fused_entry["risk_score"] = min(100, chain.get("risk_score",base_conf)+extra)
            fused_entry["fused"]      = True
            fused_entry["fusion_reasons"] = reasons
            fused_entry["is_attack_candidate"] = fused_entry["confidence"] >= 75
        fused_entry["narrative"] = _build_narrative(chain, reasons)
        fused.append(fused_entry)

    chain_images = {c.get("image") for c in chains}
    for beacon in beacons:
        if beacon["image"] not in chain_images:
            b = dict(beacon)
            b["narrative"] = _build_narrative(b,[])
            fused.append(b)

    return sorted(fused, key=lambda x: x.get("confidence",0), reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# FIX-8: Entity correlation
# ─────────────────────────────────────────────────────────────────────────────

def _entity_correlation(findings: List[Dict], df: pd.DataFrame) -> List[Dict]:
    """FIX-8: Group by host/image to detect coordinated activity → confidence boost."""
    if not findings:
        return findings
    host_cnt:  Dict[str,int] = defaultdict(int)
    image_cnt: Dict[str,int] = defaultdict(int)
    for f in findings:
        host_cnt[f.get("computer","unknown")] += 1
        image_cnt[f.get("image","unknown")]   += 1

    enriched = []
    for f in findings:
        f = dict(f)
        host = f.get("computer","unknown")
        img  = f.get("image","unknown")
        if host_cnt[host] >= 3:
            f["confidence"] = min(100, f.get("confidence",50)+10)
            f["risk_score"] = min(100, f.get("risk_score",50)+10)
            f["narrative"]  = f.get("narrative","") + f" | HOST HOTSPOT: {host_cnt[host]} findings on {host}"
        if image_cnt[img] >= 2:
            f["confidence"] = min(100, f.get("confidence",50)+5)
            f["risk_score"] = min(100, f.get("risk_score",50)+5)
        enriched.append(f)

    return sorted(enriched, key=lambda x: x.get("confidence",0), reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# FIX-10: Pipeline entry point
# ─────────────────────────────────────────────────────────────────────────────

def advanced_hunt(df: pd.DataFrame, run_id: str = "") -> List[Dict[str, Any]]:
    """
    FIX-10: Master hunt function — pipeline integration point.
    Called by analysis_engine. Returns prioritized findings with narratives.
    """
    if df.empty:
        return []
    beacons  = detect_beaconing(df)
    roots    = build_process_tree(df)
    chains   = detect_suspicious_chains(roots)
    findings = _fuse_signals(beacons, chains, df)
    findings = _entity_correlation(findings, df)
    for f in findings:
        f["run_id"] = run_id
    return findings
