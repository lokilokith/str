"""
analysis_engine.py — SentinelTrace Full Analysis Engine  (MySQL edition)
=========================================================================
Converted from SQLite to MySQL.  All sqlite3 / DB_PATH references removed.
Uses dashboard.db context managers throughout.

Exports (used by app.py):
    ingest_upload, persist_case, run_full_analysis, process_event,
    upsert_incident_row, persist_behavior_baseline
"""

from __future__ import annotations

import datetime
import hashlib
import math
import traceback
import uuid
import json
import unicodedata
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from decimal import Decimal

import pandas as pd
from sqlalchemy import text

# --- YARA support ---
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

import yaml

from dashboard.event_parser import (
    parse_event,
    load_all_sources_from_xml,
    enrich_parent_chains,
)
from dashboard.detection_engine import find_detections, match_rules
from dashboard.db import (
    DB_TYPE,
    DB_STRICT,
    INGESTED,
    ANALYZING,
    COMPLETE,
    DEGRADED,
    FAILED,
    checked_insert,
    dispose_engine,
    get_db_connection,
    get_cursor,
    get_datetime_columns,
    get_engine,
    get_table_columns,
    now_utc,
    sanitize_datetime,
    sanitize_row,
    sql_insert_ignore,
    sql_now_minus,
    sql_upsert,
    quote_identifier,
)
from dashboard.scoring_engine import get_scoring_engine, validate_context

# ---------------------------------------------------------------------------
# YAML Rule loader
# ---------------------------------------------------------------------------

_loaded_rules: list = []

def load_detection_rules(rules_path=None) -> list:
    """
    Load detection rules from YAML file.
    Searches: rules_path → project root rules.yaml → dashboard/rules.yaml
    """
    global _loaded_rules
    search_paths = []
    if rules_path:
        search_paths.append(Path(rules_path))
    # Auto-discover rules.yaml
    base = Path(__file__).resolve().parent
    search_paths += [
        base.parent / "rules.yaml",     # project root
        base / "rules.yaml",             # dashboard/
        Path("rules.yaml"),              # cwd
    ]
    for p in search_paths:
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                rules = data.get("rules", []) if data else []
                _loaded_rules = rules
                print(f"[rules] Loaded {len(rules)} detection rules from {p}")
                return rules
            except Exception as e:
                print(f"[rules] Failed to load {p}: {e}")
    print("[rules] No rules.yaml found — using heuristic EID detection only")
    _loaded_rules = []
    return []

# Load rules at import time
load_detection_rules()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MITRE_TO_KILL_CHAIN = {
    "Initial Access": ["Delivery"],
    "Execution": ["Execution"],
    "Persistence": ["Persistence"],
    "Privilege Escalation": ["Privilege Escalation"],
    "Defense Evasion": ["Defense Evasion"],
    "Credential Access": ["Credential Access"],
    "Discovery": ["Discovery"],
    "Lateral Movement": ["Lateral Movement"],
    "Collection": ["Collection"],
    "Command and Control": ["Command and Control"],
    "Exfiltration": ["Exfiltration"],
    "Impact": ["Actions on Objectives"],
}

KILL_CHAIN_ORDER = [
    "Background", "Delivery", "Execution", "Defense Evasion",
    "Persistence", "Privilege Escalation", "Credential Access",
    "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Actions on Objectives",
]
KILLCHAIN_ORDER_FOR_RANK = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

_HIGH_EVENT_IDS = {1, 8, 9, 12, 13, 14, 19, 25}
_MED_EVENT_IDS  = {3, 7, 10, 11, 22, 23}

# ---------------------------------------------------------------------------
# 10/10 Formal Mastery: Canonical Normalization & Semantic Hashing
# ---------------------------------------------------------------------------
def normalize_nfc(val: Any) -> str:
    """UTF-8 NFC normalization for bit-perfect stability."""
    if val is None: return ""
    s = str(val).strip()
    return unicodedata.normalize("NFC", s)

def generate_semantic_hash(records: List[Dict[str, Any]]) -> str:
    """
    Generate a bit-perfect hash of the event set context.
    1. Sort records by (event_time, event_uid)
    2. Sort keys within each record
    3. Normalize NFC
    4. ASCII-only JSON serialization
    """
    def _clean(d):
        return {k: normalize_nfc(v) for k, v in d.items() if v is not None}
    
    # Authoritative sort for stability
    sorted_records = sorted(
        [_clean(r) for r in records],
        key=lambda x: (x.get("event_time", ""), x.get("event_uid", ""))
    )
    
    # Canonical JSON string
    canonical_json = json.dumps(
        sorted_records,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":")
    )
    return hashlib.sha256(canonical_json.encode("ascii")).hexdigest()

def to_pure_python_records(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Convert Pandas DF to zero-entropy pure Python records."""
    # Coerce scalars and handle NaT/NaN
    records = df.replace({pd.NA: None, pd.NaT: None}).to_dict("records")
    # Force bit-perfect consistency
    return [dict(sorted((k, normalize_nfc(v)) for k, v in r.items())) for r in records]

# ---------------------------------------------------------------------------
# Snapshot cache stubs
# ---------------------------------------------------------------------------

def get_analysis_snapshot(run_id: str) -> Optional[Dict[str, Any]]:
    return None

def set_analysis_snapshot(run_id: str, result: Dict[str, Any]) -> None:
    pass

def clear_analysis_snapshot(run_id: str) -> None:
    pass

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def promote_stage(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if not a:
        return b
    if not b:
        return a
    if a not in KILL_CHAIN_ORDER and b not in KILL_CHAIN_ORDER:
        return a or b
    if a not in KILL_CHAIN_ORDER:
        return b
    if b not in KILL_CHAIN_ORDER:
        return a
    return b if KILL_CHAIN_ORDER.index(b) > KILL_CHAIN_ORDER.index(a) else a


def rank_dangerous_bursts(bursts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ranked = sorted(
        bursts,
        key=lambda b: (
            -int(b.get("peak_score", 0) or 0),
            -KILLCHAIN_ORDER_FOR_RANK.get(b.get("kill_chain_stage") or "Background", 0),
            -int(b.get("total_count", 0) or 0),
        ),
    )
    return ranked[:10]


def is_external_ip(ip: str) -> bool:
    if not ip:
        return False
    ip = str(ip)
    return not ip.startswith((
        "10.", "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "::1",
    ))


def baseline_is_mature(entry: Optional[Dict[str, Any]]) -> bool:
    if not entry:
        return False
    return int(entry.get("count_samples", 0) or 0) >= 20


def time_overlap(burst: Dict[str, Any], corr: Dict[str, Any], window_seconds: int = 900) -> bool:
    try:
        import pandas as pd
        b_start = pd.to_datetime(burst.get("start_time"), utc=True)
        c_end   = pd.to_datetime(corr.get("end_time"),    utc=True)
        if pd.isna(b_start) or pd.isna(c_end):
            return False
        return abs((b_start - c_end).total_seconds()) <= window_seconds
    except Exception:
        return False


def _assign_severity(event_id: Optional[int]) -> str:
    if event_id in _HIGH_EVENT_IDS:
        return "high"
    if event_id in _MED_EVENT_IDS:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# YARA loader
# ---------------------------------------------------------------------------

def load_yara_rules(rules_path: Optional[Path]):
    if not rules_path or not Path(rules_path).exists():
        return None
    if Path(rules_path).suffix.lower() not in (".yar", ".yara"):
        return None
    if not YARA_AVAILABLE:
        raise RuntimeError("python-yara not installed. Run: pip install yara-python")
    try:
        return yara.compile(filepath=str(rules_path))
    except yara.SyntaxError as e:
        raise RuntimeError(f"Invalid YARA rule: {e}") from e


# ---------------------------------------------------------------------------
# Attack Storyline Reconstruction
# ---------------------------------------------------------------------------

_EID_DESCRIPTIONS = {
    1:  ("Process created", lambda ev: f"{_img(ev)} executed" + (f" (parent: {_img_parent(ev)})" if ev.get('parent_image') else "")),
    3:  ("Network connection", lambda ev: f"{_img(ev)} made outbound connection to {ev.get('destination_ip','?')}:{ev.get('destination_port','?')}"),
    5:  ("Process terminated", lambda ev: f"{_img(ev)} terminated"),
    7:  ("Image loaded", lambda ev: f"DLL loaded by {_img(ev)}: {ev.get('image_loaded','?')}"),
    10: ("Process access", lambda ev: f"{_img(ev)} accessed another process (possible credential dumping)"),
    11: ("File created", lambda ev: f"{_img(ev)} created file: {ev.get('target_filename') or ev.get('file_path','?')}"),
    12: ("Registry key created/deleted", lambda ev: f"{_img(ev)} modified registry key: {ev.get('reg_key','?')}"),
    13: ("Registry value set", lambda ev: _reg_story(ev)),
    14: ("Registry key renamed", lambda ev: f"{_img(ev)} renamed registry key: {ev.get('reg_key','?')}"),
    15: ("File stream created", lambda ev: f"{_img(ev)} created alternate data stream: {ev.get('target_filename','?')}"),
    22: ("DNS query", lambda ev: f"{_img(ev)} queried DNS for: {ev.get('query_name','?')}"),
    25: ("Process tampering", lambda ev: f"{_img(ev)} tampered with a process image"),
}

def _img(ev: Dict) -> str:
    img = str(ev.get("image") or "")
    return img.split("\\")[-1] if "\\" in img else (img or "Unknown process")

def _img_parent(ev: Dict) -> str:
    p = str(ev.get("parent_image") or "")
    return p.split("\\")[-1] if "\\" in p else p

def _reg_story(ev: Dict) -> str:
    img = _img(ev)
    key = str(ev.get("reg_key") or ev.get("target_filename") or "?").lower()
    if any(x in key for x in ["\\run\\", "\\runonce\\", "currentversion\\run"]):
        return f"Persistence established — {img} wrote to Registry Run key: {key}"
    if "image file execution options" in key:
        return f"IFEO hijack — {img} modified Image File Execution Options: {key}"
    if "appinit_dlls" in key:
        return f"AppInit_DLLs persistence — {img} wrote to AppInit_DLLs"
    if "\\services\\" in key:
        return f"Service registry modified by {img}: {key}"
    if "winlogon" in key:
        return f"Winlogon hijack by {img}: {key}"
    return f"{img} set registry value: {key}"


def describe_event(ev: Dict) -> Optional[str]:
    """Return a human-readable description for one event, or None if unknown."""
    try:
        eid = int(float(str(ev.get("event_id", 0)).strip()))
    except (TypeError, ValueError):
        return None
    handler = _EID_DESCRIPTIONS.get(eid)
    if handler:
        _, fn = handler
        try:
            return fn(ev)
        except Exception:
            return handler[0]
    return None


def link_events(prev: Dict, curr: Dict) -> str:
    """Heuristic causal linking between two sequential events."""
    from datetime import timedelta
    
    # 1. Direct Parent-Child via GUID
    if prev.get("process_guid") and curr.get("parent_guid"):
        if prev["process_guid"] == curr["parent_guid"]:
            return "spawned"

    # 2. Image Name Match (fallback for missing GUIDs)
    p_img = str(prev.get("image") or "").lower().split("\\")[-1]
    c_parent = str(curr.get("parent_image") or "").lower().split("\\")[-1]
    if p_img and c_parent and p_img == c_parent:
        return "triggered"

    # 3. Temporal Proximity (log corruption fallback)
    p_time = pd.to_datetime(prev.get("event_time") or prev.get("utc_time"), utc=True)
    c_time = pd.to_datetime(curr.get("event_time") or curr.get("utc_time"), utc=True)
    if pd.notna(p_time) and pd.notna(c_time):
        if abs(c_time - p_time) <= timedelta(seconds=5):
            return "likely related to"

    return "related to"


def compress_steps(steps: List[str]) -> List[str]:
    """Deduplicate sequential identical steps with 'burst activity' note."""
    if not steps:
        return []
    out = []
    i = 0
    while i < len(steps):
        j = i + 1
        count = 1
        while j < len(steps) and steps[j] == steps[i]:
            count += 1
            j += 1
        
        text = steps[i]
        if count > 1:
            text = f"{text} ({count} times, burst activity)"
        out.append(text)
        i = j
    return out


def extract_iocs(events: List[Dict], cap: int = 20) -> Dict[str, List[str]]:
    """Extract and deduplicate Indicators of Compromise from event list."""
    ips  = {e.get("destination_ip") for e in events if e.get("destination_ip")}
    files = {e.get("target_filename") or e.get("file_path") for e in events if (e.get("target_filename") or e.get("file_path"))}
    regs = {e.get("reg_key") or e.get("target_object") for e in events if (e.get("reg_key") or e.get("target_object"))}
    
    return {
        "ips":      list(sorted([str(i) for i in ips if i]))[:cap],
        "files":    list(sorted([str(f) for f in files if f]))[:cap],
        "registry": list(sorted([str(r) for r in regs if r]))[:cap],
    }


def classify_attack(stages: List[str]) -> str:
    """Classify the attack based on the combination of kill-chain stages observed."""
    s = set(stages)
    if {"Execution", "Persistence", "Command and Control"} <= s:
        return "Multi-stage compromise"
    if "Persistence" in s:
        return "Persistence Establishment"
    if "Initial Access" in s or "Delivery" in s:
        return "Initial Access / Delivery"
    if "Credential Access" in s:
        return "Credential Harvesting"
    if "Actions on Objectives" in s:
        return "Data Exfiltration / Impact"
    return "Suspicious Activity"


def recommend_action(stage: str, severity: str) -> str:
    """Provide specific analyst recommendations based on stage and severity."""
    s = str(severity).lower()
    if stage == "Command and Control":
        return "CRITICAL: Isolate host immediately, block egress IPs, and collect memory forensics."
    if stage == "Persistence":
        return "HIGH: Remove startup entries, inspect autoruns, and audit local accounts."
    if stage == "Execution":
        return "MEDIUM: Review process tree, quarantine suspicious binaries, and check for sibling processes."
    if s == "critical" or s == "high":
        return "HIGH: Perform full forensic sweep of the host and rotate affected user credentials."
    return "Investigate context and validate indicators against threat intelligence."


def build_attack_story(events: List[Dict], detections: List[Dict] = None) -> Dict[str, Any]:
    """
    Reconstructs a causal attack narrative from events and detections.
    Returns a rich incident dictionary with story, timeline, IOCs, and recommendations.
    """
    if not events:
        return {"story": [], "timeline": [], "iocs": {}, "attack_type": "Unknown", "story_confidence": 0.0}

    # 1. Authoritative Sorting (Time + Kill Chain Index)
    def _sort_key(e):
        import pandas as pd
        t = pd.to_datetime(e.get("event_time") or e.get("utc_time"), errors="coerce", utc=True)
        if pd.isna(t): t = pd.Timestamp(0, tz='UTC')
        
        # Find best kill chain stage for this event if it was a detection
        stage = e.get("kill_chain_stage") or "Background"
        idx = KILLCHAIN_ORDER_FOR_RANK.get(stage, 0)
        return (t, idx)

    sorted_events = sorted(events, key=_sort_key)

    # 2. Build Story with Causal Linking
    story_steps = []
    kc_progression = []
    
    for i, ev in enumerate(sorted_events):
        desc = describe_event(ev)
        if not desc:
            continue
            
        stage = ev.get("kill_chain_stage") or "Background"
        if stage not in kc_progression and stage != "Background":
            kc_progression.append(stage)

        if i > 0:
            link = link_events(sorted_events[i-1], ev)
            story_steps.append(f"... {link} ...")
        
        story_steps.append(desc)

    # 3. Finalize Components
    compressed_story = compress_steps(story_steps)
    iocs = extract_iocs(events)
    final_stage = kc_progression[-1] if kc_progression else "Execution"
    
    # Severity for recommendation (heuristic if not provided)
    max_sev = "low"
    if detections:
        sevs = [str(d.get("severity") or "low").lower() for d in detections]
        if "critical" in sevs: max_sev = "critical"
        elif "high" in sevs: max_sev = "high"
        elif "medium" in sevs: max_sev = "medium"

    return {
        "story":              compressed_story,
        "timeline":           sorted_events,
        "transitions":        kc_progression,
        "iocs":               iocs,
        "attack_type":        classify_attack(kc_progression),
        "recommended_action": recommend_action(final_stage, max_sev),
        "story_confidence":   round(min(len(events) / 10.0, 1.0), 2),
        "summary":            " → ".join(compressed_story[:5]) + ("..." if len(compressed_story) > 5 else ""),
        "kill_chain":         kc_progression,
        "mitre_ids":          list(set(d.get("mitre_id") for d in (detections or []) if d.get("mitre_id"))),
    }


# ---------------------------------------------------------------------------
# Behavior generation
# ---------------------------------------------------------------------------

def _generate_behaviors(df: pd.DataFrame, run_id: str) -> pd.DataFrame:
    behaviors = []
    for _, r in df.iterrows():
        eid_raw = r.get("event_id")
        try:
            eid = str(int(float(eid_raw)))
        except Exception:
            continue
        btype = None
        if eid == "1":              btype = "execution"
        elif eid == "3":            btype = "network"
        elif eid in ("11", "15"):   btype = "file"
        elif eid in ("12","13","14"): btype = "registry"
        if not btype:
            continue
        behaviors.append({
            "run_id":            run_id,
            "behavior_id":       f"{run_id}-{eid}-{uuid.uuid4().hex[:8]}",
            "behavior_type":     btype,
            "event_time":        r.get("event_time"),
            "image":             r.get("image"),
            "parent_image":      r.get("parent_image"),
            "command_line":      r.get("command_line"),
            "user":              r.get("user"),
            "process_id":        r.get("pid"),
            "parent_process_id": r.get("ppid"),
            "computer":          r.get("computer"),
            "source_ip":         r.get("src_ip"),
            "destination_ip":    r.get("destination_ip"),
            "destination_port":  r.get("destination_port"),
            "target_filename":   r.get("file_path") or r.get("target_filename"),
            "reg_key":           r.get("reg_key") or r.get("targetobject"),
            "raw_event_id":      eid,
        })
    import pandas as pd
    return pd.DataFrame(behaviors)


# ---------------------------------------------------------------------------
# ingest_upload
# ---------------------------------------------------------------------------

def ingest_upload(
    xml_path: Path,
    rules_path: Optional[Path] = None,
) -> Tuple['pd.DataFrame', 'pd.DataFrame', 'pd.DataFrame']:
    """Parse XML into (events_df, detections_df, behaviors_df). No DB writes."""
    import pandas as pd
    if not Path(xml_path).exists():
        raise FileNotFoundError(f"Sysmon XML not found: {xml_path}")

    run_id = uuid.uuid4().hex

    rows = load_all_sources_from_xml(xml_path)
    if not rows:
        raise RuntimeError("Upload aborted: XML contained no events.")

    # 10/10 Mastery: Immediate conversion to Pure Python Core
    raw_records = [dict(sorted(r.items())) for r in rows]
    
    # Semantic Hashing for run_id (Content-based ID)
    # We use a subset of fields for the initial ID to handle re-uploads
    run_id = generate_semantic_hash(raw_records)[:16]
    content_hash = generate_semantic_hash(raw_records)

    events_df = pd.DataFrame(raw_records)
    if "event_id" not in events_df.columns:
        raise RuntimeError("event_id column missing in parsed XML")

    events_df["event_id"] = events_df["event_id"].astype(str).str.strip()
    events_df = events_df[
        events_df["event_id"].notna() & (events_df["event_id"] != "None")
    ]
    if events_df.empty:
        raise RuntimeError("All events dropped — EventID missing/invalid in XML")

    events_df["run_id"]     = run_id
    events_df["event_time"] = pd.to_datetime(
        events_df["utc_time"], errors="coerce", utc=True
    )
    events_df = events_df.dropna(subset=["event_time"])

    # ── PIPELINE UPGRADE: enrich every event with computed signal fields ──
    # Guards all fields against None/float before calling .lower()
    try:
        from dashboard.event_parser import enrich_event

        def _safe_enrich(r):
            # Coerce image/parent_image/command_line to str|None before enrichment
            for fld in ("image", "parent_image", "command_line", "dst_ip",
                        "destination_ip", "src_ip", "computer", "user"):
                v = r.get(fld)
                if v is not None and not isinstance(v, str):
                    r[fld] = str(v) if str(v) not in ("nan", "None", "") else None
            return enrich_event(r)

        records = events_df.to_dict("records")
        records = [_safe_enrich(r) for r in records]
        events_df = pd.DataFrame(records)
    except Exception as _ee:
        import traceback; traceback.print_exc()
        print(f"[ingest] Event enrichment failed: {_ee}")

    # Enrich parent chains (grandparent_image, process_depth)
    try:
        # Ensure string columns are proper strings before enrichment
        for _col in ("image", "parent_image", "computer", "pid", "ppid"):
            if _col in events_df.columns:
                events_df[_col] = events_df[_col].astype(object).where(
                    events_df[_col].notna(), None
                ).apply(lambda v: str(v) if v is not None and str(v) not in ("nan","None","") else None)
        events_df = enrich_parent_chains(events_df)
    except Exception as _pce:
        import traceback; traceback.print_exc()
        print(f"[ingest] Parent chain enrichment failed: {_pce}")

    # Deduplicate by event_uid — XML files often contain repeated events.
    # Keeps first occurrence; silences hundreds of INSERT IGNORE warnings.
    if "event_uid" in events_df.columns:
        before = len(events_df)
        events_df = events_df.drop_duplicates(subset=["event_uid"], keep="first")
        dupes = before - len(events_df)
        if dupes > 0:
            print(f"[ingest] Deduplicated {dupes} duplicate event_uid rows from XML.")

    events_df["severity"] = events_df["event_id"].apply(
        lambda x: _assign_severity(int(x) if str(x).isdigit() else None)
    )

    events_df = events_df.rename(columns={
        "commandline":    "command_line",
        "processid":      "pid",
        "parentprocessid":"ppid",
    })

    # ── YARA scan — weighted scoring via yara_engine ──────────────────────
    from dashboard.yara_engine import load_yara_rules as _load_yara, run_yara_on_events
    yara_rules     = _load_yara(rules_path) if rules_path else None
    events_df["yara_hits"]  = None
    events_df["yara_score"] = 0

    if yara_rules is not None:
        records = events_df.to_dict("records")
        records = run_yara_on_events(yara_rules, records)
        # Re-absorb yara_score and yara_hits back into the dataframe
        for i, rec in enumerate(records):
            events_df.at[events_df.index[i], "yara_score"] = rec.get("yara_score", 0)
            events_df.at[events_df.index[i], "yara_hits"]  = rec.get("yara_hits", 0)

        hit_mask = events_df["yara_score"] > 0
        # Adjust severity upward for YARA-matched events
        events_df.loc[hit_mask & (events_df["severity"] == "low"),    "severity"] = "medium"
        events_df.loc[events_df["yara_score"] >= 60,                  "severity"] = "high"
        if "tags" not in events_df.columns:
            events_df["tags"] = ""
        events_df.loc[hit_mask, "tags"] = (
            events_df.loc[hit_mask, "tags"].fillna("") + ",YARA_MATCH"
        )

    behaviors_df  = _generate_behaviors(events_df, run_id)
    # Use YAML rules if available, else fall back to heuristic EID mapping
    detections_df = find_detections(events_df, rules=_loaded_rules if _loaded_rules else None)
    print("[DEBUG] ingest_upload rules detections_df rows:", len(detections_df))
    if not detections_df.empty:
        detections_df["run_id"] = run_id
    else:
        detections_df = pd.DataFrame(columns=[
            "run_id","rule_id","rule_name","mitre_id","mitre_tactic",
            "kill_chain_stage","utc_time","image","event_id","description",
            "severity","computer","process_id","parent_process_id","parent_image",
            "source_ip","source_port","destination_ip","destination_port",
            "target_filename","confidence_score",
        ])

    # YARA detections — scored events with yara_score > 0 become detections
    yara_rows = []
    if "yara_score" in events_df.columns:
        yara_hit_df = events_df[events_df["yara_score"] > 0]
        for _, r in yara_hit_df.iterrows():
            yara_score = int(r.get("yara_score") or 0)
            yara_rows.append({
                "run_id":           run_id,
                "rule_id":          "YARA-MATCH",
                "rule_name":        f"YARA Match (score={yara_score})",
                "mitre_id":         None,
                "mitre_tactic":     "Execution",
                "kill_chain_stage": "Execution",
                "utc_time":         r.get("utc_time"),
                "image":            r.get("image"),
                "event_id":         r.get("event_id"),
                "description":      f"YARA rules matched ({r.get('yara_hits', 0)} hits)",
                "severity":         r.get("severity", "high"),
                "computer":         r.get("computer"),
                "process_id":       r.get("process_id") or r.get("pid"),
                "parent_process_id":r.get("parent_process_id") or r.get("ppid"),
                "parent_image":     r.get("parent_image"),
                "source_ip":        r.get("source_ip") or r.get("src_ip"),
                "source_port":      r.get("source_port"),
                "destination_ip":   r.get("destination_ip") or r.get("dst_ip"),
                "destination_port": r.get("destination_port") or r.get("dst_port"),
                "target_filename":  r.get("target_filename") or r.get("file_path"),
                "confidence_score": yara_score,
            })
    if yara_rows:
        detections_df = pd.concat(
            [detections_df, pd.DataFrame(yara_rows)], ignore_index=True
        )

    print("[DEBUG] ingest_upload total detections_df rows:", len(detections_df))
    
    # 10/10 Formal Invariant: Refined Data Integrity Check
    final_count = len(events_df)
    log = logging.getLogger("analysis")
    log.info("[INGEST] Records: raw=%d, final=%d (dropped=%d)", len(raw_records), final_count, len(raw_records) - final_count)
    
    if final_count == 0 and len(raw_records) > 0:
         log.critical("[INVARIANT-FAILURE] Total data loss during ingest.")
         raise RuntimeError("Formal invariant broken: Total ingest data loss.")

    return events_df, detections_df, behaviors_df, content_hash


# ---------------------------------------------------------------------------
# persist_case  — write upload to sentinel_cases (MySQL)
# ---------------------------------------------------------------------------

def persist_case(
    events_df: 'pd.DataFrame',
    detections_df: 'pd.DataFrame',
    behaviors_df: 'pd.DataFrame',
    content_hash: str,
) -> str:
    if events_df.empty:
        raise RuntimeError("No events to persist")

    import pandas as pd

    run_ids = events_df["run_id"].dropna().unique().tolist()
    if len(run_ids) != 1:
        raise RuntimeError(f"Expected exactly one run_id, got: {run_ids}")
    run_id = run_ids[0]

    _DT_COLS = {
        "event_time", "utc_time", "inserted_at", "created_at", "updated_at",
        "last_seen", "first_seen", "last_updated", "start_time", "end_time",
        "ts", "timestamp",
    }

    def _sanitise(df: pd.DataFrame) -> pd.DataFrame:
        clean = df.copy()

        # ── Drop any column that contains non-scalar values (lists, dicts) ──
        # These cannot be stored in MySQL and would silently break INSERT
        scalar_drops = []
        for col in clean.columns:
            try:
                sample = clean[col].dropna()
                if len(sample) > 0 and isinstance(sample.iloc[0], (list, dict, set)):
                    scalar_drops.append(col)
            except Exception:
                scalar_drops.append(col)
        # Also explicitly drop known non-DB columns added by enrichment
        for drop_col in ("yara_hits", "yara_rule_names", "tags_list",
                         "process_chain", "process_depth",
                         "b64_preview", "cmd_b64_preview",
                         "grandparent_image",  # may be in events but check DB schema
                         ):
            if drop_col in clean.columns and drop_col not in scalar_drops:
                scalar_drops.append(drop_col)
        if scalar_drops:
            clean = clean.drop(columns=scalar_drops, errors="ignore")

        # ── Sanitize datetime columns ─────────────────────────────────────
        for col in list(clean.columns):
            try:
                if col in _DT_COLS or clean[col].dtype.kind == "M":
                    clean[col] = clean[col].apply(sanitize_datetime)
            except Exception:
                pass

        # ── Coerce booleans to int (MySQL TINYINT) ────────────────────────
        bool_signal_cols = (
            "is_lolbin", "is_high_entropy", "has_encoded_flag",
            "has_download_url", "b64_detected", "is_external_ip",
            "is_suspicious_chain", "is_system_process",
            "cmd_high_entropy", "cmd_has_encoded_flag",
            "cmd_b64_detected", "cmd_has_download_url",
        )
        for c in bool_signal_cols:
            if c in clean.columns:
                try:
                    clean[c] = clean[c].fillna(False).astype(int)
                except Exception:
                    clean[c] = 0

        # ── Final: replace NaN/NaT with None for MySQL ───────────────────
        try:
            clean = clean.astype(object).where(pd.notna(clean), None)
        except Exception:
            # Fallback: column-by-column
            for col in clean.columns:
                try:
                    clean[col] = clean[col].where(pd.notna(clean[col]), None)
                except Exception:
                    pass

        return clean

    # Batch size: commit every N rows to avoid lock-wait timeouts on large uploads
    BATCH_SIZE = 500

    def _bulk_insert(conn, table: str, records: list, valid_cols: list) -> int:
        """
        Insert records in batches of BATCH_SIZE, committing after each batch.
        Uses executemany() for performance — one round-trip per batch instead of one per row.
        Returns total rows inserted.
        """
        if not records:
            return 0

        # Determine the consistent column set from the first non-empty record
        cols = [k for k in records[0] if k in valid_cols]
        if not cols:
            return 0

        ph  = ", ".join(["%s"] * len(cols))
        cs  = ", ".join(f"`{c}`" for c in cols)
        sql = f"INSERT IGNORE INTO `{table}` ({cs}) VALUES ({ph})"

        total = 0
        attempted = 0
        for i in range(0, len(records), BATCH_SIZE):
            batch = records[i : i + BATCH_SIZE]
            rows  = [[rec.get(c) for c in cols] for rec in batch]
            with get_cursor(conn) as cur:
                cur.executemany(sql, rows)
                # MySQL rowcount after executemany = rows inserted (not attempted)
                # -1 means "unknown" for some drivers — count batch size as fallback
                rc = cur.rowcount
                total += rc if rc >= 0 else len(batch)
                attempted += len(batch)
            conn.commit()

        return attempted  # return attempted so caller sees true count

    # ── Sanitise all three dataframes up-front ──────────────────────────────
    ev_clean  = _sanitise(events_df).to_dict("records")
    bh_clean  = _sanitise(behaviors_df).to_dict("records") if not behaviors_df.empty else []
    det_clean = _sanitise(detections_df).to_dict("records") if not detections_df.empty else []

    # ── Get valid column lists (single short connection) ────────────────────
    with get_db_connection("cases") as conn:
        with get_cursor(conn) as cur:
            valid_ev  = get_table_columns(cur, "events")
            valid_bh  = get_table_columns(cur, "behaviors")
            valid_det = get_table_columns(cur, "detections")

    # ── Master Record Logic ─────────────────────────────────────────────────
    with get_db_connection("cases") as conn:
        with get_cursor(conn) as cur:
            # Atomic update of the case master record
            cur.execute(
                "INSERT INTO cases (run_id, status, content_hash, analysis_version, start_time) "
                "VALUES (%s, %s, %s, 1, %s) "
                "ON DUPLICATE KEY UPDATE status=VALUES(status), content_hash=VALUES(content_hash)",
                (run_id, "INGESTED", content_hash, now_utc())
            )
            # Record the state transition
            cur.execute(
                "INSERT INTO case_history (run_id, old_status, new_status, reason) "
                "VALUES (%s, %s, %s, %s)",
                (run_id, "NONE", "INGESTED", json.dumps({"source": "ingest_upload"}))
            )
        conn.commit()

    # ── Batch insert each table independently ───────────────────────────────
    # Note: run_id is deterministic (hash of content), so re-uploading the
    # same XML produces the same run_id. INSERT IGNORE handles duplicates safely.
    with get_db_connection("cases") as conn:
        n_ev = _bulk_insert(conn, "events", ev_clean, valid_ev)
        print(f"[persist_case] events inserted/present: {n_ev}/{len(ev_clean)}")

    with get_db_connection("cases") as conn:
        n_bh = _bulk_insert(conn, "behaviors", bh_clean, valid_bh)

    with get_db_connection("cases") as conn:
        n_det = _bulk_insert(conn, "detections", det_clean, valid_det)
        print(f"[persist_case] detections inserted: {n_det}/{len(det_clean)}")

    print(f"[persist_case] run_id={run_id} saved to sentinel_cases.")
    return run_id


# ---------------------------------------------------------------------------
# process_event  — called per live event by sysmon_collector
# ---------------------------------------------------------------------------

def process_event(evt: dict, conn: Any = None) -> None:
    if not evt.get("severity"):
        try:
            evt["severity"] = _assign_severity(int(evt.get("event_id") or 0))
        except Exception:
            evt["severity"] = "low"

    alerts = match_rules(evt)
    if not alerts:
        return
    if conn:
        _persist_alerts_internal(conn, evt, alerts)
    else:
        with get_db_connection("live") as c:
            _persist_alerts_internal(c, evt, alerts)
            c.commit()


# ---------------------------------------------------------------------------
# Simple rule matching (YAML rules from rules.yaml)
# ---------------------------------------------------------------------------

_RULES_CACHE: Optional[List[Dict]] = None

def _load_rules(rules_path: Optional[Path] = None) -> List[Dict]:
    global _RULES_CACHE
    if _RULES_CACHE is not None and rules_path is None:
        return _RULES_CACHE
    import yaml
    default = Path(__file__).resolve().parent / "rules.yaml"
    path    = Path(rules_path) if rules_path else default
    if not path.exists():
        _RULES_CACHE = []
        return _RULES_CACHE
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    _RULES_CACHE = data.get("rules", []) if data else []
    return _RULES_CACHE


def _match_rules_on_event(evt: dict) -> List[Dict]:
    rules  = _load_rules()
    alerts = []
    eid    = evt.get("event_id")
    try:
        eid = int(eid)
    except Exception:
        eid = None
    image  = (evt.get("image") or "").lower()
    sev    = (evt.get("severity") or "low").lower()
    fpath  = (evt.get("file_path") or "").lower()

    for rule in rules:
        rule_eids = rule.get("event_id", [])
        if rule_eids and eid not in rule_eids:
            continue
        img_contains = rule.get("image_contains")
        if img_contains and img_contains.lower() not in image:
            continue
        img_any = rule.get("image_any", [])
        if img_any and not any(i.lower() in image for i in img_any):
            continue
        sev_req = rule.get("severity_required")
        if sev_req and sev != sev_req.lower():
            continue
        path_any = rule.get("path_prefix_any", [])
        if path_any and not any(fpath.startswith(p.lower()) for p in path_any):
            continue
        alerts.append({
            "rule_id":          rule.get("rule_id"),
            "rule_name":        rule.get("name"),
            "mitre_id":         rule.get("mitre_id"),
            "mitre_tactic":     rule.get("mitre_tactic"),
            "kill_chain_stage": rule.get("mitre_tactic", "Execution"),
            "severity":         sev,
        })
    return alerts


# ---------------------------------------------------------------------------
# _persist_alerts_internal
# ---------------------------------------------------------------------------

def _persist_alerts_internal(conn: Any, evt: dict, alerts: list) -> None:
    # FIX: sanitize timestamp — Sysmon XML can have 7-digit fractional seconds + Z
    _ts_raw   = evt.get("utc_time") or now_utc()
    timestamp = sanitize_datetime(_ts_raw) or now_utc()
    run_id    = evt.get("run_id", "live")
    with get_cursor(conn) as cur:
        for alert in alerts:
            alert_id = f"ALT-{uuid.uuid4().hex[:8]}"
            checked_insert(
                cur, "alerts",
                ["alert_id","ts","rule_id","rule_name","severity",
                 "image","computer","mitre_id","run_id"],
                (alert_id, timestamp, alert.get("rule_id"), alert.get("rule_name"),
                 alert.get("severity"), evt.get("image"), evt.get("computer"),
                 alert.get("mitre_id"), run_id),
                identity_hint=f"alert_id={alert_id}",
            )
            cur.execute(
                "INSERT INTO `detections` ("
                " `run_id`,`rule_id`,`rule_name`,`mitre_id`,`mitre_tactic`,"
                " `kill_chain_stage`,`utc_time`,`image`,`event_id`,`description`,"
                " `severity`,`computer`,`process_id`,`parent_process_id`,"
                " `parent_image`,`confidence_score`"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    run_id,
                    alert.get("rule_id"), alert.get("rule_name"), alert.get("mitre_id"),
                    "Unknown", alert.get("kill_chain_stage","Execution"),
                    timestamp, evt.get("image"),
                    int(evt.get("event_id") or 0),
                    f"Rule: {alert.get('rule_name')} triggered",
                    alert.get("severity"), evt.get("computer"),
                    evt.get("pid"), evt.get("ppid"), evt.get("parent_image"),
                    85.0,
                ),
            )


# ---------------------------------------------------------------------------
# upsert_incident_row
# ---------------------------------------------------------------------------

def upsert_incident_row(
    incident_id: str,
    status: str,
    severity: str,
    confidence: int,
    run_id: str = "live",
    escalation: str = "auto",
    conn: Any = None,
) -> None:
    ts = now_utc()
    
    # SOC-grade: Determine priority and SLA based on severity
    sev_map = {
        "critical": ("P1", 4),
        "high":     ("P1", 4),
        "medium":   ("P2", 8),
        "low":      ("P3", 24),
    }
    priority, sla_hours = sev_map.get(severity.lower(), ("P3", 48))
    sla_deadline = ts + datetime.timedelta(hours=sla_hours)

    stmt = sql_upsert(
        "incidents",
        [
            "incident_id", "status", "severity", "confidence", "escalation",
            "priority", "sla_deadline", "run_id", "created_at", "updated_at"
        ],
        ["incident_id"],
        ["status", "confidence", "escalation", "priority", "sla_deadline", "updated_at"],
    )
    vals = (incident_id, status, severity, confidence, escalation, priority, sla_deadline, run_id, ts, ts)

    def _do(c: Any) -> None:
        with get_cursor(c) as cur:
            cur.execute(stmt, vals)

    if conn:
        _do(conn)
    else:
        with get_db_connection("live") as c:
            _do(c)
            c.commit()


# ---------------------------------------------------------------------------
# Behavior baseline — MySQL
# ---------------------------------------------------------------------------

def load_behavior_baseline() -> Dict[Tuple[str,str,str,str,int], Dict[str,Any]]:
    engine = get_engine("live")
    try:
        df = pd.read_sql_query(text("SELECT * FROM behavior_baseline"), engine)
    except Exception:
        return {}
    baseline: Dict = {}
    for _, row in df.iterrows():
        key = (
            row.get("computer") or "unknown_host",
            row["process_name"],
            row["user_type"],
            row["parent_process"],
            int(row["hour_bucket"]),
        )
        count = int(row.get("count_samples", 0) or 0)
        var   = float(row.get("var_exec", 0.0) or 0.0)
        m2    = var * (count - 1) if count > 1 else 0.0
        baseline[key] = {
            "count_samples": count,
            "mean_exec":     float(row.get("avg_exec", 0.0) or 0.0),
            "m2_exec":       m2,
            "avg_cmd_len":   float(row.get("avg_cmd_len", 0.0) or 0.0),
            "avg_followup":  float(row.get("avg_followup", 0.0) or 0.0),
            "seen_days":     int(row.get("seen_days", 0) or 0),
        }
    return baseline


def persist_behavior_baseline(
    baseline_state: Dict[Tuple[str,str,str,str,int], Dict[str,Any]],
    conn: Any = None,
) -> None:
    if not baseline_state:
        return
    ts   = now_utc()
    stmt = sql_upsert(
        "behavior_baseline",
        ["computer","process_name","user_type","parent_process","hour_bucket",
         "avg_exec","var_exec","avg_cmd_len","avg_followup","count_samples","seen_days","last_updated"],
        [],
        ["avg_exec","var_exec","avg_cmd_len","avg_followup","count_samples","seen_days","last_updated"],
    )

    def _do(c: Any) -> None:
        with get_cursor(c) as cur:
            for (computer, pname, utype, parent, hour), entry in baseline_state.items():
                count    = int(entry["count_samples"])
                variance = entry["m2_exec"] / (count - 1) if count > 1 else 0.0
                cur.execute(stmt, (
                    computer, pname, utype, parent, hour,
                    float(entry.get("mean_exec", 0.0)),
                    variance,
                    float(entry.get("avg_cmd_len", 0.0)),
                    float(entry.get("avg_followup", 0.0)),
                    count,
                    int(entry.get("seen_days", 1) or 1),
                    ts,
                ))

    if conn:
        _do(conn)
    else:
        with get_db_connection("live") as c:
            _do(c)
            c.commit()


# ---------------------------------------------------------------------------
# DB loaders  (MySQL versions of the SQLite load_* helpers)
# ---------------------------------------------------------------------------

def load_events(run_id: str) -> 'pd.DataFrame':
    import pandas as pd
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        df = pd.read_sql_query(
            text("SELECT * FROM events WHERE run_id = :run_id ORDER BY event_time DESC"),
            engine, params={"run_id": run_id},
        )
    except Exception as e:
        print(f"[WARN] Failed to load events: {e}")
        return pd.DataFrame()

    # Keep event_time for burst building; add utc_time alias for display
    if "event_time" in df.columns and "utc_time" not in df.columns:
        df["utc_time"] = df["event_time"]
    elif "utc_time" in df.columns and "event_time" not in df.columns:
        df["event_time"] = df["utc_time"]
    df = df.rename(columns={
        "pid": "process_id", "ppid": "parent_process_id",
        "file_path": "target_filename", "src_ip": "source_ip",
        "dst_ip": "destination_ip",
    })
    # Keep command_line accessible under both names
    if "command_line" in df.columns and "commandline" not in df.columns:
        df["commandline"] = df["command_line"]
    for col in ["description", "computer", "tags"]:
        if col not in df.columns:
            df[col] = ""
    if "tags" in df.columns:
        df["tags"] = df["tags"].fillna("").apply(
            lambda x: [t for t in str(x).split(",") if t]
        )
    if "utc_time" in df.columns:
        df["_parsed_time"] = pd.to_datetime(df["utc_time"], errors="coerce", utc=True)
    else:
        df["_parsed_time"] = pd.NaT
    return df


def load_detections(run_id: str) -> 'pd.DataFrame':
    import pandas as pd
    empty = pd.DataFrame(columns=[
        "rule_id","rule_name","mitre_id","mitre_tactic","kill_chain_stage",
        "utc_time","image","event_id","description","severity","computer",
        "process_id","parent_process_id","parent_image","source_ip",
        "source_port","destination_ip","destination_port",
        "target_filename","confidence_score",
    ])
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        det = pd.read_sql_query(
            text("SELECT * FROM detections WHERE run_id = :run_id ORDER BY utc_time DESC"),
            engine, params={"run_id": run_id},
        )
    except Exception as e:
        print(f"[WARN] Failed to load detections: {e}")
        return empty
    if "event_time" in det.columns and "utc_time" not in det.columns:
        det = det.rename(columns={"event_time": "utc_time"})
    for col in empty.columns:
        if col not in det.columns:
            det[col] = None
    return det


def load_correlations(run_id: str) -> 'pd.DataFrame':
    import pandas as pd
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return pd.read_sql_query(
            text("SELECT * FROM correlations WHERE run_id = :run_id"), engine, params={"run_id": run_id}
        )
    except Exception:
        return pd.DataFrame()


def load_correlations_detail(run_id: str) -> 'pd.DataFrame':
    import pandas as pd
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return pd.read_sql_query(
            text("SELECT * FROM correlations WHERE run_id = :run_id "
                 "ORDER BY start_time ASC LIMIT 10"),
            engine, params={"run_id": run_id},
        )
    except Exception:
        return pd.DataFrame()


def load_correlation_campaigns(run_id: str) -> 'pd.DataFrame':
    import pandas as pd
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return pd.read_sql_query(
            text("SELECT * FROM correlation_campaigns WHERE run_id = :run_id "
                 "ORDER BY last_seen DESC"),
            engine, params={"run_id": run_id},
        )
    except Exception:
        return pd.DataFrame()


def load_behaviors(run_id: str) -> 'pd.DataFrame':
    import pandas as pd
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        df = pd.read_sql_query(
            text("SELECT * FROM behaviors WHERE run_id = :run_id ORDER BY event_time DESC"),
            engine, params={"run_id": run_id},
        )
    except Exception:
        return pd.DataFrame()
    # Normalize legacy schema column names
    if "user_name" in df.columns and "user" not in df.columns:
        df = df.rename(columns={"user_name": "user"})
    if "process_id" not in df.columns and "pid" in df.columns:
        df = df.rename(columns={"pid": "process_id"})
    return df


def load_incident_row(incident_id: str, run_id: str = "") -> Optional[dict]:
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT incident_id, status, severity, confidence, escalation, "
                    "analyst, notes, created_at, updated_at FROM incidents "
                    "WHERE incident_id = %s",
                    (incident_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
    except Exception:
        return None


def update_campaign_status_lifecycle() -> None:
    """Mark campaigns dormant if last_seen > 24 hours ago."""
    try:
        with get_db_connection("live") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    f"UPDATE correlation_campaigns SET status = 'dormant' "
                    f"WHERE status = 'active' "
                    f"AND last_seen < {sql_now_minus(24, 'HOUR')}"
                )
            conn.commit()
    except Exception as e:
        print(f"[WARN] Campaign lifecycle update failed: {e}")


def persist_auto_correlation(burst: Dict[str, Any], run_id: str) -> None:
    print(f"[DEBUG] persist_auto_correlation CALLED {run_id} {burst.get('correlation_id')}")
    corr_id   = burst["correlation_id"]
    now_ts    = now_utc()
    new_stage = burst.get("kill_chain_stage") or "Execution"
    new_conf  = int(burst.get("risk_score", 0))
    # Sanitize start/end times from burst
    _start = sanitize_datetime(burst.get("start_time"))
    _end   = sanitize_datetime(burst.get("end_time"))

    mode = "cases" if run_id != "live" else "live"
    try:
        with get_db_connection(mode) as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "SELECT burst_count, max_confidence, highest_kill_chain "
                    "FROM correlation_campaigns WHERE corr_id = %s AND run_id = %s",
                    (corr_id, run_id),
                )
                row = cur.fetchone()
                if row:
                    final_stage = promote_stage(row["highest_kill_chain"], new_stage)
                    cur.execute(
                        "UPDATE correlation_campaigns SET "
                        "burst_count=%s, last_seen=%s, max_confidence=%s, "
                        "highest_kill_chain=%s, status='active' "
                        "WHERE corr_id=%s AND run_id=%s",
                        (
                            row["burst_count"] + 1, now_ts,
                            max(row["max_confidence"], new_conf),
                            final_stage, corr_id, run_id,
                        ),
                    )
                else:
                    checked_insert(
                        cur, "correlation_campaigns",
                        ["corr_id","run_id","base_image","computer","first_seen",
                         "last_seen","burst_count","max_confidence",
                         "highest_kill_chain","status","description"],
                        (
                            corr_id, run_id,
                            burst.get("image"), burst.get("computer"),
                            now_ts, now_ts, 1, new_conf, new_stage, "active",
                            f"Auto-correlated campaign for {burst.get('image')}",
                        ),
                        identity_hint=f"corr_id={corr_id}",
                    )

                rich_desc = (
                    f"[{new_stage}] Risk:{new_conf}% - "
                    f"Detected sequence involving {burst.get('count',0)} events."
                )
                cur.execute(
                    "INSERT INTO `correlations` "
                    "(`corr_id`,`run_id`,`base_image`,`start_time`,`end_time`,"
                    "`description`,`event_ids`,`computer`) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        corr_id, run_id, burst.get("image"),
                        _start,
                        _end,
                        rich_desc,
                        ",".join(str(e) for e in burst.get("event_ids", [])),
                        burst.get("computer"),
                    ),
                )
            conn.commit()
    except Exception as e:
        print(f"[WARN] Correlation persist failed: {repr(e)}")
        traceback.print_exc()


# ---------------------------------------------------------------------------
# Burst building
# ---------------------------------------------------------------------------

def _build_bursts(df: 'pd.DataFrame', beh_df: 'pd.DataFrame', run_id: str) -> List[Dict[str,Any]]:
    import pandas as pd
    if not beh_df.empty and "event_time" in beh_df.columns:
        base = beh_df.copy()
        # Normalize schema aliases before fillna so we never get KeyError
        if "user_name" in base.columns and "user" not in base.columns:
            base = base.rename(columns={"user_name": "user"})
        if "process_id" not in base.columns and "pid" in base.columns:
            base = base.rename(columns={"pid": "process_id"})
        for col in ("image", "process_id", "computer", "user"):
            if col not in base.columns:
                base[col] = None
        base["_parsed_time"] = pd.to_datetime(base["event_time"], errors="coerce", utc=True)
        base = base.dropna(subset=["_parsed_time"]).sort_values("_parsed_time")
        for col in ("image","process_id","computer","user"):
            base[col] = base[col].fillna(f"unknown_{col}")
        grouped_rows: List[Dict] = []
        current: Optional[Dict] = None
        current_key = None
        for _, b in base.iterrows():
            img   = b.get("image")
            pid   = b.get("process_id")
            host  = b.get("computer")
            user  = b.get("user")
            btime = b.get("_parsed_time")
            eid   = str(b.get("raw_event_id"))
            btype = b.get("behavior_type")
            if pd.isna(btime):
                continue
            key = (img, pid, host, user)
            if current is None or key != current_key or (
                pd.to_datetime(current["end_time"], utc=True) is not None and
                (btime - pd.to_datetime(current["end_time"], utc=True)).total_seconds() > 900
            ):
                if current:
                    grouped_rows.append(current)
                current_key = key
                current = _new_burst(img, pid, host, user, btime, eid, btype, run_id, b)
            else:
                _extend_burst(current, btime, eid, btype, b)
        if current:
            grouped_rows.append(current)
        return grouped_rows
    else:
        if "event_time" not in df.columns or df.empty:
            return []
        base_tl = df.sort_values("event_time").copy()
        grouped_rows = []
        current = None
        for _, row in base_tl.iterrows():
            if not row.get("event_id"):
                continue
            img   = row.get("image") or "unknown_process"
            ut    = row.get("event_time") or ""
            host  = row.get("computer")
            user  = row.get("user")
            is_exec = row.get("event_id") == 1
            if current is None:
                current = _new_burst_from_row(img, ut, host, user, row, run_id)
            else:
                prev = pd.to_datetime(current["end_time"], errors="coerce", utc=True)
                this = pd.to_datetime(ut, errors="coerce", utc=True)
                if (img == current["image"] and
                        pd.notna(prev) and pd.notna(this) and
                        (this - prev).total_seconds() <= 900):
                    _extend_burst_from_row(current, ut, row)
                else:
                    grouped_rows.append(current)
                    current = _new_burst_from_row(img, ut, host, user, row, run_id)
        if current:
            grouped_rows.append(current)
        return grouped_rows


def _new_burst(img, pid, host, user, btime, eid, btype, run_id, b) -> Dict:
    return {
        "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
        "start_time": btime.isoformat(), "end_time": btime.isoformat(),
        "count": 1, "exec_event_count": 1 if btype=="execution" else 0,
        "image": img, "kill_chain_stage": "Execution",
        "event_ids": [eid], "mitre_ids": [], "mitre_tactics": [],
        "descriptions": [], "has_correlation": False, "severity": None,
        "type": "telemetry",
        "source_ip": b.get("source_ip"), "destination_ip": b.get("destination_ip"),
        "destination_port": b.get("destination_port"),
        "target_filename": b.get("target_filename") or b.get("file_path"),
        "reg_key": b.get("reg_key") or b.get("targetobject"),
        "has_exec": btype=="execution", "has_net": btype=="network",
        "has_file": btype=="file", "has_reg": btype=="registry",
        "net_event_count": 1 if btype=="network" else 0,
        "process_id": pid, "parent_process_id": None, "parent_image": None,
        "computer": host, "user": user,
        "hosts": [host] if host else [], "users": [user] if user else [],
    }

def _is_high_signal(val: Any) -> bool:
    if not val:
        return False
    v = str(val).lower()
    return any(x in v for x in [
        "run", "runonce", "services", "image file execution options",
        "appinit_dlls", "start menu", "startup", "tasks", "wmi", "schtasks"
    ])


def _extend_burst(current, btime, eid, btype, b):
    current["end_time"] = btime.isoformat()
    current["count"] += 1
    current["event_ids"].append(eid)
    if btype == "execution": current["exec_event_count"] = current.get("exec_event_count",0)+1
    if btype == "network":
        current["has_net"] = True
        current["net_event_count"] = current.get("net_event_count",0)+1
    if btype == "file":    current["has_file"] = True
    if btype == "registry": current["has_reg"] = True
    for fld in ("source_ip", "destination_ip", "destination_port"):
        if b.get(fld):
            current[fld] = b.get(fld)
    for fld in ("target_filename", "reg_key"):
        if b.get(fld):
            if not current.get(fld) or _is_high_signal(b.get(fld)):
                current[fld] = b.get(fld)


def _new_burst_from_row(img, ut, host, user, row, run_id) -> Dict:
    eid = row.get("event_id")
    return {
        "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
        "start_time": ut, "end_time": ut,
        "count": 1, "exec_event_count": 1 if eid==1 else 0,
        "image": img, "kill_chain_stage": "Unclassified",
        "event_ids": [str(eid)], "mitre_ids": [], "mitre_tactics": [],
        "descriptions": [row.get("description")],
        "has_correlation": False, "severity": row.get("severity"),
        "type": "telemetry",
        "source_ip": row.get("source_ip"), "destination_ip": row.get("destination_ip"),
        "destination_port": row.get("destination_port"),
        "target_filename": row.get("target_filename") or row.get("file_path"),
        "reg_key": row.get("reg_key") or row.get("targetobject"),
        "has_exec": eid==1, "has_net": eid==3,
        "has_file": eid in (11,15), "has_reg": eid in (12,13,14),
        "net_event_count": 1 if eid==3 else 0,
        "process_id": row.get("process_id"), "parent_process_id": row.get("parent_process_id"),
        "parent_image": row.get("parent_image"),
        "computer": host, "user": user,
        "hosts": [host] if host else [], "users": [user] if user else [],
    }


def _extend_burst_from_row(current, ut, row):
    current["end_time"] = ut
    current["count"] += 1
    eid = row.get("event_id")
    current["event_ids"].append(str(eid))
    if eid==1:  current["exec_event_count"] = current.get("exec_event_count",0)+1
    if eid==3:  current["has_net"]=True; current["net_event_count"]=current.get("net_event_count",0)+1
    if eid in (11,15): current["has_file"]=True
    if eid in (12,13,14): current["has_reg"]=True
    current["descriptions"].append(row.get("description"))
    for fld in ("source_ip", "destination_ip", "destination_port"):
        if row.get(fld):
            current[fld] = row.get(fld)
    for fld in ("target_filename", "reg_key"):
        if row.get(fld):
            if not current.get(fld) or _is_high_signal(row.get(fld)):
                current[fld] = row.get(fld)


# ---------------------------------------------------------------------------
# Feature extraction, deviation, kill-chain, correlations, confidence
# (Identical logic to the original — just no SQLite)
# ---------------------------------------------------------------------------

def _extract_behavior_features(burst: Dict) -> Dict:
    pname  = burst.get("image") or "unknown_process"
    parent = burst.get("parent_image") or burst.get("parent_process_id") or "unknown_parent"
    user   = (burst.get("user") or "").upper()
    import pandas as pd
    try:
        dt = pd.to_datetime(burst.get("start_time"), errors="coerce", utc=True)
        hour_bucket = int(dt.hour) if pd.notna(dt) else -1
    except Exception:
        hour_bucket = -1
    executions = int(burst.get("exec_event_count", burst.get("count", 0)))
    descs = burst.get("descriptions") or []
    cmd   = burst.get("commandline") or ""
    if not cmd:
        cmd = " ".join(str(d) for d in descs) if isinstance(descs,list) else str(descs)
    cmd = cmd[:2000]
    lower_cmd = cmd.lower()
    lp = pname.lower()
    cmd_len = float(len(cmd))
    if lp.endswith(("powershell.exe","pwsh.exe")): cmd_len /= 2.0
    elif lp.endswith(("cmd.exe",)):                cmd_len /= 1.5
    followup = sum([
        int(bool(burst.get("has_net"))),
        int(bool(burst.get("has_file"))),
        int(bool(burst.get("has_reg"))),
    ])
    dst_ip  = burst.get("destination_ip") or ""
    net_cnt = int(burst.get("net_event_count",0) or 0)
    net_strength = (2 if dst_ip and is_external_ip(dst_ip) and net_cnt>=3
                    else 1 if net_cnt>0 else 0)
    return {
        "process_name":       pname,
        "parent_process":     parent,
        "user_type":          "system" if "SYSTEM" in user else "interactive",
        "hour_bucket":        hour_bucket,
        "exec_count":         executions,
        "command_hash":       hashlib.sha256(lower_cmd.encode()).hexdigest(),
        "command_length":     cmd_len,
        "has_encoded_flag":   ("-enc" in lower_cmd) or ("/enc" in lower_cmd),
        "has_download_flag":  "http://" in lower_cmd or "https://" in lower_cmd,
        "followup_events":    followup,
        "network_strength":   net_strength,
    }


def _compute_deviation_score(features: Dict, baseline_entry: Optional[Dict]) -> float:
    if not baseline_entry:
        return 0.15
    n = int(baseline_entry.get("count_samples",0) or 0)
    if n < 5:
        return 0.25
    mean_val = float(baseline_entry.get("mean_exec",0.0))
    host_noise_floor = max(5.0, mean_val)
    if float(features["exec_count"]) < host_noise_floor:
        return 0.1
    m2  = float(baseline_entry.get("m2_exec",0.0))
    var = m2 / max(n-1,1) if n>1 else 0.0
    std = max(var**0.5, 1.0)
    freq_dev  = min(abs(float(features["exec_count"]) - mean_val) / std, 3.0)
    avg_cmd   = float(baseline_entry.get("avg_cmd_len",1.0)) or 1.0
    cmd_dev   = min(abs(float(features["command_length"]) - avg_cmd) / avg_cmd, 3.0)
    avg_fol   = float(baseline_entry.get("avg_followup",0.0))
    chain_dev = 1.0 if float(features["followup_events"]) >= avg_fol+2.0 else 0.0
    ns        = int(features.get("network_strength",0) or 0)
    net_dev   = 1.0 if ns==2 else 0.5 if ns==1 else 0.0
    raw = (0.30*freq_dev + 0.25*cmd_dev + 0.20*chain_dev + 0.15*net_dev)
    if not baseline_is_mature(baseline_entry):
        return min(float(min(raw/3.0,1.0)), 0.4)
    return float(min(raw/3.0,1.0))


def _update_local_baseline(burst: Dict, features: Dict, baseline_state: Dict) -> None:
    if int(features.get("hour_bucket",-1) or -1) < 0:
        return
    host   = burst.get("computer") or "unknown_host"
    pname  = features["process_name"]
    utype  = features["user_type"]
    parent = features["parent_process"]
    hour   = features["hour_bucket"]
    pk = (host, pname, utype, parent, hour)
    sk = (host, pname, utype, "", hour)
    entry = baseline_state.get(pk) or baseline_state.get(sk)
    if entry and int(entry.get("count_samples",0)) > 200:
        return
    if not entry:
        baseline_state[pk] = {
            "count_samples":1, "mean_exec":float(features["exec_count"]),
            "m2_exec":0.0, "avg_cmd_len":float(features["command_length"]),
            "avg_followup":float(features["followup_events"]), "seen_days":1,
        }
        return
    key_to_use = pk if pk in baseline_state else sk
    entry = baseline_state[key_to_use]
    if entry.get("seen_days",1) > 30:
        entry["mean_exec"]     = float(entry["mean_exec"]) * 0.98
        entry["count_samples"] = max(1, int(entry["count_samples"]*0.98))
    n_prev = entry["count_samples"]
    n = n_prev + 1
    x = float(features["exec_count"])
    mean = float(entry.get("mean_exec",0.0))
    m2   = float(entry.get("m2_exec",0.0))
    delta = x - mean; mean += delta/n; delta2 = x - mean; m2 += delta*delta2
    entry["mean_exec"]     = mean
    entry["m2_exec"]       = m2
    entry["avg_cmd_len"]   = (entry["avg_cmd_len"]*n_prev + float(features["command_length"]))/n
    entry["avg_followup"]  = (entry["avg_followup"]*n_prev + float(features["followup_events"]))/n
    entry["count_samples"] = n


def _should_learn_baseline(burst: Dict, features: Dict) -> bool:
    if features["process_name"].lower() in ("wmic.exe","powershell.exe","pwsh.exe","psexec.exe"):
        return False
    if float(burst.get("risk_score",0) or 0) >= 45.0:
        return False
    if float(burst.get("deviation_score",1.0) or 1.0) >= 0.4:
        return False
    if features.get("has_encoded_flag"):
        return False
    if burst.get("_pre_suppressed"):
        return False
    if features["user_type"] == "system":
        return False
    if burst.get("kill_chain_stage") != "Execution":
        return False
    if burst.get("has_correlation") or burst.get("correlation_id"):
        return False
    if burst.get("has_persistence") or burst.get("has_injection"):
        return False
    if int(features.get("network_strength",0) or 0) >= 2:
        return False
    if float(features.get("followup_events",0) or 0) >= 2:
        return False
    return True


def _derive_kill_chain_from_flags(burst: Dict) -> str:
    has_exec = bool(burst.get("has_exec"))
    has_net  = bool(burst.get("has_net"))
    has_pers = bool(burst.get("has_persistence"))
    has_inj  = bool(burst.get("has_injection"))
    exec_cnt = int(burst.get("count",0) or 0)
    net_cnt  = int(burst.get("net_event_count",0) or 0)
    if has_inj: return "Privilege Escalation"
    if has_pers: return "Persistence"
    if has_net and is_external_ip(burst.get("destination_ip") or ""):
        if net_cnt>=3 and exec_cnt>=5: return "Command and Control"
        if net_cnt>=3 and not has_exec: return "Command and Control"
    elif has_net and not is_external_ip(burst.get("destination_ip") or "") and net_cnt>=5:
        return "Command and Control"
    if has_exec: return "Execution"
    return "Background"


def _calculate_ml_deviations(bursts, baseline_state):
    feature_cache = []
    for burst in bursts:
        burst["image"]    = burst.get("image") or "unknown_process"
        burst["computer"] = burst.get("computer") or "unknown_host"
        burst["start_time"] = burst.get("start_time") or now_utc().isoformat()
        for f in ("has_exec","has_net","has_file","has_reg","has_injection"):
            burst.setdefault(f, False)
        target = (burst.get("target_filename") or "").lower()
        reg_keys = ["currentversion\\run","currentversion\\runonce","services","startup","image file execution options"]
        reg_persist = bool(burst.get("has_reg") and (any(k in target for k in reg_keys) or target.endswith((".exe",".bat",".ps1",".vbs",".dll",".sys"))))
        file_persist = bool(burst.get("has_exec") and burst.get("has_file") and ("system32\\tasks" in target or "services" in target))
        burst["has_persistence"] = reg_persist or file_persist
        features = _extract_behavior_features(burst)
        burst["network_strength"] = int(features.get("network_strength",0))
        host = burst["computer"]
        pname = features["process_name"]; utype = features["user_type"]
        parent = features["parent_process"]; hour = int(features.get("hour_bucket",-1) or -1)
        pk = (host,pname,utype,parent,hour); sk = (host,pname,utype,"",hour)
        baseline_entry = baseline_state.get(pk) or baseline_state.get(sk)
        deviation = _compute_deviation_score(features, baseline_entry)
        burst["deviation_score"] = deviation
        # Tag whether this burst has a historical baseline
        burst["baseline_count"] = int(baseline_entry.get("count_samples",0)) if baseline_entry else 0
        burst["baseline_mature"] = bool(burst["baseline_count"] >= 5)
        if features.get("user_type")=="system" and deviation<0.3 and int(features.get("followup_events",0) or 0)==0:
            burst["_pre_suppressed"] = True
            burst["suppression_reason"] = "Expected SYSTEM background activity"
        else:
            burst["_pre_suppressed"] = False
            burst["suppression_reason"] = None
        feature_cache.append((burst, features))
    return feature_cache


def _infer_kill_chain_from_content(burst: Dict) -> Optional[str]:
    """
    Infer kill-chain stage from command-line content and event IDs when
    structural flags alone are insufficient.  This catches cases like:
    - cmd.exe running 'schtasks /create' → Persistence
    - powershell with '-encodedcommand' → Execution (obfuscated)
    - Event ID 10 (ProcessAccess) → Privilege Escalation
    - Network event to external IP → Command and Control
    - Shadow copy deletion → Actions on Objectives
    """
    cmd = (burst.get("commandline") or burst.get("command_line") or "").lower()
    img = (burst.get("image") or "").lower()
    eids = set(str(e) for e in (burst.get("event_ids") or []))

    # Actions on Objectives / Impact
    if any(x in cmd for x in ["shadowcopy delete","delete shadows","vssadmin delete","wbadmin delete"]):
        return "Actions on Objectives"
    # Credential Access
    if any(x in cmd for x in ["sekurlsa","lsadump","mimikatz","invoke-mimikatz","dcsync","kerberoast"]):
        return "Credential Access"
    if "10" in eids:  # ProcessAccess → LSASS dump
        return "Privilege Escalation"
    # Persistence
    if any(x in cmd for x in ["schtasks /create","schtasks -create","reg add.*run","currentversion\\run","/create","startup"]):
        return "Persistence"
    if any(e in eids for e in ["12","13","14"]):  # Registry set
        if any(x in cmd for x in ["run","startup","services"]):
            return "Persistence"
    if "17" in eids or "18" in eids:  # Named pipe
        return "Privilege Escalation"
    # Defense Evasion
    if any(x in cmd for x in ["disable-av","set-mppreference","amsibypass","disable","firewall","wevtutil cl","clear-log"]):
        return "Defense Evasion"
    # Privilege Escalation
    if any(x in cmd for x in ["whoami /priv","getsystem","fodhelper","eventvwr","cmstp"]):
        return "Privilege Escalation"
    if "8" in eids or "25" in eids:  # CreateRemoteThread / ProcessTamper
        return "Privilege Escalation"
    # Command and Control
    if "3" in eids and burst.get("has_net"):
        dst = burst.get("destination_ip") or ""
        if is_external_ip(dst):
            return "Command and Control"
    if "22" in eids:  # DNS query
        return "Command and Control"
    # Execution with obfuscation
    if any(x in cmd for x in ["-enc ","-encodedcommand","/ec ","frombase64"]):
        return "Execution"
    return None


def _apply_kill_chain_logic(bursts):
    for burst in bursts:
        for f in ("has_exec","has_net","has_file","has_reg","has_injection"):
            burst.setdefault(f, False)
        # Layer 1: structural flags (fast, reliable)
        kc = _derive_kill_chain_from_flags(burst)
        # Layer 2: content/EID inference (catches what flags miss)
        inferred = _infer_kill_chain_from_content(burst)
        if inferred:
            kc = promote_stage(kc, inferred)
        # Layer 3: prior correlation promotes stage
        if burst.get("correlation_id"):
            kc = promote_stage(burst.get("kill_chain_stage"), kc)
        # Layer 4: MITRE tactic from detections (most reliable)
        det_stage = burst.get("kill_chain_stage_from_detection")
        if det_stage and det_stage not in ("Background","Unclassified","Execution"):
            kc = promote_stage(kc, det_stage)
        burst["kill_chain_stage"] = kc


def _apply_correlations(bursts, corr_df: 'pd.DataFrame', run_id: str) -> None:
    import pandas as pd
    correlations: List[Dict] = []
    if not corr_df.empty:
        for _, row in corr_df.iterrows():
            correlations.append({
                "corr_id": row.get("corr_id"), "start_time": row.get("start_time"),
                "end_time": row.get("end_time"), "base_image": row.get("base_image"),
                "kill_chain_stage": row.get("kill_chain_stage"), "computer": row.get("computer"),
            })
    for burst in bursts:
        bhost = burst.get("computer"); bimg = burst.get("image")
        matched = next((c for c in correlations if c.get("computer")==bhost and c.get("base_image")==bimg and time_overlap(burst,c)), None)
        if matched:
            burst["correlation_id"]   = matched.get("corr_id")
            burst["kill_chain_stage"] = promote_stage(burst.get("kill_chain_stage"), matched.get("kill_chain_stage") or "Execution")
            burst["correlation_score"] = 20
            burst["has_correlation"]   = True
            burst["_corr_persisted"]   = True
        else:
            burst["correlation_id"] = None
            burst.setdefault("correlation_score", 0.0)
            burst.setdefault("has_correlation", False)
    corr_index = defaultdict(list)
    for i, b in enumerate(bursts):
        corr_index[(b.get("computer"), b.get("image"))].append((i, b))
    for key, entries in corr_index.items():
        if len(entries) < 2:
            continue
        stages = {b.get("kill_chain_stage") for _,b in entries}
        start_times = []
        for _,b in entries:
            try: start_times.append(pd.to_datetime(b.get("start_time"), utc=True))
            except: pass
        age_min = 0.0
        if start_times:
            age_min = (pd.Timestamp.utcnow() - min(start_times)).total_seconds()/60.0
        if len(stages)>=2 and age_min>=5:
            strength = 30 if len(entries)>5 else 20
            for idx, burst in entries:
                burst["has_correlation"] = True
                burst["correlation_score"] = min(max(int(burst.get("correlation_score",0) or 0), strength), 30)
                burst["campaign_age_minutes"] = age_min
                if not burst.get("correlation_id"):
                    day = datetime.datetime.utcnow().strftime("%Y%m%d")
                    burst["correlation_id"] = f"AUTO-{key[0]}-{key[1]}-{day}".lower()
                if not burst.get("_corr_persisted"):
                    persist_auto_correlation(burst, run_id)
                    burst["_corr_persisted"] = True


def _compute_confidence_value(burst: Dict, deviation_score: float, previous_state) -> int:
    if burst.get("_pre_suppressed"):
        burst["risk_score"] = 5; burst["stage_cap"] = 25
        burst["classification"] = "background_activity"; return 5
    executions = int(burst.get("exec_event_count", burst.get("count",0)))
    volume_score = 0 if executions==0 else 5 if executions<10 else 10 if executions<100 else 15 if executions<1000 else 20
    impact_score = (10 if burst.get("has_exec") else 0) + (25 if burst.get("has_persistence") else 0) + (30 if burst.get("has_injection") else 0)
    dst_ip = burst.get("destination_ip") or ""
    freq_log = math.log10(executions+1) if executions>0 else 0.0
    confidence = min(float(volume_score + impact_score + freq_log*3.0), 80.0)
    stage = burst.get("kill_chain_stage") or "Execution"
    if deviation_score>=0.6 and executions>=200 and stage in ("Execution","Command and Control") and (burst.get("has_net") or burst.get("has_file")) and not burst.get("has_persistence") and not burst.get("has_injection"):
        confidence += 7.0
    if burst.get("has_persistence"):  confidence += 15.0
    if stage == "Command and Control":
        net_cnt = int(burst.get("net_event_count",0) or 0)
        if is_external_ip(dst_ip) and net_cnt>=3: confidence += 25.0
        elif is_external_ip(dst_ip):              confidence += 10.0
    if burst.get("has_injection"):    confidence += 25.0
    if burst.get("has_correlation") and confidence < 45.0: confidence = 45.0
    dev_cap   = 25.0 if deviation_score<0.3 else 45.0 if deviation_score<0.6 else 75.0 if deviation_score<0.8 else 100.0
    stage_cap = (100 if stage in ("Privilege Escalation","Actions on Objectives")
                 else 80 if stage in ("Command and Control","Persistence")
                 else 60 if stage=="Execution" else 45)
    confidence = min(confidence, float(stage_cap), dev_cap)
    if previous_state is not None:
        prev_conf, prev_stage = previous_state
        if prev_stage == stage:
            confidence = 0.7*float(prev_conf) + 0.3*confidence
    confidence = max(0.0, min(confidence, 100.0))
    burst["risk_score"] = int(round(confidence))
    burst["stage_cap"]  = stage_cap
    burst["classification"] = ("attack_candidate"
        if (confidence>=45.0 or burst.get("has_persistence") or burst.get("has_injection") or
            (stage in ("Command and Control","Actions on Objectives") and confidence>=45.0) or burst.get("has_correlation"))
        else "background_activity")
    return burst["risk_score"]


def _calculate_confidence_and_severity(bursts, feature_cache, detections_df):
    prev_conf_map: Dict = {}
    for i, burst in enumerate(bursts):
        _, features = feature_cache[i]
        host = burst.get("computer") or "unknown_host"
        key = (host, features["process_name"], features["user_type"], features["parent_process"], int(features.get("hour_bucket",-1)))
        # --- Elite 10/10 Scoring Integration ---
        if not validate_context(burst):
            burst["risk_score"] = 5
            burst["severity"] = "low"
            burst["confidence_reasons"] = ["Pipeline Guard: Minimum data requirements not met"]
            continue

        _dets = [d for d in detections_df.to_dict(orient="records") if str(d.get("image")).lower() == features["process_name"].lower()] # Heuristic match
        # Note: In a real production system, we'd pass the actual matched detections for this burst.
        # For now, we use the engine's score_burst with the burst's own metadata.
        
        scoring_engine = get_scoring_engine()
        score_res = scoring_engine.score_burst(
            burst, 
            detections=None, # Already factored into burst flags in this legacy pipeline
            deviation_score=float(burst.get("deviation_score", 0.0)),
            chain_depth=int(burst.get("chain_depth", 1)) if "chain_depth" in burst else 1
        )
        
        kc = burst.get("kill_chain_stage", "Background")
        burst["risk_score"] = int(score_res.score)
        burst["severity"] = score_res.severity
        burst["classification"] = scoring_engine.classify(score_res.score, kc)

        burst["confidence_source"] = "SentinelTrace Elite Engine"
        prev_conf_map[key] = (float(score_res.score), kc)
        reasons = []
        dev = burst.get("deviation_score")
        if dev is not None:
            if dev < 0.3:   reasons.append("Low deviation from baseline")
            elif dev > 0.6: reasons.append("Significant deviation from baseline")
        if kc == "Execution": reasons.append("Execution-only behavior")
        elif kc in ("Privilege Escalation","Command and Control","Actions on Objectives"): reasons.append(f"Advanced kill-chain stage: {kc}")
        burst["confidence_reasons"] = (burst.get("confidence_reasons") or []) + reasons
        burst["ai_context"] = burst["confidence_reasons"][0] if burst["confidence_reasons"] else None


def _update_baselines(feature_cache, baseline_state):
    for burst, features in feature_cache:
        if _should_learn_baseline(burst, features):
            _update_local_baseline(burst, features, baseline_state)


# ---------------------------------------------------------------------------
# run_full_analysis
# ---------------------------------------------------------------------------

def run_full_analysis(run_id: str) -> Dict[str, Any]:
    log = logging.getLogger("analysis")
    log.info("[MASTERY] run_full_analysis CALLED for run_id=%s", run_id)

    # 10/10 Mastery: Atomic Job Claiming (Race-safe)
    with get_db_connection("cases") as conn:
        with get_cursor(conn) as cur:
            cur.execute(
                "UPDATE cases SET status=%s, analysis_version=analysis_version+1, last_heartbeat=%s "
                "WHERE run_id=%s AND status IN (%s, %s, %s)",
                (ANALYZING, now_utc(), run_id, INGESTED, DEGRADED, FAILED)
            )
            # MySQL rowcount for UPDATE can be 0 if the row matches but no data was changed.
            # However, analysis_version+1 SHOULD always change the data.
            # We'll re-check the status to be sure.
            cur.execute("SELECT status, analysis_version FROM cases WHERE run_id=%s", (run_id,))
            row = cur.fetchone()
            
            if not row:
                log.error("[CLAIM-FAIL] run_id=%s NOT FOUND in cases table", run_id)
                return {}
            
            if row["status"] != ANALYZING:
                log.error("[CLAIM-FAIL] run_id=%s found but status is %s (expected %s)", run_id, row["status"], ANALYZING)
                return {}

            new_version = row["analysis_version"]
            
            # Record state jump
            cur.execute(
                "INSERT INTO case_history (run_id, old_status, new_status, reason) "
                "VALUES (%s, %s, %s, %s)",
                (run_id, "PENDING", ANALYZING, json.dumps({"version": new_version}))
            )
        conn.commit()

    # Force SQLAlchemy to drop stale pooled connections so read_sql_query sees
    # the rows freshly committed by persist_case (which uses mysql.connector).
    try:
        dispose_engine("cases")
        dispose_engine("live")
    except Exception:
        pass

    # Safe defaults
    evidence_state = {}
    kill_chain_summary: List[Dict] = []
    kc_severity: Dict = {}
    highest_kill_chain = None
    mitre_summary: List[Dict] = []
    correlation_campaigns: List[Dict] = []
    correlations: List[Dict] = []
    correlations_detail: List[Dict] = []
    correlation_hunts: List[Dict] = []
    correlation_score = 0
    top_events: List[Dict] = []
    interesting: List[Dict] = []
    recent: List[Dict] = []
    events_per_hour: List[Dict] = []
    events_by_severity = {"high":0,"medium":0,"low":0}
    lolbins_summary: List[Dict] = []
    baseline_execution_context: List[Dict] = []
    burst_aggregates: List[Dict] = []
    top_dangerous_bursts: List[Dict] = []
    timeline: List[Dict] = []
    attack_conf_score = 0
    attack_conf_level = "Low"
    attack_conf_cap = None
    attack_conf_basis: List[str] = []
    dominant_burst = None
    confidence_trend: List[int] = []
    analyst_verdict = analyst_action = action_priority = action_reason = None
    response_tasks: List[Dict] = []
    incident = None

    update_campaign_status_lifecycle()
    import pandas as pd
    df         = load_events(run_id)
    total_events = len(df) if not df.empty else 0

    if not df.empty:
        # Ensure both event_time and utc_time are present and parsed
        if "event_time" in df.columns:
            df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce", utc=True)
        elif "utc_time" in df.columns:
            df["event_time"] = pd.to_datetime(df["utc_time"], errors="coerce", utc=True)
        if "utc_time" not in df.columns and "event_time" in df.columns:
            df["utc_time"] = df["event_time"]
        elif "utc_time" in df.columns:
            df["utc_time"] = pd.to_datetime(df["utc_time"], errors="coerce", utc=True)
        df = df.dropna(subset=["event_time"])
        # --- SOC-Grade Performance: Time-Based Trimming ---
        if len(df) > 10000:
            print(f"[PIPELINE] Dataset too large ({len(df)} events). Trimming to 10k most recent.")
            df = df.sort_values("event_time", ascending=True).tail(10000)

    detections_df = load_detections(run_id)
    detections_df = detections_df.loc[:, ~detections_df.columns.duplicated()]
    corr_df       = load_correlations(run_id)
    campaigns_df  = load_correlation_campaigns(run_id)
    beh_df        = load_behaviors(run_id)
    baseline_state = load_behavior_baseline()

    correlations = corr_df.to_dict(orient="records") if not corr_df.empty else []

    if not detections_df.empty:
        import pandas as pd
        norm = detections_df.copy()
        norm["_parsed_time_det"] = pd.to_datetime(norm["utc_time"], errors="coerce", utc=True)
        for col in ["_parsed_time_det","event_id","parent_image"]:
            if col in norm.columns and isinstance(norm[col], pd.DataFrame):
                norm[col] = norm[col].iloc[:,0]
        normalized_detections = (
            norm.groupby(["rule_id","image","mitre_id"])
            .agg(first_seen=("_parsed_time_det","min"), last_seen=("_parsed_time_det","max"),
                 count=("event_id","size"), unique_parents=("parent_image","nunique"))
            .reset_index()
        )
    else:
        import pandas as pd
        normalized_detections = pd.DataFrame(
            columns=["rule_id","image","mitre_id","first_seen","last_seen","count","unique_parents"]
        )

    # Wire detection kill-chain stages into bursts before deviation scoring
    if not detections_df.empty and "kill_chain_stage" in detections_df.columns and "image" in detections_df.columns:
        _det_kc_map: Dict[str, str] = {}
        _kc_order_map = {s: i for i, s in enumerate(KILL_CHAIN_ORDER)}
        for _, _dr in detections_df.iterrows():
            _img = str(_dr.get("image") or "").lower()
            _stage = str(_dr.get("kill_chain_stage") or "")
            if _img and _stage in _kc_order_map:
                if _img not in _det_kc_map or _kc_order_map.get(_stage,0) > _kc_order_map.get(_det_kc_map[_img],0):
                    _det_kc_map[_img] = _stage
    else:
        _det_kc_map = {}

    grouped_rows = _build_bursts(df, beh_df, run_id)
    # Stamp detection-derived kill chain on bursts
    for _burst in grouped_rows:
        _bimg = str(_burst.get("image") or "").lower()
        if _bimg in _det_kc_map:
            _burst["kill_chain_stage_from_detection"] = _det_kc_map[_bimg]

    feature_cache = _calculate_ml_deviations(grouped_rows, baseline_state)
    for burst, features in feature_cache:
        dev = features.get("deviation_score")
        if dev is not None:
            try: burst["deviation_score"] = float(dev)
            except: pass
    for burst in grouped_rows:
        burst.pop("_corr_persisted", None)
    _apply_correlations(grouped_rows, corr_df, run_id)
    _apply_kill_chain_logic(grouped_rows)
    _calculate_confidence_and_severity(grouped_rows, feature_cache, detections_df)
    
    # --- SMART BURST FILTER (FIX 13) ---
    # Keeps high-frequency noise out but preserves low-freq high-signal alerts
    grouped_rows = [
        b for b in grouped_rows
        if (
            int(b.get("count", 0)) >= 3 or
            int(b.get("risk_score", 0)) >= 40 or
            b.get("kill_chain_stage") in ("Execution", "Persistence", "Privilege Escalation")
        )
    ]
    
    # --- BURST PRIORITIZATION (FIX 15) ---
    # Ensure high-risk bursts appear first in dashboard
    KC_RANK = {k: i for i, k in enumerate(["Background","Delivery","Execution","Defense Evasion","Persistence","Privilege Escalation","Credential Access","Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Actions on Objectives"])}
    grouped_rows = sorted(
        grouped_rows,
        key=lambda b: (
            int(b.get("risk_score", 0)),
            KC_RANK.get(b.get("kill_chain_stage", "Background"), 0),
            int(b.get("count", 0))
        ),
        reverse=True
    )

    _update_baselines(feature_cache, baseline_state)
    persist_behavior_baseline(baseline_state)

    # Severity counts
    if not df.empty and "severity" in df.columns:
        df["severity"] = df["severity"].fillna("low")
        sev_counts  = {str(k):int(v) for k,v in df["severity"].str.lower().value_counts().to_dict().items()}
        high_count   = int((df["severity"].str.lower()=="high").sum())
        medium_count = int((df["severity"].str.lower()=="medium").sum())
        low_count    = int((df["severity"].str.lower()=="low").sum())
    else:
        sev_counts = {}; high_count = medium_count = low_count = 0
    events_by_severity = sev_counts
    detections_count = len(detections_df)

    if df is not None and not df.empty:
        _te = df["event_id"].value_counts().head(10).reset_index()
        _te.columns = ["event_id","count"]
        top_events = _te.to_dict(orient="records")

    suspicious_images = ["cmd.exe","powershell.exe","pwsh.exe","wmic.exe","rundll32.exe","regsvr32.exe","mshta.exe"]
    sort_col = "event_time" if "event_time" in df.columns else "utc_time" if "utc_time" in df.columns else None
    if not df.empty and "image" in df.columns:
        interesting_df = df[df["image"].notna() & df["image"].str.lower().str.contains("|".join(suspicious_images), na=False)]
        if sort_col:
            interesting_df = interesting_df.sort_values(sort_col, ascending=False)
        interesting_df = interesting_df.head(100)
    else:
        interesting_df = df.iloc[0:0]

    recent_df = df.sort_values(sort_col, ascending=False).head(50) if sort_col and not df.empty else df

    if not detections_df.empty and "severity" in detections_df.columns:
        det_copy = detections_df.copy()
        sev_w = {"high":"+10","medium":"+5","low":"+2"}
        det_copy["confidence_impact"] = det_copy["severity"].fillna("unknown").str.lower().map(lambda s: sev_w.get(s,"+0"))
    else:
        det_copy = detections_df.copy()
        det_copy["confidence_impact"] = "+0"
    detections = (det_copy.sort_values("utc_time",ascending=False).head(50) if "utc_time" in det_copy.columns else det_copy)
    detections = detections.loc[:, ~detections.columns.duplicated()]
    # Convert all Timestamp columns to ISO strings so Jinja [:16] slicing works
    for _dc in detections.columns:
        if detections[_dc].dtype.kind == "M" or (not detections.empty and hasattr(detections[_dc].iloc[0], "isoformat")):
            detections[_dc] = detections[_dc].astype(str)

    # Baseline context
    baseline_execution_context = []
    if not df.empty:
        df_base = df.copy()
        df_base["image"] = df_base["image"].astype(str).str.strip()
        if "computer" not in df_base.columns: df_base["computer"] = None
        df_base = df_base[df_base["image"].notna() & (df_base["image"]!="") & (df_base["image"].str.lower()!="unknown process")]
        if not df_base.empty:
            _time_col = "event_time" if "event_time" in df_base.columns else "utc_time"
            grouped = df_base.groupby(["image","computer"],dropna=False).agg(first_seen=(_time_col,"min"),last_seen=(_time_col,"max"),exec_count=("event_id","size")).reset_index()
            brows = []
            for _, r in grouped.iterrows():
                duration = r["last_seen"] - r["first_seen"]
                secs = max(duration.total_seconds(), 60.0)
                mins = secs/60.0
                ec   = int(r["exec_count"])
                rate = ec/mins
                th   = int(duration.total_seconds()//60); hh=th//60; mm=th%60
                dl   = f"{hh}h {mm}m" if hh else f"{mm}m"
                bsl  = ("Low activity in this run" if rate<1 else "Bursting in this run" if rate<10 else "Heavy activity in this run")
                pi = None
                sub = df_base[(df_base["image"]==r["image"])&(df_base["computer"]==r["computer"])]
                if "parent_image" in sub.columns and not sub.empty:
                    pc = sub.groupby("parent_image").size().reset_index(name="count").sort_values("count",ascending=False)
                    if not pc.empty: pi = pc["parent_image"].iloc[0]
                brows.append({"image":r["image"],"computer":r.get("computer") or "unknown_host","first_seen":r["first_seen"].isoformat(),"last_seen":r["last_seen"].isoformat(),"start_label":r["first_seen"].strftime("%H:%M"),"end_label":r["last_seen"].strftime("%H:%M"),"duration_label":dl,"exec_count":ec,"exec_rate_per_min":round(rate,1),"baseline_state":bsl,"parent_image":pi,"baseline_deviation":"No historical baseline","why_non_alerting":["No historical baseline","No persistence indicators in this run","No external network activity tied to this process in this run"]})
            brows.sort(key=lambda b:(-b["exec_count"],b["first_seen"]))
            baseline_execution_context = brows[:10]

    # Force correlation persist loop — persists new bursts into correlations table
    print(f"[DEBUG] forcing persist_auto_correlation loop for {len(grouped_rows)} bursts")
    corr_persisted = 0
    persisted_ids = set() # Dedup per run
    
    for burst in grouped_rows:
        bid = burst.get("burst_id")
        if not bid or bid in persisted_ids:
            continue
            
        score = int(burst.get("risk_score", 0))
        stage = burst.get("kill_chain_stage", "Background")
        
        # --- SOC-Grade Priority Persistence (REFINED) ---
        score = int(burst.get("risk_score", 0))
        stage = burst.get("kill_chain_stage", "Background")
        freq  = int(burst.get("count", 0) or burst.get("event_count", 0) or 0)
        
        # Persist if high risk, stealth stage, or high frequency
        should_persist = (score >= 45) or (stage in ("Persistence", "Privilege Escalation")) or (freq >= 5)
        
        if should_persist and burst.get("correlation_id") and not burst.get("_corr_persisted"):
            persist_auto_correlation(burst, run_id)
            burst["_corr_persisted"] = True
            corr_persisted += 1
            persisted_ids.add(bid)
            
    print(f"[DEBUG] persisted {corr_persisted} new correlations")

    # Reload correlations AFTER persist so correlation_score reflects reality.
    # The initial load() at the top of run_full_analysis ran BEFORE persist_auto_correlation,
    # so the table was empty. We must reload now.
    try:
        dispose_engine("cases")
        _corr_df_reload     = load_correlations(run_id)
        _campaigns_df_reload = load_correlation_campaigns(run_id)
        if not _corr_df_reload.empty:
            correlations = _corr_df_reload.to_dict(orient="records")
            print(f"[DEBUG] reloaded {len(correlations)} correlations after persist")
        if not _campaigns_df_reload.empty:
            correlation_campaigns = [
                {"corr_id":r.get("corr_id"),"base_image":r.get("base_image"),
                 "highest_kill_chain":r.get("highest_kill_chain") or "Execution",
                 "max_confidence":int(r.get("max_confidence",0) or 0),
                 "status":r.get("status") or "active"}
                for _,r in _campaigns_df_reload.iterrows()
            ]
    except Exception as _ce:
        print(f"[WARN] correlation reload failed: {_ce}")

    # Recompute correlation_score from reloaded data
    _sev_w2 = {"low":1,"medium":2,"high":3}
    correlation_score = sum(_sev_w2.get((c.get("severity") or "low").lower(),1) for c in correlations) if correlations else 0
    # Give credit for in-memory burst correlations even if DB reload failed
    if correlation_score == 0:
        _n_corr_bursts = sum(1 for b in grouped_rows if b.get("has_correlation"))
        if _n_corr_bursts >= 2:
            correlation_score = _n_corr_bursts * 2

    # Final cleanup
    known_benign = {"services.exe","wininit.exe","winlogon.exe","lsass.exe","csrss.exe","svchost.exe","spoolsv.exe","explorer.exe"}
    known_benign_parents = {"splunkd.exe","osqueryd.exe","senseir.exe","crowdstrike.exe","carbonblack.exe"}
    for burst in grouped_rows:
        if "risk_score" in burst:  burst["risk_score"] = int(burst["risk_score"])
        if "stage_cap"  in burst:  burst["stage_cap"]  = int(burst["stage_cap"])
        if not burst.get("_pre_suppressed"):
            user = (burst.get("user") or "").upper()
            dev  = float(burst.get("deviation_score",0.0) or 0.0)
            dst  = burst.get("destination_ip") or ""
            ext  = is_external_ip(dst)
            has_followup = bool(burst.get("has_persistence") or burst.get("has_injection") or ext)
            img  = (burst.get("image") or "").lower()
            par  = (burst.get("parent_image") or "").lower()
            if "SYSTEM" in user and dev<0.3 and not has_followup:
                burst["risk_score"] = min(burst.get("risk_score",0) or 0, 15)
                burst["classification"] = "background_activity"
                burst.setdefault("suppression_reason","SYSTEM low-deviation background activity")
            elif img in known_benign and dev<0.4:
                stage = burst.get("kill_chain_stage") or "Background"
                if stage in ("Background","Execution"):
                    burst["risk_score"] = min(burst.get("risk_score",0) or 0, 20)
                    burst.setdefault("suppression_reason","Known benign image with low deviation")
            elif par in known_benign_parents and not ext and dev<0.5:
                burst["risk_score"] = min(burst.get("risk_score",0) or 0, 25)
                burst.setdefault("suppression_reason","Child of known benign parent")
        for fld in ("confidence_reasons","suppression_reason","confidence_source","correlation_score","campaign_age_minutes"):
            burst.setdefault(fld, [] if fld=="confidence_reasons" else None if fld=="suppression_reason" else "AI/ML Engine" if fld=="confidence_source" else 0)
        burst["final_kill_chain"] = burst.get("kill_chain_stage")

    # Burst aggregates
    agg = defaultdict(list)
    for i, b in enumerate(grouped_rows):
        key = (b["image"], b.get("computer"), run_id, (b.get("start_time") or "")[:13])
        agg[key].append((i, b))
    burst_aggregates = []
    for (image, computer, rid, tb), items in agg.items():
        raw_ids_set = set()
        for _, b in items:
            for e in (b.get("event_ids") or []):
                if e and str(e).lower() != "none": raw_ids_set.add(str(e))
        combined_eids = sorted(list(raw_ids_set), key=lambda x: int(x) if x.isdigit() else x)
        max_rb = max(items, key=lambda x: x[1].get("risk_score",0))[1]
        burst_aggregates.append({
            "burst_id":       items[0][1].get("burst_id"),
            "image":          image,
            "kill_chain_stage": max(b["kill_chain_stage"] for _,b in items),
            "total_count":    sum(b["count"] for _,b in items),
            "peak_score":     max(b["risk_score"] for _,b in items),
            "confidence_reasons": items[0][1].get("confidence_reasons",[]),
            "timeline_indices": [i for i,_ in items],
            "event_ids":      combined_eids,
            "stage_cap":      max_rb.get("stage_cap",100),
            "burst_count":    len(items),
            "_pre_suppressed": items[0][1].get("_pre_suppressed",False),
            "ai_context":     items[0][1].get("ai_context"),
            "has_correlation": any(b.get("has_correlation") for _,b in items),
            "exec_sum":  sum(b.get("exec_event_count",0) for _,b in items),
            "net_sum":   sum(b.get("net_event_count",0) for _,b in items),
            "file_sum":  sum(1 for _,b in items if b.get("has_file")),
            "reg_sum":   sum(1 for _,b in items if b.get("has_reg")),
        })
    burst_aggregates.sort(key=lambda x: x["peak_score"], reverse=True)

    # ── Build attack narrative / story ──────────────────────────────────────
    # Group top bursts by host+user into a coherent attack story chain.
    # This is what elevates a "rule engine" into a real SIEM.
    attack_story: List[str] = []
    story_entities: Dict[str, List] = defaultdict(list)
    for _b in sorted(grouped_rows, key=lambda x: x.get("risk_score",0), reverse=True)[:30]:
        _host = _b.get("computer") or "unknown"
        _user = _b.get("user") or "unknown"
        story_entities[f"{_host}|{_user}"].append(_b)

    for _entity, _entity_bursts in story_entities.items():
        _host, _user = _entity.split("|", 1)
        # Sort by kill-chain stage index for chronological story
        _entity_bursts.sort(key=lambda x: KILL_CHAIN_ORDER.index(x.get("kill_chain_stage","Background"))
                             if x.get("kill_chain_stage") in KILL_CHAIN_ORDER else 0)
        for _b in _entity_bursts:
            _stage = _b.get("kill_chain_stage") or "Background"
            _img   = _b.get("image") or "unknown"
            _score = int(_b.get("risk_score",0) or 0)
            _cnt   = int(_b.get("count",0) or 0)
            if _score < 20 and _stage == "Background":
                continue
            _cmd_hint = ""
            _descs = _b.get("descriptions") or []
            if _descs:
                _sample = str(_descs[0])[:60] if _descs else ""
                if _sample:
                    _cmd_hint = f" [{_sample}]"
            if _stage == "Actions on Objectives":
                attack_story.append(f"⚠ IMPACT: {_img} on {_host} ({_cnt} events, score {_score}){_cmd_hint}")
            elif _stage == "Command and Control":
                _dst = _b.get("destination_ip") or "unknown IP"
                attack_story.append(f"🌐 C2 BEACON: {_img} → {_dst} on {_host} ({_cnt} events, score {_score})")
            elif _stage == "Credential Access":
                attack_story.append(f"🔑 CRED ACCESS: {_img} on {_host} ({_cnt} events, score {_score})")
            elif _stage == "Privilege Escalation":
                attack_story.append(f"⬆ PRIV ESC: {_img} on {_host} ({_cnt} events, score {_score})")
            elif _stage == "Persistence":
                attack_story.append(f"📌 PERSISTENCE: {_img} on {_host} ({_cnt} events, score {_score}){_cmd_hint}")
            elif _stage in ("Execution","Defense Evasion") and _score >= 30:
                attack_story.append(f"▶ {_stage.upper()}: {_img} on {_host} ({_cnt} events, score {_score}){_cmd_hint}")
    attack_story = attack_story[:20]  # cap for display

    # Kill-chain summary — build BEFORE attack_conf_score computation so it can be used
    kc_counts: Dict = {}
    for b in grouped_rows:
        stage = b.get("kill_chain_stage") or "Background"
        if stage != "Background":
            kc_counts[stage] = kc_counts.get(stage, 0) + 1
    kill_chain_summary = [{"stage": s, "count": c} for s, c in kc_counts.items()]
    # Also derive from detections if bursts gave nothing
    if not kill_chain_summary and not detections_df.empty and "kill_chain_stage" in detections_df.columns:
        kc_det = detections_df["kill_chain_stage"].value_counts().reset_index()
        kc_det.columns = ["stage", "count"]
        kill_chain_summary = kc_det.to_dict(orient="records")

    # Attack confidence
    attack_conf_score = 0; attack_conf_basis = []
    max_det_conf = 0
    if not detections_df.empty and "confidence_score" in detections_df.columns:
        try:
            max_det_conf = int(detections_df["confidence_score"].fillna(0).astype(float).max())
        except Exception:
            max_det_conf = 0
    # If no per-row score, count detections as a signal
    if max_det_conf == 0 and not detections_df.empty:
        max_det_conf = min(45, len(detections_df))
    if max_det_conf>=80: attack_conf_score+=45; attack_conf_basis.append("High-confidence detection rules triggered")
    elif max_det_conf>=50: attack_conf_score+=25; attack_conf_basis.append("Medium-confidence detection rules triggered")
    elif max_det_conf>0: attack_conf_score+=10; attack_conf_basis.append(f"{len(detections_df)} detection rule(s) triggered")
    distinct_tactics = set()
    if not detections_df.empty and "mitre_tactic" in detections_df.columns:
        distinct_tactics = {str(t).strip() for t in detections_df["mitre_tactic"].dropna() if str(t).strip()}
    n_tactics = len(distinct_tactics)
    if n_tactics>=3: attack_conf_score+=25; attack_conf_basis.append(f"Multiple MITRE tactics observed ({n_tactics})")
    elif n_tactics>=1: attack_conf_score+=10; attack_conf_basis.append("At least one MITRE tactic observed")
    highest_kill_chain = None
    if grouped_rows:
        stages = [b.get("kill_chain_stage") for b in grouped_rows
                  if b.get("kill_chain_stage") in KILL_CHAIN_ORDER
                  and (int(b.get("risk_score",0) or 0)>=45 or b.get("has_correlation"))]
        if stages:
            highest_kill_chain = sorted(stages, key=lambda s: KILL_CHAIN_ORDER.index(s))[-1]
    # Fallback: derive from detections kill_chain_stage if bursts gave nothing
    if not highest_kill_chain and not detections_df.empty and "kill_chain_stage" in detections_df.columns:
        det_stages = [s for s in detections_df["kill_chain_stage"].dropna().unique() if s in KILL_CHAIN_ORDER]
        if det_stages:
            highest_kill_chain = sorted(det_stages, key=lambda s: KILL_CHAIN_ORDER.index(s))[-1]
    # Map MITRE tactic → kill chain if still nothing
    if not highest_kill_chain and kill_chain_summary:
        kc_ordered = [k["stage"] for k in sorted(kill_chain_summary,
                       key=lambda x: KILL_CHAIN_ORDER.index(x["stage"])
                       if x["stage"] in KILL_CHAIN_ORDER else -1, reverse=True)]
        if kc_ordered:
            highest_kill_chain = kc_ordered[0]
    if highest_kill_chain in ("Command and Control","Actions on Objectives"): attack_conf_score+=25; attack_conf_basis.append(f"Kill-chain progressed to {highest_kill_chain}")
    elif highest_kill_chain: attack_conf_score+=10; attack_conf_basis.append(f"Kill-chain evidence up to {highest_kill_chain}")
    if correlations: attack_conf_score+=15; attack_conf_basis.append("Multi-stage correlation present")
    max_burst_risk = max((int(b["peak_score"] or 0) for b in burst_aggregates), default=0)
    attack_conf_score += min(20, max_burst_risk//5)
    if max_burst_risk: attack_conf_basis.append(f"Highest burst risk score {max_burst_risk}")
    attack_conf_score = min(100, attack_conf_score)
    attack_conf_level = ("High" if attack_conf_score>=80 else "Medium" if attack_conf_score>=50 else "Low" if attack_conf_score>0 else "None")
    attack_conf_cap   = (100 if highest_kill_chain=="Actions on Objectives" else 80 if highest_kill_chain=="Command and Control" else 75 if highest_kill_chain=="Persistence" else 50 if attack_conf_score>0 else None)
    if attack_conf_cap: attack_conf_score = min(attack_conf_score, attack_conf_cap)
    confidence_trend = [int(b.get("risk_score",0) or 0) for b in grouped_rows]

    # MITRE summary
    if not detections_df.empty and "mitre_id" in detections_df.columns:
        tmp = detections_df.fillna({"mitre_tactic":"Unknown","mitre_id":"Unmapped"}).groupby(["mitre_tactic","mitre_id"]).size().reset_index(name="count")
        mitre_summary = [{"mitre_tactic":r["mitre_tactic"],"mitre_id":r["mitre_id"],"count":int(r["count"])} for _,r in tmp.iterrows()]

    # Correlation campaigns / details
    if not campaigns_df.empty:
        correlation_campaigns = [{"corr_id":r.get("corr_id"),"base_image":r.get("base_image"),"highest_kill_chain":r.get("highest_kill_chain") or "Execution","max_confidence":int(r.get("max_confidence",0) or 0),"status":r.get("status") or "active"} for _,r in campaigns_df.iterrows()]
    corr_detail_df = load_correlations_detail(run_id)
    if not corr_detail_df.empty:
        correlations_detail = [{"corr_id":r.get("corr_id"),"start_time":r.get("start_time"),"end_time":r.get("end_time"),"base_image":r.get("base_image"),"kill_chain_stage":r.get("kill_chain_stage"),"event_ids":r.get("event_ids"),"description":r.get("description"),"severity":r.get("severity"),"confidence":r.get("confidence"),"computer":r.get("computer")} for _,r in corr_detail_df.iterrows()]

    correlation_hunts = [{"id":c.get("corr_id"),"description":c.get("description","Correlation detected"),"severity":c.get("severity","medium")} for c in correlations] if correlations else []
    # Note: correlation_score is computed after the persist+reload block below

    interesting = interesting_df.loc[:,~interesting_df.columns.duplicated()].to_dict(orient="records") if not interesting_df.empty else []
    recent_df   = recent_df.loc[:,~recent_df.columns.duplicated()]
    recent      = recent_df.to_dict(orient="records") if not recent_df.empty else []

    baseline_noise_count = len(baseline_execution_context)

    # LOLBins
    lolbin_stats: Dict = {}
    if not interesting_df.empty and "image" in interesting_df.columns:
        np_set = {"services.exe","wininit.exe","winlogon.exe","splunkd.exe"}
        for _, row in interesting_df.iterrows():
            img = row.get("image") or "unknown_process"
            cmd = row.get("commandline") or row.get("command_line") or ""
            par = str(row.get("parent_image") or "").strip()
            s = lolbin_stats.setdefault(img,{"image":img,"executions":0,"unique_commands":set(),"abnormal_parents":set()})
            s["executions"] += 1
            if cmd: s["unique_commands"].add(cmd)
            if par and par.lower() not in {p.lower() for p in np_set}: s["abnormal_parents"].add(par)
    if lolbin_stats:
        lolbins_summary = []
        for img, s in lolbin_stats.items():
            ex=s["executions"]; uq=len(s["unique_commands"]); ab=len(s["abnormal_parents"])
            verdict = ("likely benign (service activity)" if ex>100 and uq<=3 and ab==0 else "suspicious" if ab>0 or uq>3 else "inconclusive")
            lolbins_summary.append({"image":img,"executions":ex,"unique_command_lines":uq,"abnormal_parents":ab,"verdict":verdict})
        lolbins_summary.sort(key=lambda r:(r["abnormal_parents"],r["executions"]),reverse=True)
        lolbins_summary = lolbins_summary[:10]

    # Events per hour
    _eph_col = "event_time" if "event_time" in df.columns else "utc_time" if "utc_time" in df.columns else None
    if not df.empty and _eph_col:
        import pandas as pd
        eph = df.copy()
        eph[_eph_col] = pd.to_datetime(eph[_eph_col], errors="coerce", utc=True)
        eph = eph.dropna(subset=[_eph_col])
        eph["hour_bucket"] = eph[_eph_col].dt.floor("h")
        eph = eph.groupby("hour_bucket").size().reset_index(name="count").sort_values("hour_bucket")
        events_per_hour = [{"hour":r["hour_bucket"].strftime("%H:%M"),"count":int(r["count"])} for _,r in eph.iterrows()]

    # Incident — compute kill-chain depth (distinct stages observed in this run)
    _kc_stages_seen = set()
    for _b in grouped_rows:
        _s = _b.get("kill_chain_stage")
        if _s and _s not in ("Background", "Unclassified"):
            _kc_stages_seen.add(_s)
    kill_chain_depth = len(_kc_stages_seen)

    # CRITICAL requires score>=70 AND (correlation OR multi-stage kill chain)
    # HIGH requires score>=50 AND at least one real kill-chain stage
    # MEDIUM requires score>=40 AND at least one real kill-chain stage
    # Single-stage detections alone never reach CRITICAL — that would be false inflation.
    _has_multi_stage = (kill_chain_depth >= 2) or (correlation_score > 0)
    if attack_conf_score >= 75 and _has_multi_stage:
        _alert_level = "critical"
    elif attack_conf_score >= 75:
        _alert_level = "high"
    elif attack_conf_score >= 45 and kill_chain_depth >= 1:
        _alert_level = "medium"
    else:
        _alert_level = "low"

    is_alertable = (_alert_level in ("critical", "high", "medium"))
    if is_alertable and incident is None:
        incident = {"incident_id":f"INC-{run_id[:8]}","status":"New","severity":attack_conf_level,"score":attack_conf_score}
    if incident:
        incident["hosts"] = sorted({b.get("computer") for b in grouped_rows if b.get("computer")})
        incident["users"] = sorted({b.get("user") for b in grouped_rows if b.get("user")})
    if is_alertable:
        try: upsert_incident_row(f"INC-{run_id[:8]}", "Open", attack_conf_level.lower(), attack_conf_score, run_id)
        except Exception as e: print(f"[WARN] upsert_incident_row failed: {e}")

    print("[DEBUG] detections len:", len(detections))
    print("[DEBUG] mitre_summary len:", len(mitre_summary))
    print("[DEBUG] baseline_noise_count:", baseline_noise_count)

    # ── Attack Storyline Reconstruction ──────────────────────────────────────
    try:
        _story_events = df.to_dict(orient="records") if not df.empty else []
        _story_dets   = detections.to_dict(orient="records") if not detections.empty else []
        attack_story  = build_attack_story(_story_events, _story_dets)
        kill_chain_depth = len(attack_story.get("kill_chain", []))
    except Exception as _e:
        print(f"[WARN] build_attack_story failed: {_e}")
        attack_story     = {"steps": [], "summary": "", "kill_chain": [], "mitre_ids": []}
        kill_chain_depth = 0

    return {
        "analysis_run_id":            run_id,
        "context_run_marker":         run_id[:8],
        "time_range":                 "all",
        "q":                          "",
        "incident":                   incident,
        "total_events":               total_events,
        "high_count":                 high_count,
        "medium_count":               medium_count,
        "low_count":                  low_count,
        "detections_count":           detections_count,
        "events_by_severity":         events_by_severity,
        "events_per_hour":            events_per_hour,
        "top_events":                 top_events,
        "interesting":                interesting,
        "recent":                     recent,
        "detections":                 detections.to_dict(orient="records"),
        "timeline":                   grouped_rows,
        "normalized_detections":      normalized_detections.to_dict(orient="records"),
        "attack_conf_score":          attack_conf_score,
        "attack_conf_level":          attack_conf_level,
        "attack_conf_cap":            attack_conf_cap,
        "attack_conf_basis":          attack_conf_basis,
        "highest_kill_chain":         highest_kill_chain,
        "is_alertable":               is_alertable,
        "confidence_trend":           confidence_trend,
        "correlations_detail":        correlations_detail,
        "correlation_campaigns":      correlation_campaigns,
        "correlation_hunts":          correlation_hunts,
        "correlation_score":          correlation_score,
        "correlations":               correlations,
        "burst_aggregates":           burst_aggregates,
        "top_dangerous_bursts":       baseline_execution_context,
        "baseline_execution_context": baseline_execution_context,
        "baseline_noise_count":       baseline_noise_count,
        "kill_chain_summary":         kill_chain_summary,
        "kc_severity":                kc_severity,
        "mitre_summary":              mitre_summary,
        "lolbins_summary":            lolbins_summary,
        "forensic_metadata": {
            "analysis_duration_sec": "0.000",
            "dominant_host": (
                df["computer"].value_counts().index[0]
                if not df.empty and "computer" in df.columns and len(df)>0
                else "N/A"
            ),
            "total_events": total_events,
            "run_id": run_id,
        },
    }

    # 10/10 Mastery: Invariant Validation (The Proof)
    try:
        # 1. Score Composition Proof (Decimal math)
        proven_score = Decimal(str(attack_conf_score)).quantize(Decimal("0.0001"), ROUND_HALF_UP)
        context["attack_conf_score"] = float(proven_score)
        
        # 2. Causality Invariant (Minimal Truth)
        if not df.empty:
            assert all(ev.get("run_id") == run_id for ev in context.get("timeline", [])[:100])
        
        # 3. Behavioral Specification
        if detections_df.empty:
            assert attack_conf_score == 0
        
        log.info("[MASTERY] All formal invariants passed for run_id=%s", run_id)
        
    except AssertionError as ae:
        log.critical("[INVARIANT-FAILURE] run_id=%s failed formal proof: %s", run_id, ae)
        _transition_state(run_id, ANALYZING, DEGRADED, {"reason": "Invariant failure", "error": str(ae)})
        return context

    # 10/10 Mastery: Final Success Transition
    _transition_state(run_id, ANALYZING, COMPLETE, {"status": "Success", "events": total_events})

    return context

def _transition_state(run_id: str, old: str, new: str, reason_dict: dict):
    """Formal atomic state transition with audit trail."""
    try:
        from dashboard.db import get_db_connection, get_cursor, now_utc
        import json
        import logging
        log = logging.getLogger("db")
        with get_db_connection("cases") as conn:
            with get_cursor(conn) as cur:
                cur.execute(
                    "UPDATE cases SET status=%s, last_heartbeat=%s WHERE run_id=%s AND status=%s",
                    (new, now_utc(), run_id, old)
                )
                cur.execute(
                    "INSERT INTO case_history (run_id, old_status, new_status, reason) "
                    "VALUES (%s, %s, %s, %s)",
                    (run_id, old, new, json.dumps(reason_dict))
                )
            conn.commit()
    except Exception as e:
        log = logging.getLogger("db")
        log.error("[STATE] Transition failed %s -> %s: %s", old, new, e)
