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
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

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
    find_detections,
    enrich_parent_chains,
)
from dashboard.db import (
    DB_TYPE,
    DB_STRICT,
    checked_insert,
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
    "Background",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Command and Control",
    "Actions on Objectives",
]
KILLCHAIN_ORDER_FOR_RANK = {k: i for i, k in enumerate(KILL_CHAIN_ORDER)}

_HIGH_EVENT_IDS = {1, 8, 9, 12, 13, 14, 19, 25}
_MED_EVENT_IDS  = {3, 7, 10, 11, 22, 23}

# ---------------------------------------------------------------------------
# Snapshot cache stubs (kept for interface compat with app.py)
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
            "raw_event_id":      eid,
        })
    return pd.DataFrame(behaviors)


# ---------------------------------------------------------------------------
# ingest_upload
# ---------------------------------------------------------------------------

def ingest_upload(
    xml_path: Path,
    rules_path: Optional[Path] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Parse XML into (events_df, detections_df, behaviors_df). No DB writes."""
    if not Path(xml_path).exists():
        raise FileNotFoundError(f"Sysmon XML not found: {xml_path}")

    run_id = uuid.uuid4().hex

    rows = load_all_sources_from_xml(xml_path)
    if not rows:
        raise RuntimeError("Upload aborted: XML contained no events.")

    events_df = pd.DataFrame(rows)
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
    return events_df, detections_df, behaviors_df


# ---------------------------------------------------------------------------
# persist_case  — write upload to sentinel_cases (MySQL)
# ---------------------------------------------------------------------------

def persist_case(
    events_df: pd.DataFrame,
    detections_df: pd.DataFrame,
    behaviors_df: pd.DataFrame,
) -> None:
    if events_df.empty:
        raise RuntimeError("No events to persist")

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


# ---------------------------------------------------------------------------
# process_event  — called per live event by sysmon_collector
# ---------------------------------------------------------------------------

def process_event(evt: dict, conn: Any = None) -> None:
    if not evt.get("severity"):
        try:
            evt["severity"] = _assign_severity(int(evt.get("event_id") or 0))
        except Exception:
            evt["severity"] = "low"

    alerts = _match_rules_on_event(evt)
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
    ts    = now_utc()
    stmt  = sql_upsert(
        "incidents",
        ["incident_id","status","severity","confidence","escalation","run_id","created_at","updated_at"],
        ["incident_id"],
        ["status","confidence","escalation","updated_at"],
    )
    vals  = (incident_id, status, severity, confidence, escalation, run_id, ts, ts)

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
        df = pd.read_sql_query("SELECT * FROM behavior_baseline", engine)
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

def load_events(run_id: str) -> pd.DataFrame:
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        df = pd.read_sql_query(
            "SELECT * FROM events WHERE run_id = %s ORDER BY event_time DESC",
            engine, params=(run_id,),
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


def load_detections(run_id: str) -> pd.DataFrame:
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
            "SELECT * FROM detections WHERE run_id = %s ORDER BY utc_time DESC",
            engine, params=(run_id,),
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


def load_correlations(run_id: str) -> pd.DataFrame:
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return pd.read_sql_query(
            "SELECT * FROM correlations WHERE run_id = %s", engine, params=(run_id,)
        )
    except Exception:
        return pd.DataFrame()


def load_correlations_detail(run_id: str) -> pd.DataFrame:
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return pd.read_sql_query(
            "SELECT * FROM correlations WHERE run_id = %s "
            "ORDER BY start_time ASC LIMIT 10",
            engine, params=(run_id,),
        )
    except Exception:
        return pd.DataFrame()


def load_correlation_campaigns(run_id: str) -> pd.DataFrame:
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        return pd.read_sql_query(
            "SELECT * FROM correlation_campaigns WHERE run_id = %s "
            "ORDER BY last_seen DESC",
            engine, params=(run_id,),
        )
    except Exception:
        return pd.DataFrame()


def load_behaviors(run_id: str) -> pd.DataFrame:
    engine = get_engine("cases" if run_id != "live" else "live")
    try:
        df = pd.read_sql_query(
            "SELECT * FROM behaviors WHERE run_id = %s ORDER BY event_time DESC",
            engine, params=(run_id,),
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

def _build_bursts(df: pd.DataFrame, beh_df: pd.DataFrame, run_id: str) -> List[Dict[str,Any]]:
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
                current = _new_burst(img, pid, host, user, btime, eid, btype, run_id)
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


def _new_burst(img, pid, host, user, btime, eid, btype, run_id) -> Dict:
    return {
        "burst_id": f"{run_id}-{uuid.uuid4().hex[:8]}",
        "start_time": btime.isoformat(), "end_time": btime.isoformat(),
        "count": 1, "exec_event_count": 1 if btype=="execution" else 0,
        "image": img, "kill_chain_stage": "Execution",
        "event_ids": [eid], "mitre_ids": [], "mitre_tactics": [],
        "descriptions": [], "has_correlation": False, "severity": None,
        "type": "telemetry",
        "source_ip": None, "destination_ip": None, "destination_port": None,
        "target_filename": None,
        "has_exec": btype=="execution", "has_net": btype=="network",
        "has_file": btype=="file", "has_reg": btype=="registry",
        "net_event_count": 1 if btype=="network" else 0,
        "process_id": pid, "parent_process_id": None, "parent_image": None,
        "computer": host, "user": user,
        "hosts": [host] if host else [], "users": [user] if user else [],
    }


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
    for fld in ("source_ip","destination_ip","destination_port","target_filename"):
        if not current.get(fld) and b.get(fld):
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
        "target_filename": row.get("target_filename"),
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
    for fld in ("source_ip","destination_ip","destination_port","target_filename"):
        if not current.get(fld) and row.get(fld):
            current[fld] = row.get(fld)


# ---------------------------------------------------------------------------
# Feature extraction, deviation, kill-chain, correlations, confidence
# (Identical logic to the original — just no SQLite)
# ---------------------------------------------------------------------------

def _extract_behavior_features(burst: Dict) -> Dict:
    pname  = burst.get("image") or "unknown_process"
    parent = burst.get("parent_image") or burst.get("parent_process_id") or "unknown_parent"
    user   = (burst.get("user") or "").upper()
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
    if float(burst.get("risk_score",0) or 0) >= 40.0:
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
        if features.get("user_type")=="system" and deviation<0.3 and int(features.get("followup_events",0) or 0)==0:
            burst["_pre_suppressed"] = True
            burst["suppression_reason"] = "Expected SYSTEM background activity"
        else:
            burst["_pre_suppressed"] = False
            burst["suppression_reason"] = None
        feature_cache.append((burst, features))
    return feature_cache


def _apply_kill_chain_logic(bursts):
    for burst in bursts:
        for f in ("has_exec","has_net","has_file","has_reg","has_injection"):
            burst.setdefault(f, False)
        kc = _derive_kill_chain_from_flags(burst)
        if burst.get("correlation_id"):
            kc = promote_stage(burst.get("kill_chain_stage"), kc)
        burst["kill_chain_stage"] = kc


def _apply_correlations(bursts, corr_df: pd.DataFrame, run_id: str) -> None:
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
    if burst.get("has_correlation") and confidence < 40.0: confidence = 40.0
    dev_cap   = 25.0 if deviation_score<0.3 else 40.0 if deviation_score<0.6 else 70.0 if deviation_score<0.8 else 100.0
    stage_cap = (100 if stage in ("Privilege Escalation","Actions on Objectives")
                 else 80 if stage in ("Command and Control","Persistence")
                 else 60 if stage=="Execution" else 40)
    confidence = min(confidence, float(stage_cap), dev_cap)
    if previous_state is not None:
        prev_conf, prev_stage = previous_state
        if prev_stage == stage:
            confidence = 0.7*float(prev_conf) + 0.3*confidence
    confidence = max(0.0, min(confidence, 100.0))
    burst["risk_score"] = int(round(confidence))
    burst["stage_cap"]  = stage_cap
    burst["classification"] = ("attack_candidate"
        if (confidence>=40.0 or burst.get("has_persistence") or burst.get("has_injection") or
            (stage in ("Command and Control","Actions on Objectives") and confidence>=40.0) or burst.get("has_correlation"))
        else "background_activity")
    return burst["risk_score"]


def _calculate_confidence_and_severity(bursts, feature_cache):
    prev_conf_map: Dict = {}
    for i, burst in enumerate(bursts):
        _, features = feature_cache[i]
        host = burst.get("computer") or "unknown_host"
        key = (host, features["process_name"], features["user_type"], features["parent_process"], int(features.get("hour_bucket",-1)))
        score = _compute_confidence_value(burst, float(burst.get("deviation_score",0.0) or 0.0), prev_conf_map.get(key))
        kc = burst.get("kill_chain_stage","Background")
        r  = burst.get("risk_score",0)
        if kc in ("Persistence","Command and Control","Actions on Objectives","Privilege Escalation") or len(burst.get("hosts",[]))>1:
            burst["severity"] = "high"
        elif r>=60:
            burst["severity"] = "medium"
        else:
            burst["severity"] = "low"
        burst["confidence_source"] = "AI/ML Engine"
        prev_conf_map[key] = (float(score), kc)
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
    print("run_full_analysis CALLED with run_id =", run_id)

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

    detections_df = load_detections(run_id)
    detections_df = detections_df.loc[:, ~detections_df.columns.duplicated()]
    corr_df       = load_correlations(run_id)
    campaigns_df  = load_correlation_campaigns(run_id)
    beh_df        = load_behaviors(run_id)
    baseline_state = load_behavior_baseline()

    correlations = corr_df.to_dict(orient="records") if not corr_df.empty else []

    if not detections_df.empty:
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
        normalized_detections = pd.DataFrame(
            columns=["rule_id","image","mitre_id","first_seen","last_seen","count","unique_parents"]
        )

    grouped_rows = _build_bursts(df, beh_df, run_id)
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
    _calculate_confidence_and_severity(grouped_rows, feature_cache)
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

    # Force correlation persist loop
    print(f"[DEBUG] forcing persist_auto_correlation loop for {len(grouped_rows)} bursts")
    for burst in grouped_rows:
        if burst.get("correlation_id"):
            persist_auto_correlation(burst, run_id)

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
        max_det_conf = min(40, len(detections_df))
    if max_det_conf>=80: attack_conf_score+=40; attack_conf_basis.append("High-confidence detection rules triggered")
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
                  and (int(b.get("risk_score",0) or 0)>=40 or b.get("has_correlation"))]
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
    attack_conf_cap   = (100 if highest_kill_chain=="Actions on Objectives" else 80 if highest_kill_chain=="Command and Control" else 70 if highest_kill_chain=="Persistence" else 50 if attack_conf_score>0 else None)
    if attack_conf_cap: attack_conf_score = min(attack_conf_score, attack_conf_cap)
    confidence_trend = [int(b.get("risk_score",0) or 0) for b in grouped_rows]

    # Kill-chain summary — count bursts per stage
    kc_counts: Dict = {}
    for b in grouped_rows:
        stage = b.get("kill_chain_stage") or "Background"
        if stage != "Background":
            kc_counts[stage] = kc_counts.get(stage, 0) + 1
    kill_chain_summary = [{"stage": s, "count": c} for s, c in kc_counts.items()]

    # Also derive kill_chain_summary from detections if bursts gave nothing
    if not kill_chain_summary and not detections_df.empty and "kill_chain_stage" in detections_df.columns:
        kc_det = detections_df["kill_chain_stage"].value_counts().reset_index()
        kc_det.columns = ["stage", "count"]
        kill_chain_summary = kc_det.to_dict(orient="records")

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
    sev_w2 = {"low":1,"medium":2,"high":3}
    correlation_score = sum(sev_w2.get((c.get("severity") or "low").lower(),1) for c in correlations) if correlations else 0

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
            par = (row.get("parent_image") or "").strip()
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
        eph = df.copy()
        eph[_eph_col] = pd.to_datetime(eph[_eph_col], errors="coerce", utc=True)
        eph = eph.dropna(subset=[_eph_col])
        eph["hour_bucket"] = eph[_eph_col].dt.floor("h")
        eph = eph.groupby("hour_bucket").size().reset_index(name="count").sort_values("hour_bucket")
        events_per_hour = [{"hour":r["hour_bucket"].strftime("%H:%M"),"count":int(r["count"])} for _,r in eph.iterrows()]

    # Incident
    is_alertable = (attack_conf_score>=40 and (correlation_score>0 or highest_kill_chain not in (None,"Background")))
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
        "analyst_verdict":            analyst_verdict,
        "analyst_action":             analyst_action,
        "action_priority":            action_priority,
        "action_reason":              action_reason,
        "response_tasks":             response_tasks,
        "dominant_burst":             dominant_burst,
        "evidence_state":             evidence_state,
        "source_file_hash":           run_id,
        "next_expected_stage":        highest_kill_chain,
        "missing_evidence":           [],
        "effective_urgency":          attack_conf_level,
    }
