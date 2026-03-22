"""
event_parser.py — SentinelTrace v2.2
=====================================
Every parsed event is now fully enriched with computed signal fields
before leaving the parser. Downstream engines receive consistent,
pre-computed signals rather than having to recompute them ad-hoc.

New fields added to every event:
  cmd_entropy         float   Shannon entropy of command line
  is_high_entropy     bool    entropy > 4.5
  has_encoded_flag    bool    -enc/-encodedcommand/frombase64string
  has_download_url    bool    http:// or https:// in cmd
  b64_detected        bool    base64 blob in cmd
  b64_preview         str     decoded preview (first 80 chars)
  cmd_length          int     len(command_line)
  is_lolbin           bool    image in LOLBin set
  lolbin_weight       float   0.5-1.0 risk weight for this LOLBin
  is_external_ip      bool    dst_ip is non-RFC1918
  is_suspicious_chain bool    parent not in known-benign set
  is_system_process   bool    image is a known system process
  process_depth       int     hop count from a benign root (0=benign, 3=unknown)
"""
from __future__ import annotations

import base64
import hashlib
import logging
import math
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

log = logging.getLogger("event_parser")

# ---------------------------------------------------------------------------
# MITRE mapping
# ---------------------------------------------------------------------------
EID_MITRE_MAP: Dict[int, Dict[str, str]] = {
    1:  {"mitre_id": "T1059",     "tactic": "Execution",            "stage": "Execution",             "desc": "Process Create"},
    2:  {"mitre_id": "T1070.006", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "File Creation Time Changed"},
    3:  {"mitre_id": "T1071",     "tactic": "Command and Control",  "stage": "Command and Control",   "desc": "Network Connection"},
    4:  {"mitre_id": "T1562.001", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Sysmon Service State Changed"},
    5:  {"mitre_id": "T1057",     "tactic": "Discovery",            "stage": "Execution",             "desc": "Process Terminated"},
    6:  {"mitre_id": "T1014",     "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Driver Loaded"},
    7:  {"mitre_id": "T1574.002", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Image Loaded"},
    8:  {"mitre_id": "T1055",     "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "CreateRemoteThread"},
    9:  {"mitre_id": "T1055",     "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "RawAccessRead"},
    10: {"mitre_id": "T1003",     "tactic": "Credential Access",    "stage": "Privilege Escalation",  "desc": "ProcessAccess (LSASS)"},
    11: {"mitre_id": "T1105",     "tactic": "Command and Control",  "stage": "Command and Control",   "desc": "FileCreate"},
    12: {"mitre_id": "T1112",     "tactic": "Defense Evasion",      "stage": "Persistence",           "desc": "Registry Create/Delete"},
    13: {"mitre_id": "T1112",     "tactic": "Defense Evasion",      "stage": "Persistence",           "desc": "Registry Set Value"},
    14: {"mitre_id": "T1112",     "tactic": "Defense Evasion",      "stage": "Persistence",           "desc": "Registry Rename"},
    15: {"mitre_id": "T1096",     "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "FileCreateStreamHash (ADS)"},
    16: {"mitre_id": "T1562.001", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "Sysmon Config Change"},
    17: {"mitre_id": "T1559",     "tactic": "Execution",            "stage": "Execution",             "desc": "PipeEvent Create"},
    18: {"mitre_id": "T1559",     "tactic": "Execution",            "stage": "Execution",             "desc": "PipeEvent Connect"},
    19: {"mitre_id": "T1546.003", "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "WmiEvent Filter"},
    20: {"mitre_id": "T1546.003", "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "WmiEvent Consumer"},
    21: {"mitre_id": "T1546.003", "tactic": "Privilege Escalation", "stage": "Privilege Escalation",  "desc": "WmiEvent Binding"},
    22: {"mitre_id": "T1071.004", "tactic": "Command and Control",  "stage": "Command and Control",   "desc": "DNSEvent"},
    23: {"mitre_id": "T1107",     "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "FileDelete"},
    24: {"mitre_id": "T1115",     "tactic": "Collection",           "stage": "Actions on Objectives", "desc": "ClipboardChange"},
    25: {"mitre_id": "T1055.012", "tactic": "Defense Evasion",      "stage": "Privilege Escalation",  "desc": "ProcessTampering"},
    26: {"mitre_id": "T1485",     "tactic": "Impact",               "stage": "Actions on Objectives", "desc": "FileDeleteDetected"},
    27: {"mitre_id": "T1036.005", "tactic": "Defense Evasion",      "stage": "Defense Evasion",       "desc": "FileBlockExecutable"},
}

BENIGN_PARENTS = frozenset({
    "services.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "csrss.exe",
    "svchost.exe", "spoolsv.exe", "explorer.exe", "taskhost.exe",
    "taskhostw.exe", "smss.exe",
})

SYSTEM_PROCESSES = frozenset({
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "spoolsv.exe",
    "explorer.exe", "taskhost.exe", "taskhostw.exe",
})

# Risk weight per LOLBin: higher = more suspicious in unusual context
LOLBIN_WEIGHTS: Dict[str, float] = {
    "mshta.exe":       1.0,
    "regsvr32.exe":    1.0,
    "cmstp.exe":       1.0,
    "psexec.exe":      1.0,
    "psexec64.exe":    1.0,
    "wmic.exe":        0.9,
    "certutil.exe":    0.9,
    "bitsadmin.exe":   0.9,
    "installutil.exe": 0.9,
    "msbuild.exe":     0.9,
    "hh.exe":          0.9,
    "rundll32.exe":    0.8,
    "wscript.exe":     0.8,
    "cscript.exe":     0.8,
    "at.exe":          0.8,
    "powershell.exe":  0.7,
    "pwsh.exe":        0.7,
    "schtasks.exe":    0.6,
    "cmd.exe":         0.5,
}
LOLBIN_SET = frozenset(LOLBIN_WEIGHTS.keys())

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_B64_RE = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
)
_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "127.", "::1", "fe80:",
)


def _is_external_ip(ip: str) -> bool:
    return bool(ip) and not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def score_command_entropy(cmd: Optional[str]) -> Dict[str, Any]:
    if not cmd:
        return {
            "entropy": 0.0, "is_high_entropy": False,
            "b64_detected": False, "b64_preview": None,
            "has_encoded_flag": False, "has_download_url": False,
        }
    lower = cmd.lower()
    entropy = _shannon_entropy(cmd)
    b64_matches = _B64_RE.findall(cmd)
    b64_detected = bool(b64_matches)
    b64_preview  = None
    for m in b64_matches:
        for enc in ("utf-16-le", "utf-8"):
            try:
                dec = base64.b64decode(m + "==").decode(enc, "replace").strip()
                if len(dec) > 4:
                    b64_preview = dec[:80]
                    break
            except Exception:
                pass
        if b64_preview:
            break
    # Broadened: includes -ec shorthand, frombase64string, [convert]::frombase64
    has_encoded_flag = any(x in lower for x in [
        "-enc ", "-encodedcommand", " -e ", "-ec ",
        "frombase64string", "[convert]::frombase64", "::frombase64",
    ])
    return {
        "entropy":          round(entropy, 3),
        "is_high_entropy":  entropy > 4.5,
        "b64_detected":     b64_detected,
        "b64_preview":      b64_preview,
        "has_encoded_flag": has_encoded_flag,
        "has_download_url": "http://" in lower or "https://" in lower,
    }


# ---------------------------------------------------------------------------
# Core enrichment — runs on every event
# ---------------------------------------------------------------------------

def enrich_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add computed signal fields to a parsed event dict in-place.
    Called at parse time so all downstream code sees consistent signals.
    """
    cmd        = str(evt.get("command_line") or "")
    image      = (evt.get("image") or "").lower()
    image_base = image.split("\\")[-1] if "\\" in image else image
    parent     = (evt.get("parent_image") or "").lower()
    parent_base = parent.split("\\")[-1] if "\\" in parent else parent
    dst_ip     = evt.get("dst_ip") or evt.get("destination_ip") or ""

    ea = score_command_entropy(cmd or None)

    # Entropy signals — dual names (new canonical + old compat)
    evt["cmd_entropy"]          = ea["entropy"]
    evt["is_high_entropy"]      = ea["is_high_entropy"]
    evt["cmd_high_entropy"]     = ea["is_high_entropy"]
    evt["has_encoded_flag"]     = ea["has_encoded_flag"]
    evt["cmd_has_encoded_flag"] = ea["has_encoded_flag"]
    evt["has_download_url"]     = ea["has_download_url"]
    evt["cmd_has_download_url"] = ea["has_download_url"]
    evt["b64_detected"]         = ea["b64_detected"]
    evt["cmd_b64_detected"]     = ea["b64_detected"]
    evt["b64_preview"]          = ea["b64_preview"]
    evt["cmd_b64_preview"]      = ea["b64_preview"]
    evt["cmd_length"]           = len(cmd)

    # LOLBin signals
    evt["is_lolbin"]     = image_base in LOLBIN_SET
    evt["lolbin_weight"] = LOLBIN_WEIGHTS.get(image_base, 0.0)

    # Network signals
    evt["is_external_ip"] = _is_external_ip(dst_ip)

    # Process-chain signals
    evt["is_suspicious_chain"] = bool(parent_base) and parent_base not in BENIGN_PARENTS
    evt["is_system_process"]   = image_base in SYSTEM_PROCESSES

    return evt


# ---------------------------------------------------------------------------
# XML parsing helpers
# ---------------------------------------------------------------------------

def _get_text(elem: Optional[ET.Element]) -> Optional[str]:
    if elem is None:
        return None
    t = elem.text
    return t.strip() if t else None


def _find(root: ET.Element, tag: str) -> Optional[ET.Element]:
    return root.find(tag) or root.find(f"{_NS}{tag}")


def _find_all(root: ET.Element, tag: str) -> List[ET.Element]:
    return list({id(e): e for e in root.findall(tag) + root.findall(f"{_NS}{tag}")}.values())


def _compute_event_uid(computer, time_created, event_id, image, pid, ppid, command_line) -> str:
    parts = [
        computer or "", time_created or "", str(event_id or ""),
        image or "", pid or "", ppid or "", (command_line or "")[:256],
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8", "ignore")).hexdigest()


def parse_event(ev: ET.Element) -> Dict[str, Any]:
    system = _find(ev, "System")
    event_id = time_created = computer = None
    if system is not None:
        eid_elem = _find(system, "EventID")
        try:
            event_id = int(_get_text(eid_elem) or "0") or None
        except Exception:
            pass
        tc = _find(system, "TimeCreated")
        if tc is not None:
            time_created = tc.attrib.get("SystemTime") or tc.attrib.get("systemTime")
        computer = _get_text(_find(system, "Computer"))

    event_data = _find(ev, "EventData")
    data_map: Dict[str, Optional[str]] = {}
    if event_data is not None:
        for d in _find_all(event_data, "Data"):
            name = d.attrib.get("Name")
            if name:
                data_map[name.lower()] = _get_text(d)

    raw_image    = data_map.get("image") or data_map.get("processimage")
    raw_parent   = data_map.get("parentimage")
    image        = Path(raw_image).name.lower()  if raw_image  else None
    parent_image = Path(raw_parent).name.lower() if raw_parent else None
    command_line = data_map.get("commandline") or data_map.get("cmdline")
    user         = data_map.get("user") or data_map.get("username")
    pid          = data_map.get("processid") or data_map.get("pid")
    ppid         = data_map.get("parentprocessid") or data_map.get("ppid")
    src_ip       = data_map.get("sourceip") or data_map.get("src_ip")
    dst_ip       = data_map.get("destinationip") or data_map.get("dst_ip")
    dst_port     = data_map.get("destinationport") or data_map.get("dst_port")
    file_path    = data_map.get("targetfilename") or data_map.get("filepath")
    reg_key      = data_map.get("targetobject") or data_map.get("details")
    dns_query    = data_map.get("queryname")
    hashes       = data_map.get("hashes")

    eid_info = EID_MITRE_MAP.get(event_id or 0, {})
    severity = (
        "high"   if event_id in {1, 8, 9, 12, 13, 14, 19, 25}
        else "medium" if event_id in {3, 7, 10, 11, 22, 23}
        else "low"
    )

    evt: Dict[str, Any] = {
        "event_uid":         _compute_event_uid(computer, time_created, event_id, image, pid, ppid, command_line),
        "event_time":        time_created,
        "utc_time":          time_created,
        "event_id":          event_id,
        "image":             image,
        "parent_image":      parent_image,
        "command_line":      command_line,
        "user":              user,
        "pid":               pid,
        "ppid":              ppid,
        "src_ip":            src_ip,
        "dst_ip":            dst_ip,
        "dst_port":          dst_port,
        "file_path":         file_path,
        "severity":          severity,
        "computer":          computer,
        "reg_key":           reg_key,
        "dns_query":         dns_query,
        "hashes":            hashes,
        "mitre_id":          eid_info.get("mitre_id"),
        "mitre_tactic":      eid_info.get("tactic"),
        "description":       eid_info.get("desc", ""),
        "kill_chain_stage":  eid_info.get("stage"),
        "destination_ip":    dst_ip,
        "source_ip":         src_ip,
        "source_port":       None,
        "target_filename":   file_path,
        "process_id":        pid,
        "parent_process_id": ppid,
        "tags":              None,
        "parser_version":    "2.2.0",
    }

    # Enrich every event at parse time
    enrich_event(evt)
    return evt


# ---------------------------------------------------------------------------
# Batch loading
# ---------------------------------------------------------------------------

def load_all_sources_from_xml(xml_path) -> List[Dict[str, Any]]:
    xml_path = Path(xml_path)
    if not xml_path.exists():
        raise FileNotFoundError(f"Sysmon XML not found: {xml_path}")
    tree   = ET.parse(xml_path)
    root   = tree.getroot()
    events = list({
        id(e): e
        for e in root.findall(f".//{_NS}Event") + root.findall(".//Event")
    }.values())
    if not events:
        raise RuntimeError("No <Event> elements found in XML.")
    log.info("Parsed %d raw XML events from %s", len(events), xml_path.name)
    return [parse_event(ev) for ev in events]


def parse_xml_to_dataframe(xml_path) -> pd.DataFrame:
    return pd.DataFrame(load_all_sources_from_xml(xml_path))


# ---------------------------------------------------------------------------
# Parent-chain enrichment
# ---------------------------------------------------------------------------

def enrich_parent_chains(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or "ppid" not in df.columns:
        return df
    df = df.copy()
    pid_to_image: Dict[tuple, str] = {}
    for _, row in df.iterrows():
        comp = row.get("computer") or "unknown"
        p    = str(row.get("pid") or "")
        img  = row.get("image") or ""
        if p and img:
            pid_to_image[(comp, p)] = img

    def _gp(row: Any) -> Optional[str]:
        comp_v = row.get("computer")
        comp = str(comp_v) if comp_v and not isinstance(comp_v, float) else "unknown"
        ppid_v = row.get("ppid")
        ppid = str(ppid_v) if ppid_v and not isinstance(ppid_v, float) else ""
        if ppid:
            p_img = pid_to_image.get((comp, ppid))
            if p_img:
                mask = (df["computer"] == comp) & (df["image"] == p_img)
                vals = df.loc[mask, "ppid"].values
                if len(vals) > 0 and vals[0]:
                    return pid_to_image.get((comp, str(vals[0])))
        return None

    def _depth(row: Any) -> int:
        # Guard against float/None values from pandas NA
        def _s(v):
            if v is None or (isinstance(v, float)):
                return ""
            return str(v).lower()
        img = _s(row.get("image"))
        par = _s(row.get("parent_image"))
        gp  = _s(row.get("grandparent_image"))
        img_b = img.split("\\")[-1] if "\\" in img else img
        par_b = par.split("\\")[-1] if "\\" in par else par
        gp_b  = gp.split("\\")[-1]  if "\\" in gp  else gp
        if img_b in BENIGN_PARENTS:
            return 0
        if par_b in BENIGN_PARENTS:
            return 1
        if gp_b in BENIGN_PARENTS:
            return 2
        return 3

    df["grandparent_image"] = df.apply(_gp, axis=1)
    df["process_chain"] = df.apply(
        lambda r: " → ".join(
            str(x) for x in [r.get("grandparent_image"), r.get("parent_image"), r.get("image")]
            if x and str(x) not in ("", "None", "nan")
        ),
        axis=1,
    )
    df["process_depth"] = df.apply(_depth, axis=1)
    return df


# ---------------------------------------------------------------------------
# Rule matching (kept for backward compat)
# ---------------------------------------------------------------------------

def _match_rule(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    raw = event.get("event_id")
    try:
        eid = int(float(raw)) if raw is not None and str(raw) not in ("", "None", "nan") else None
    except (ValueError, TypeError):
        eid = None
    rule_eids = rule.get("event_id", [])
    if rule_eids and eid not in rule_eids:
        return False

    def _sl(v: Any) -> str:
        return str(v).lower() if v and str(v) not in ("", "None", "nan") else ""

    image  = _sl(event.get("image"))
    cmd    = _sl(event.get("command_line"))
    parent = _sl(event.get("parent_image"))
    fpath  = _sl(event.get("file_path") or event.get("target_filename") or event.get("reg_key"))

    if ic := rule.get("image_contains"):
        if ic.lower() not in image:
            return False
    if ia := rule.get("image_any"):
        if image not in [x.lower() for x in ia]:
            return False
    if ca := rule.get("cmd_any"):
        if not any(s.lower() in cmd for s in ca):
            return False
    if pa := rule.get("parent_any"):
        if parent not in [x.lower() for x in pa]:
            return False
    if pp := rule.get("path_prefix_any"):
        if not any(fpath.startswith(x.lower()) for x in pp):
            return False
    if rule.get("filter_benign_parent") and parent in BENIGN_PARENTS:
        return False
    return True


def find_detections(df: pd.DataFrame, rules: Optional[List[Dict]] = None) -> pd.DataFrame:
    out_cols = [
        "rule_id", "rule_name", "mitre_id", "mitre_tactic", "kill_chain_stage",
        "utc_time", "event_time", "image", "event_id", "description", "severity",
        "computer", "process_id", "parent_process_id", "parent_image", "source_ip",
        "source_port", "destination_ip", "destination_port", "target_filename",
        "command_line", "confidence_score",
    ]
    if df.empty:
        return pd.DataFrame(columns=out_cols)
    hits = []
    if rules:
        for _, row in df.iterrows():
            ev = row.to_dict()
            for rule in rules:
                if not _match_rule(ev, rule):
                    continue
                conf = int(rule.get("confidence", 50))
                if ev.get("cmd_high_entropy") or ev.get("is_high_entropy"):
                    conf = min(conf + 15, 100)
                if ev.get("cmd_b64_detected") or ev.get("b64_detected"):
                    conf = min(conf + 10, 100)
                if ev.get("has_encoded_flag") or ev.get("cmd_has_encoded_flag"):
                    conf = min(conf + 10, 100)
                lw = float(ev.get("lolbin_weight") or 0.0)
                if lw > 0:
                    conf = min(int(conf * (1 + lw * 0.2)), 100)
                hits.append({
                    "rule_id":           rule.get("rule_id"),
                    "rule_name":         rule.get("name"),
                    "mitre_id":          rule.get("mitre_id"),
                    "mitre_tactic":      rule.get("mitre_tactic"),
                    "kill_chain_stage":  rule.get("kill_chain_stage", "Execution"),
                    "utc_time":          ev.get("utc_time") or ev.get("event_time"),
                    "event_time":        ev.get("event_time") or ev.get("utc_time"),
                    "image":             ev.get("image"),
                    "event_id":          ev.get("event_id"),
                    "description":       rule.get("description", ""),
                    "severity":          rule.get("severity", "medium"),
                    "computer":          ev.get("computer"),
                    "process_id":        ev.get("process_id") or ev.get("pid"),
                    "parent_process_id": ev.get("parent_process_id") or ev.get("ppid"),
                    "parent_image":      ev.get("parent_image"),
                    "source_ip":         ev.get("source_ip") or ev.get("src_ip"),
                    "source_port":       ev.get("source_port"),
                    "destination_ip":    ev.get("destination_ip") or ev.get("dst_ip"),
                    "destination_port":  ev.get("destination_port") or ev.get("dst_port"),
                    "target_filename":   ev.get("target_filename") or ev.get("file_path"),
                    "command_line":      ev.get("command_line"),
                    "confidence_score":  conf,
                })
    else:
        for _, row in df.iterrows():
            ev  = row.to_dict()
            raw = ev.get("event_id")
            try:
                eid = int(float(raw)) if raw is not None and str(raw) not in ("", "None", "nan") else None
            except (ValueError, TypeError):
                eid = None
            info = EID_MITRE_MAP.get(eid or 0)
            if not info:
                continue
            hits.append({
                "rule_id":           f"HEUR-{eid}",
                "rule_name":         f"EID {eid}: {info['desc']}",
                "mitre_id":          info["mitre_id"],
                "mitre_tactic":      info["tactic"],
                "kill_chain_stage":  info["stage"],
                "utc_time":          ev.get("utc_time") or ev.get("event_time"),
                "event_time":        ev.get("event_time") or ev.get("utc_time"),
                "image":             ev.get("image"),
                "event_id":          eid,
                "description":       info["desc"],
                "severity":          ev.get("severity", "low"),
                "computer":          ev.get("computer"),
                "process_id":        ev.get("process_id") or ev.get("pid"),
                "parent_process_id": ev.get("parent_process_id") or ev.get("ppid"),
                "parent_image":      ev.get("parent_image"),
                "source_ip":         ev.get("source_ip") or ev.get("src_ip"),
                "source_port":       ev.get("source_port"),
                "destination_ip":    ev.get("destination_ip") or ev.get("dst_ip"),
                "destination_port":  ev.get("destination_port") or ev.get("dst_port"),
                "target_filename":   ev.get("target_filename") or ev.get("file_path"),
                "command_line":      ev.get("command_line"),
                "confidence_score":  40,
            })
    return pd.DataFrame(hits, columns=out_cols) if hits else pd.DataFrame(columns=out_cols)
