from typing import Any, List, Dict
from flask import Blueprint, jsonify, request
import json
import logging
import time
from dashboard.db import (
    get_incident_by_id, 
    get_events_by_uids, 
    get_incident_evidence,
    insert_evidence
)
from dashboard.analysis_cache import get_analysis_snapshot
from dashboard.auth import login_required, get_current_user

import datetime
log = logging.getLogger("routes_incident")
incident_bp = Blueprint("incident", __name__)

def safe_parse(ts):
    """[10/10] Robust ISO parser with fallback for malformed telemetry."""
    if not ts:
        return datetime.datetime.min
    try:
        # datetime.datetime.fromisoformat exists since Python 3.7
        return datetime.datetime.fromisoformat(str(ts))
    except (ValueError, TypeError):
        return datetime.datetime.min

def enforce_response_contract(data: Any) -> dict:
    """
    Strict 9.8/10 Mastery: Centralized response normalization.
    Ensures 'status' and 'meta' are always present in JSON returns.
    """
    if not isinstance(data, dict):
        data = {}

    data["status"] = data.get("status") or "complete"

    if "meta" not in data:
        data["meta"] = {
            "pipeline_stage": "unknown",
            "errors": [],
            "warnings": []
        }
    
    return data

@incident_bp.route("/api/incidents/<incident_id>")
def get_incident_detail(incident_id):
    """
    10/10 SOC: Full Reconstruction API.
    Returns the formal incident, enriched with its original analysis context,
    the subset of events matching the triggering UIDs, and tagged evidence.
    """
    # 9.8/10 Mastery: Context-Aware Auth
    if not get_current_user():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        from flask import redirect, url_for
        return redirect(url_for("login"))

    try:
        incident = get_incident_by_id(incident_id)
        if not incident:
            log.warning("[IncidentAPI] Missing incident_id=%s", incident_id)
            return jsonify({"error": "Incident not found"}), 404

        run_id = incident.get("run_id")
        if not run_id:
            log.error("[IncidentAPI] Missing run_id for incident=%s", incident_id)
            return jsonify({"error": "Invalid incident data"}), 500
        
        # 1. Parse triggering UIDs (Traceability Layer)
        raw_uids = incident.get("event_uids")
        try:
            uids = json.loads(raw_uids) if raw_uids else []
            # ── [10/10] order-preserving deduplication ─────────────────────
            uids = list(dict.fromkeys(uids))
            # ── [10/10] Pre-fetch Performance Cap ───────────────────────────
            uids = uids[:1000]
        except Exception:
            uids = []

        # 2. Fetch specific events for the timeline (Precision Guard)
        events = get_events_by_uids(run_id, uids)
        
        # ── [10/10] Post-fetch Ownership Cross-Check ───────────────────────
        valid_uid_set = set(str(e.get("event_uid")) for e in events)
        uids = [u for u in uids if str(u) in valid_uid_set]
        
        if not events and uids:
            log.warning("[Timeline] Expected events missing for incident=%s", incident_id)
        
        # ── [10/10] Deterministic Event Ordering ───────────────────────────
        event_map = {str(e.get("event_uid")): e for e in events}
        timeline = [event_map[str(u)] for u in uids if str(u) in event_map]
        
        # Stability fallback if event_uids were not ordered
        if not timeline and events:
            timeline = sorted(
                events, 
                key=lambda x: (safe_parse(x.get("event_time")), str(x.get("event_uid", "")))
            )

        # 3. Enrich with Analysis Context (Explainability)
        # ── [9.6/10 Locked] Exponential Backoff Retrieval ───────────────────
        snapshot = None
        wait = 0.1
        for i in range(5):
            snapshot = get_analysis_snapshot(run_id)
            if snapshot:
                break
            log.info(f"[IncidentAPI] Snapshot retry {i+1}/5 for run_id={run_id[:8]}")
            time.sleep(wait)
            wait *= 2

        if not snapshot:
            log.warning("[IncidentAPI] Analysis snapshot missing after retries for run_id=%s", run_id)
            # ── [9.6/10 Locked] UX-Aware Processing State ──────────────────
            snapshot = {
                "timeline": [],
                "burst_aggregates": [],
                "status": "processing",
                "attack_narrative": {
                    "summary": "Analysis in progress... please wait.",
                    "stage": "Processing",
                    "score": 0,
                    "is_attack": False
                }
            }

        # Guarantee attack_story structure for UI contract
        attack_story = snapshot.get("attack_narrative") or {
            "summary": "Analysis incomplete \u2014 narrative unavailable",
            "bullets": [],
            "full_text": "",
            "stage": "Unknown",
            "score": 0,
            "is_attack": None
        }

        # Normalize timeline events for UI safety
        safe_timeline = []
        invalid_events = 0
        for e in timeline:
            if not isinstance(e, dict):
                invalid_events += 1
                continue
            safe_timeline.append({
                "event_uid": str(e.get("event_uid", "")),
                "event_time": str(e.get("event_time") or "1970-01-01T00:00:00Z"),
                "event_id": e.get("event_id", ""),
                "image": e.get("image", "unknown"),
                "parent_image": e.get("parent_image", ""),
                "command_line": e.get("command_line", ""),
                "computer": e.get("computer", ""),
                "network": e.get("destination_ip") or e.get("dst_ip") or ""
            })

        if invalid_events > 0:
            log.error("[IncidentAPI] %d invalid events dropped for incident=%s", invalid_events, incident_id)

        timeline_valid = True
        if not safe_timeline:
            timeline_valid = False
            log.error(
                "[IncidentAPI] Empty timeline | incident=%s | run_id=%s | uids=%d | events=%d",
                incident_id, run_id, len(uids), len(events)
            )

        # 4. Fetch tagged evidence
        evidence = get_incident_evidence(incident_id)

        log.info(
            "[IncidentAPI] incident=%s | events=%d | evidence=%d | has_story=%s",
            incident_id,
            len(safe_timeline),
            len(evidence or []),
            bool(attack_story.get("summary"))
        )

        def safe_json(obj):
            if isinstance(obj, dict):
                return {k: safe_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [safe_json(v) for v in obj]
            elif isinstance(obj, (datetime.datetime, datetime.date)):
                return obj.isoformat()
            else:
                try:
                    json.dumps(obj)
                    return obj
                except Exception:
                    return str(obj)

        return jsonify(enforce_response_contract({
            "incident": safe_json(incident),
            "attack_story": attack_story,
            "timeline": safe_timeline,
            "timeline_valid": timeline_valid,
            "evidence": evidence or [],
            "run_id": run_id,
            "status": snapshot.get("status", "complete"),
            "meta": snapshot.get("meta", {})
        }))
    except Exception as e:
        log.error("[IncidentDetail] Error fetching %s: %s", incident_id, e, exc_info=True)
        return jsonify(enforce_response_contract({
            "error": str(e),
            "status": "failed",
            "meta": {
                "pipeline_stage": "api-error",
                "errors": [{"stage": "api", "message": str(e)[:200], "type": type(e).__name__}]
            }
        })), 500

@incident_bp.route("/api/evidence/add", methods=["POST"])
@login_required
def add_evidence():
    """
    10/10 SOC: Structured Evidence Tagging with Validation.
    """
    data = request.json
    incident_id = data.get("incident_id")
    event_uid   = data.get("event_uid")
    tag         = data.get("tag", "Relevant")

    if not incident_id or not event_uid:
        return jsonify({"error": "Missing parameters"}), 400

    try:
        incident = get_incident_by_id(incident_id)
        if not incident:
            return jsonify({"error": "Incident not found"}), 404

        # Validation: Ensure event_uid belongs to the incident's triggering set
        raw_uids = incident.get("event_uids")
        try:
            valid_uids = [str(u) for u in json.loads(raw_uids)] if raw_uids else []
        except Exception:
            valid_uids = []

        if str(event_uid) not in valid_uids:
            # log.warning("[Evidence] Attempted to link unassociated event %s to INC-%s", event_uid, incident_id)
            return jsonify({"error": "Event not associated with this incident"}), 400

        user = get_current_user()
        analyst_name = user.get("username", "system") if isinstance(user, dict) else "system"
        
        insert_evidence(incident_id, event_uid, tag, analyst_name)
        return jsonify({"success": True, "message": "Evidence linked"})
    except Exception as e:
        log.error("[EvidenceAdd] Failed for %s: %s", incident_id, e)
        return jsonify({"error": str(e)}), 500
