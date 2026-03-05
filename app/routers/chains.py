import copy
import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, LogEvent, User
from app.routers.events import _resolve_project_filter
from app.services.threat_intel_service import enrich_ip

router = APIRouter(tags=["Chains"])

_MAX_EVENTS = 500
_CACHE_TTL_SECONDS = 60
_CHAIN_CACHE: dict[str, tuple[float, dict]] = {}

_PHASE_ORDER = [
    "Reconnaissance",
    "Credential Access",
    "Initial Access",
    "Privilege Escalation",
    "Impact / Config",
]


def _phase_for_event(event: LogEvent) -> Optional[str]:
    event_type = (event.event_type or "").lower()
    raw = (event.raw_line or "").lower()

    if "scan" in event_type or "port" in event_type or "port scan" in raw:
        return "Reconnaissance"
    if event_type in {"ssh_failed_login", "ssh_invalid_user"} or "failed password" in raw or "authentication failure" in raw:
        return "Credential Access"
    if event_type in {"ssh_accepted_login"} or "accepted password" in raw or "session opened" in raw:
        return "Initial Access"
    if "sudo" in raw or "privilege" in raw or "admin" in raw:
        return "Privilege Escalation"
    if "config" in raw or "modified" in raw or "service stopped" in raw or "useradd" in raw:
        return "Impact / Config"
    return None


def _cluster_sessions(events: list[LogEvent], gap_minutes: int = 10) -> list[list[LogEvent]]:
    if not events:
        return []
    clusters: list[list[LogEvent]] = [[events[0]]]
    for event in events[1:]:
        prev = clusters[-1][-1]
        if (event.timestamp - prev.timestamp) > timedelta(minutes=gap_minutes):
            clusters.append([event])
        else:
            clusters[-1].append(event)
    return clusters


def _build_summary(score: int, has_recon: bool, has_cred: bool, has_init: bool, has_priv: bool, has_impact: bool, is_tor: bool) -> str:
    if has_cred and has_init and (has_priv or has_impact):
        return "Brute-force/credential activity followed by successful access and privileged or config actions indicates probable compromise attempt."
    if has_recon and has_cred and has_init:
        return "Reconnaissance plus credential attacks followed by successful access suggests active intrusion progression."
    if has_recon and has_cred:
        return "Reconnaissance and credential access patterns detected; likely pre-compromise attack activity."
    if has_recon:
        return "Reconnaissance-like activity detected."
    if is_tor and score >= 50:
        return "High-risk chain includes TOR/proxy reputation with suspicious behavior."
    return "Partial attack-chain evidence detected; continue investigation with broader context."


def _next_actions(score: int, has_init: bool, has_priv: bool, has_impact: bool) -> list[str]:
    actions = ["Review related alerts and timeline for the same entity"]
    if score >= 40:
        actions.append("Block or rate-limit source IP at perimeter")
    if has_init:
        actions.append("Reset potentially affected credentials")
    if has_priv or has_impact:
        actions.append("Audit privileged actions and configuration changes")
    if score >= 70:
        actions.append("Open or escalate incident case to high priority")
    return actions[:4]


@router.get("/api/chains/build", tags=["Chains"])
def build_chain(
    ip: Optional[str] = Query(None),
    user_name: Optional[str] = Query(None, alias="user"),
    host: Optional[str] = Query(None),
    alert_id: Optional[int] = Query(None, ge=1),
    hours: int = Query(24, ge=1, le=168),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    return build_chain_payload(
        db=db,
        user=user,
        ip=ip,
        user_name=user_name,
        host=host,
        alert_id=alert_id,
        hours=hours,
        project_id=project_id,
    )


def build_chain_payload(
    db: Session,
    user: User,
    ip: Optional[str],
    user_name: Optional[str],
    host: Optional[str],
    alert_id: Optional[int],
    hours: int,
    project_id: Optional[int],
) -> dict:
    if not any([ip, user_name, host, alert_id]):
        raise HTTPException(status_code=400, detail="Provide at least one of ip, user, host, or alert_id")

    project_filter = _resolve_project_filter(db, user, project_id)

    cache_key = f"u={user.id}|p={project_filter}|ip={ip}|user={user_name}|host={host}|alert={alert_id}|h={hours}"
    now = time.time()
    cached = _CHAIN_CACHE.get(cache_key)
    if cached and (now - cached[0]) <= _CACHE_TTL_SECONDS:
        return copy.deepcopy(cached[1])

    if alert_id and not any([ip, user_name, host]):
        alert = db.query(Alert).filter(Alert.id == alert_id, Alert.user_id == user.id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        ip = alert.source_ip

    since = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(LogEvent).filter(LogEvent.user_id == user.id, LogEvent.timestamp >= since)
    if project_filter is not None:
        q = q.filter(LogEvent.project_id == project_filter)
    if ip:
        q = q.filter(LogEvent.source_ip == ip)
    if user_name:
        q = q.filter(LogEvent.username == user_name)
    if host:
        pattern = f"%{host}%"
        q = q.filter((LogEvent.file_name.ilike(pattern)) | (LogEvent.raw_line.ilike(pattern)))

    events = q.order_by(LogEvent.timestamp.asc()).limit(_MAX_EVENTS).all()

    if not events:
        entity_type = "ip" if ip else "user" if user_name else "host"
        entity_value = ip or user_name or host or "unknown"
        result = {
            "chain_id": f"chain:{entity_type}:{entity_value}:{datetime.utcnow().strftime('%Y%m%d%H')}",
            "entity": {"type": entity_type, "value": entity_value},
            "window_hours": hours,
            "score": 0,
            "confidence": "Low",
            "phases": [],
            "summary": "No matching events in the selected window.",
            "next_actions": ["Expand time window", "Review related alerts"],
        }
        _CHAIN_CACHE[cache_key] = (now, result)
        return copy.deepcopy(result)

    clusters = _cluster_sessions(events)

    def cluster_score(cluster: list[LogEvent]) -> int:
        pts = 0
        for event in cluster:
            phase = _phase_for_event(event)
            if phase == "Reconnaissance":
                pts += 2
            elif phase == "Credential Access":
                pts += 3
            elif phase == "Initial Access":
                pts += 3
            elif phase == "Privilege Escalation":
                pts += 4
            elif phase == "Impact / Config":
                pts += 4
        return pts

    strongest = max(clusters, key=cluster_score)

    phase_events: dict[str, list[dict]] = {name: [] for name in _PHASE_ORDER}
    for event in strongest:
        phase = _phase_for_event(event)
        if not phase:
            continue
        phase_events[phase].append(
            {
                "id": event.id,
                "ts": event.timestamp,
                "message": event.raw_line,
                "event_type": event.event_type,
            }
        )

    if ip:
        alerts_q = db.query(Alert).filter(
            Alert.user_id == user.id,
            Alert.source_ip == ip,
            Alert.created_at >= since,
        )
        if project_filter is not None:
            alerts_q = alerts_q.filter(Alert.project_id == project_filter)
        if alert_id:
            alerts_q = alerts_q.filter(Alert.id == alert_id)
        related_alerts = alerts_q.limit(80).all()

        for alert in related_alerts:
            name = (alert.rule_name or "").lower()
            if "port scan" in name:
                phase_events["Reconnaissance"].append(
                    {
                        "id": f"alert:{alert.id}",
                        "ts": alert.created_at,
                        "message": f"Alert evidence: {alert.rule_name}",
                    }
                )
            if "brute" in name or "login" in name:
                phase_events["Credential Access"].append(
                    {
                        "id": f"alert:{alert.id}",
                        "ts": alert.created_at,
                        "message": f"Alert evidence: {alert.rule_name}",
                    }
                )

    has_recon = bool(phase_events["Reconnaissance"])
    has_cred = bool(phase_events["Credential Access"])
    has_init = bool(phase_events["Initial Access"])
    has_priv = bool(phase_events["Privilege Escalation"])
    has_impact = bool(phase_events["Impact / Config"])

    score = 0
    if has_recon:
        score += 15
    if has_cred:
        score += 25
    if has_cred and has_init:
        score += 20
    if has_priv or has_impact:
        score += 30

    is_tor = False
    if ip:
        intel = enrich_ip(db, ip)
        is_tor = bool(intel.get("is_tor"))
        if is_tor:
            score += 10

    score = max(0, min(100, score))
    confidence = "Low" if score <= 40 else "Medium" if score <= 70 else "High"

    phase_weights = {
        "Reconnaissance": 20,
        "Credential Access": 25,
        "Initial Access": 20,
        "Privilege Escalation": 25,
        "Impact / Config": 30,
    }
    phases = []
    for name in _PHASE_ORDER:
        items = phase_events[name]
        if not items:
            continue
        phases.append(
            {
                "name": name,
                "score": phase_weights.get(name, 10),
                "events": [
                    {
                        **e,
                        "ts": e["ts"].isoformat() if hasattr(e["ts"], "isoformat") else str(e["ts"]),
                    }
                    for e in items[:60]
                ],
            }
        )

    entity_type = "ip" if ip else "user" if user_name else "host"
    entity_value = ip or user_name or host or "unknown"

    result = {
        "chain_id": f"chain:{entity_type}:{entity_value}:{datetime.utcnow().strftime('%Y%m%d%H')}",
        "entity": {"type": entity_type, "value": entity_value},
        "window_hours": hours,
        "score": score,
        "confidence": confidence,
        "phases": phases,
        "summary": _build_summary(score, has_recon, has_cred, has_init, has_priv, has_impact, is_tor),
        "next_actions": _next_actions(score, has_init, has_priv, has_impact),
    }
    _CHAIN_CACHE[cache_key] = (now, result)

    # best-effort small eviction to keep memory bounded
    if len(_CHAIN_CACHE) > 200:
        cutoff = now - _CACHE_TTL_SECONDS
        stale = [k for k, (ts, _v) in _CHAIN_CACHE.items() if ts < cutoff]
        for key in stale[:150]:
            _CHAIN_CACHE.pop(key, None)

    return copy.deepcopy(result)
