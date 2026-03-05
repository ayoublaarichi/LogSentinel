"""
Attack graph router — graph-shaped API for SOC relationship visualization.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_user
from app.models import Alert, LogEvent, User
from app.routers.events import _resolve_project_filter, _visible_user_ids

router = APIRouter(tags=["Graph"])

MAX_EVENT_ROWS = 1000
MAX_ALERT_ROWS = 400
MAX_NODES = 200
MAX_EDGES = 400


def _severity_rank(value: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get((value or "").lower(), 0)


@router.get("/api/graph", tags=["Graph"])
def attack_graph(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    project_id: Optional[int] = Query(None, ge=1),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return graph data as {nodes:[...], edges:[...]} for attack relationships."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    project_filter = _resolve_project_filter(db, user, project_id)
    visible_ids = _visible_user_ids(db, user, request)

    events_q = db.query(LogEvent).filter(
        LogEvent.user_id.in_(visible_ids),
        LogEvent.timestamp >= cutoff,
    )
    if project_filter is not None:
        events_q = events_q.filter(LogEvent.user_id == user.id, LogEvent.project_id == project_filter)
    events = events_q.order_by(LogEvent.timestamp.desc()).limit(MAX_EVENT_ROWS).all()

    alerts_q = db.query(Alert).filter(
        Alert.user_id == user.id,
        Alert.created_at >= cutoff,
    )
    if project_filter is not None:
        alerts_q = alerts_q.filter(Alert.project_id == project_filter)
    alerts = alerts_q.order_by(Alert.created_at.desc()).limit(MAX_ALERT_ROWS).all()

    nodes: dict[str, dict] = {}
    edge_weights: dict[tuple[str, str, str], int] = defaultdict(int)
    ip_counts: dict[str, int] = defaultdict(int)
    ip_top_severity: dict[str, str] = {}

    def ensure_node(node_id: str, label: str, node_type: str) -> None:
        if node_id in nodes:
            return
        nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "group": node_type,
        }

    for event in events:
        if not event.source_ip:
            continue
        ip_id = f"ip:{event.source_ip}"
        etype = event.event_type or "unknown"
        etype_id = f"etype:{etype}"

        ensure_node(ip_id, event.source_ip, "ip")
        ensure_node(etype_id, etype, "event_type")

        ip_counts[event.source_ip] += 1
        edge_weights[(ip_id, etype_id, "event")] += 1

        if event.username and event.username.lower() != "unknown":
            user_id = f"user:{event.username}"
            ensure_node(user_id, event.username, "user")
            edge_weights[(user_id, ip_id, "auth") ] += 1

    for alert in alerts:
        ip_value = alert.source_ip
        if not ip_value:
            continue
        ip_id = f"ip:{ip_value}"
        rule = alert.rule_name or "Unknown Rule"
        rule_id = f"rule:{rule}"

        ensure_node(ip_id, ip_value, "ip")
        ensure_node(rule_id, rule, "alert_rule")
        edge_weights[(ip_id, rule_id, "alert")] += max(1, int(alert.event_count or 1))

        current = ip_top_severity.get(ip_value, "")
        if _severity_rank(alert.severity) > _severity_rank(current):
            ip_top_severity[ip_value] = alert.severity

    for node in nodes.values():
        if node["type"] == "ip":
            ip = node["label"]
            node["event_count"] = int(ip_counts.get(ip, 0))
            node["severity"] = ip_top_severity.get(ip, "none")
            node["value"] = max(8, min(42, 8 + int(ip_counts.get(ip, 0) ** 0.5) * 2))

    node_scores: dict[str, int] = defaultdict(int)
    for (src, dst, _kind), weight in edge_weights.items():
        node_scores[src] += int(weight)
        node_scores[dst] += int(weight)

    for node_id, node in nodes.items():
        if node.get("type") == "ip":
            severity_bonus = _severity_rank(str(node.get("severity") or "")) * 10
            node_scores[node_id] += int(node.get("event_count") or 0) + severity_bonus

    selected_node_ids = {
        node_id
        for node_id, _score in sorted(
            node_scores.items(),
            key=lambda item: (item[1], item[0]),
            reverse=True,
        )[:MAX_NODES]
    }
    if len(selected_node_ids) < min(MAX_NODES, len(nodes)):
        for node_id in sorted(nodes.keys()):
            if len(selected_node_ids) >= MAX_NODES:
                break
            selected_node_ids.add(node_id)

    all_edges = [
        {
            "id": f"{src}->{dst}:{kind}",
            "from": src,
            "to": dst,
            "kind": kind,
            "weight": weight,
            "label": str(weight),
            "value": weight,
        }
        for (src, dst, kind), weight in edge_weights.items()
        if src in selected_node_ids and dst in selected_node_ids
    ]

    all_edges.sort(key=lambda e: (int(e["weight"]), e["id"]), reverse=True)
    edges = all_edges[:MAX_EDGES]

    connected_node_ids = set()
    for edge in edges:
        connected_node_ids.add(edge["from"])
        connected_node_ids.add(edge["to"])

    node_ids_for_output = selected_node_ids if not connected_node_ids else connected_node_ids
    output_nodes = [nodes[node_id] for node_id in sorted(node_ids_for_output) if node_id in nodes]

    return {
        "nodes": output_nodes,
        "edges": edges,
        "meta": {
            "hours": hours,
            "project_id": project_filter,
            "event_rows": len(events),
            "alert_rows": len(alerts),
            "limits": {
                "max_events": MAX_EVENT_ROWS,
                "max_alerts": MAX_ALERT_ROWS,
                "max_nodes": MAX_NODES,
                "max_edges": MAX_EDGES,
            },
        },
    }
