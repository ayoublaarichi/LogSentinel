"""
Detection engine — sliding-window rule evaluation, always scoped by user_id.

The core algorithm is a **two-pointer sliding window** (O(n) per IP
per rule) that avoids loading every event into memory at once.
"""

from datetime import timedelta
import re
from typing import Optional

from sqlalchemy import asc
from sqlalchemy.orm import Session

from app.detection.rules import ACTIVE_RULES, DetectionRule
from app.models import Alert, LogEvent


_PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)


def run_detection(
    db: Session,
    file_name: str,
    user_id: Optional[int] = None,
    project_id: Optional[int] = None,
) -> list[Alert]:
    """
    Evaluate all active detection rules against events belonging to *user_id*
    from *file_name*.

    Returns a list of newly-created Alert objects (already committed).
    """
    new_alerts: list[Alert] = []

    for rule in ACTIVE_RULES:
        alerts = _evaluate_rule(db, rule, file_name, user_id, project_id)
        new_alerts.extend(alerts)

    new_alerts.extend(_detect_port_scan(db, file_name, user_id, project_id))
    new_alerts.extend(_detect_suspicious_admin_activity(db, file_name, user_id, project_id))

    return new_alerts


def _evaluate_rule(
    db: Session,
    rule: DetectionRule,
    file_name: str,
    user_id: Optional[int],
    project_id: Optional[int],
) -> list[Alert]:
    """
    For one rule, find all IPs with qualifying events in the given file,
    then run the two-pointer sliding window per IP.
    """
    # Base query: events matching this rule's criteria, scoped to user.
    base = db.query(LogEvent).filter(
        LogEvent.file_name == file_name,
        LogEvent.event_type.in_(rule.event_types),
        LogEvent.log_source == rule.log_source,
    )
    if user_id is not None:
        base = base.filter(LogEvent.user_id == user_id)
    if project_id is not None:
        base = base.filter(LogEvent.project_id == project_id)

    # Distinct IPs in this file
    ip_rows = (
        base.filter(LogEvent.source_ip.isnot(None))
        .with_entities(LogEvent.source_ip)
        .distinct()
        .all()
    )

    new_alerts: list[Alert] = []

    for (ip,) in ip_rows:
        events = (
            base.filter(LogEvent.source_ip == ip)
            .order_by(asc(LogEvent.timestamp))
            .all()
        )
        alert = _sliding_window(db, rule, ip, events, user_id, project_id)
        if alert:
            new_alerts.append(alert)

    return new_alerts


def _sliding_window(
    db: Session,
    rule: DetectionRule,
    ip: str,
    events: list[LogEvent],
    user_id: Optional[int],
    project_id: Optional[int],
) -> Optional[Alert]:
    """
    Two-pointer O(n) sliding window over *events* (already sorted by timestamp).

    If any window of *rule.window_minutes* contains >= *rule.threshold* events,
    we create an alert (unless an identical one already exists for this user).
    """
    if not events:
        return None

    window = timedelta(minutes=rule.window_minutes)
    left = 0
    max_count = 0
    best_left = 0
    best_right = 0

    for right in range(len(events)):
        # Shrink left pointer while outside window
        while events[right].timestamp - events[left].timestamp > window:
            left += 1

        current = right - left + 1
        if current > max_count:
            max_count = current
            best_left = left
            best_right = right

    if max_count < rule.threshold:
        return None

    # Collect usernames from the window
    usernames = sorted(
        {
            ev.username
            for ev in events[best_left : best_right + 1]
            if ev.username and ev.username != "unknown"
        }
    )

    # Check for existing alert with same rule + IP + user
    exists_q = db.query(Alert).filter(
        Alert.rule_name == rule.name,
        Alert.source_ip == ip,
    )
    if user_id is not None:
        exists_q = exists_q.filter(Alert.user_id == user_id)
    if project_id is not None:
        exists_q = exists_q.filter(Alert.project_id == project_id)
    if exists_q.first():
        return None

    description = rule.description.format(
        count=max_count,
        ip=ip,
        window=rule.window_minutes,
        threshold=rule.threshold,
    )

    alert = Alert(
        user_id=user_id,
        project_id=project_id,
        rule_name=rule.name,
        severity=rule.severity,
        source_ip=ip,
        event_count=max_count,
        first_seen=events[best_left].timestamp,
        last_seen=events[best_right].timestamp,
        description=description,
        usernames=Alert.encode_usernames(usernames),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def _detect_port_scan(
    db: Session,
    file_name: str,
    user_id: Optional[int],
    project_id: Optional[int],
) -> list[Alert]:
    base = db.query(LogEvent).filter(
        LogEvent.file_name == file_name,
        LogEvent.source_ip.isnot(None),
    )
    if user_id is not None:
        base = base.filter(LogEvent.user_id == user_id)
    if project_id is not None:
        base = base.filter(LogEvent.project_id == project_id)

    ip_rows = base.with_entities(LogEvent.source_ip).distinct().all()
    generated: list[Alert] = []
    window = timedelta(minutes=2)

    for (ip,) in ip_rows:
        events = base.filter(LogEvent.source_ip == ip).order_by(asc(LogEvent.timestamp)).all()
        if len(events) < 10:
            continue

        left = 0
        port_counts: dict[int, int] = {}
        best = None

        for right in range(len(events)):
            right_ports = _extract_ports(events[right].raw_line)
            for port in right_ports:
                port_counts[port] = port_counts.get(port, 0) + 1

            while events[right].timestamp - events[left].timestamp > window:
                left_ports = _extract_ports(events[left].raw_line)
                for port in left_ports:
                    next_count = port_counts.get(port, 0) - 1
                    if next_count <= 0:
                        port_counts.pop(port, None)
                    else:
                        port_counts[port] = next_count
                left += 1

            attempts = right - left + 1
            unique_ports = len(port_counts)
            if attempts >= 10 and unique_ports >= 10:
                best = (left, right, attempts, unique_ports)

        if not best:
            continue

        if _alert_exists(db, "Port Scan Behavior", ip, user_id, project_id):
            continue

        b_left, b_right, attempts, unique_ports = best
        usernames = sorted(
            {
                ev.username
                for ev in events[b_left : b_right + 1]
                if ev.username and ev.username != "unknown"
            }
        )

        alert = Alert(
            user_id=user_id,
            project_id=project_id,
            rule_name="Port Scan Behavior",
            severity="high",
            source_ip=ip,
            event_count=attempts,
            first_seen=events[b_left].timestamp,
            last_seen=events[b_right].timestamp,
            description=(
                f"Detected {attempts} connection attempts from {ip} across "
                f"{unique_ports} ports within 2 minutes."
            ),
            usernames=Alert.encode_usernames(usernames),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        generated.append(alert)

    return generated


def _detect_suspicious_admin_activity(
    db: Session,
    file_name: str,
    user_id: Optional[int],
    project_id: Optional[int],
) -> list[Alert]:
    base = db.query(LogEvent).filter(LogEvent.file_name == file_name)
    if user_id is not None:
        base = base.filter(LogEvent.user_id == user_id)
    if project_id is not None:
        base = base.filter(LogEvent.project_id == project_id)

    events = base.order_by(asc(LogEvent.timestamp)).all()
    if not events:
        return []

    generated: list[Alert] = []
    sequence_window = timedelta(seconds=30)

    for index, event in enumerate(events):
        username = (event.username or "").lower()
        if username not in {"admin", "root"}:
            continue
        if event.event_type != "ssh_accepted_login":
            continue
        if not event.source_ip:
            continue

        if _alert_exists(db, "Suspicious Admin Activity", event.source_ip, user_id, project_id):
            continue

        trigger = None
        for candidate in events[index + 1 :]:
            if candidate.timestamp - event.timestamp > sequence_window:
                break
            message = (candidate.raw_line or "").lower()
            if "sudo" in message or "config" in message or "modified" in message:
                trigger = candidate
                break

        if not trigger:
            continue

        alert = Alert(
            user_id=user_id,
            project_id=project_id,
            rule_name="Suspicious Admin Activity",
            severity="critical",
            source_ip=event.source_ip,
            event_count=2,
            first_seen=event.timestamp,
            last_seen=trigger.timestamp,
            description=(
                f"Admin login from {event.source_ip} followed by privileged/config "
                f"activity within 30 seconds."
            ),
            usernames=Alert.encode_usernames([event.username] if event.username else []),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        generated.append(alert)

    return generated


def _extract_ports(raw_line: str) -> list[int]:
    matches = _PORT_RE.findall(raw_line or "")
    ports: list[int] = []
    for token in matches:
        try:
            port = int(token)
        except ValueError:
            continue
        if 0 < port <= 65535:
            ports.append(port)
    return ports


def _alert_exists(
    db: Session,
    rule_name: str,
    source_ip: str,
    user_id: Optional[int],
    project_id: Optional[int],
) -> bool:
    q = db.query(Alert).filter(Alert.rule_name == rule_name, Alert.source_ip == source_ip)
    if user_id is not None:
        q = q.filter(Alert.user_id == user_id)
    if project_id is not None:
        q = q.filter(Alert.project_id == project_id)
    return q.first() is not None
