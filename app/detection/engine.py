"""
Detection engine — sliding-window rule evaluation, always scoped by user_id.

The core algorithm is a **two-pointer sliding window** (O(n) per IP
per rule) that avoids loading every event into memory at once.
"""

from datetime import timedelta
from typing import Optional

from sqlalchemy import asc
from sqlalchemy.orm import Session

from app.detection.rules import ACTIVE_RULES, DetectionRule
from app.models import Alert, LogEvent


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
