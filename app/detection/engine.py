"""
Detection engine — evaluates rules against stored log events.

The engine groups events by source IP and checks whether any IP exceeds
the configured threshold within the rolling time window defined by each rule.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.detection.rules import ACTIVE_RULES, DetectionRule
from app.models import Alert, LogEvent


def run_detection(db: Session, file_name: Optional[str] = None) -> list[Alert]:
    """
    Evaluate all active detection rules against events in the database.

    Args:
        db: Active database session.
        file_name: If supplied, only evaluate events from this upload.

    Returns:
        List of newly-created Alert objects.
    """
    new_alerts: list[Alert] = []

    for rule in ACTIVE_RULES:
        alerts = _evaluate_rule(db, rule, file_name)
        new_alerts.extend(alerts)

    if new_alerts:
        db.add_all(new_alerts)
        db.commit()

    return new_alerts


def _evaluate_rule(
    db: Session,
    rule: DetectionRule,
    file_name: Optional[str],
) -> list[Alert]:
    """Evaluate a single detection rule and return generated alerts."""

    # ── Query matching events ────────────────────────────────────────────
    query = db.query(LogEvent).filter(
        LogEvent.event_type.in_(rule.event_types),
        LogEvent.log_source == rule.log_source,
        LogEvent.source_ip.isnot(None),
    )
    if file_name:
        query = query.filter(LogEvent.file_name == file_name)

    events: list[LogEvent] = query.order_by(LogEvent.timestamp.asc()).all()

    if not events:
        return []

    # ── Group events by source IP ────────────────────────────────────────
    ip_events: dict[str, list[LogEvent]] = defaultdict(list)
    for ev in events:
        ip_events[ev.source_ip].append(ev)  # type: ignore[arg-type]

    # ── Sliding-window check per IP ──────────────────────────────────────
    window = timedelta(minutes=rule.window_minutes)
    alerts: list[Alert] = []

    for ip, ev_list in ip_events.items():
        # Check if we already have an alert for this rule + IP combination
        existing = (
            db.query(Alert)
            .filter(Alert.rule_name == rule.name, Alert.source_ip == ip)
            .first()
        )
        if existing:
            continue  # Don't duplicate alerts

        # Sliding window: for each event, count how many follow within the window
        for i, anchor in enumerate(ev_list):
            window_end = anchor.timestamp + window
            window_events = [
                e for e in ev_list[i:] if e.timestamp <= window_end
            ]

            if len(window_events) >= rule.threshold:
                description = rule.description.format(
                    count=len(window_events),
                    ip=ip,
                    window=rule.window_minutes,
                    threshold=rule.threshold,
                )
                alert = Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    source_ip=ip,
                    event_count=len(window_events),
                    first_seen=window_events[0].timestamp,
                    last_seen=window_events[-1].timestamp,
                    description=description,
                )
                alerts.append(alert)
                break  # One alert per IP per rule is enough

    return alerts
