"""
Detection engine — evaluates rules against stored log events.

The engine groups events by source IP and applies a sliding-window check:
for each IP, it looks for the first time-window of `rule.window_minutes`
minutes that contains at least `rule.threshold` matching events.  When
found, it creates one Alert per (rule, IP) pair and records:

  - event_count  – events inside the winning window
  - first_seen   – timestamp of the first event in the window
  - last_seen    – timestamp of the last event in the window
  - usernames    – JSON list of unique usernames targeted by that IP

Only one alert is created per (rule, IP) combination so we never
duplicate alerts for the same ongoing attack.
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
        List of newly-created Alert objects (already committed to the DB).
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
    """
    Evaluate a single detection rule and return generated Alert objects.

    Algorithm (O(n) per IP):
    1. Query all matching events, ordered by timestamp ascending.
    2. Group them into per-IP buckets.
    3. For each IP bucket use a left-pointer / right-pointer sliding window
       to find the first window of rule.window_minutes that contains >=
       rule.threshold events.  This avoids re-scanning the list for every
       anchor point (the naïve O(n²) approach).
    4. If found, build an Alert; skip IPs that already have one.
    """

    # ── 1. Query matching events ─────────────────────────────────────────
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

    # ── 2. Group events by source IP ─────────────────────────────────────
    # Using defaultdict(list) keeps insertion order per-key (Python 3.7+).
    ip_events: dict[str, list[LogEvent]] = defaultdict(list)
    for ev in events:
        ip_events[ev.source_ip].append(ev)  # type: ignore[index]

    # ── 3. Sliding-window check per IP ───────────────────────────────────
    window_delta = timedelta(minutes=rule.window_minutes)
    alerts: list[Alert] = []

    for ip, ev_list in ip_events.items():

        # Skip IPs that already have an alert for this rule (no duplicates).
        existing = (
            db.query(Alert)
            .filter(Alert.rule_name == rule.name, Alert.source_ip == ip)
            .first()
        )
        if existing:
            continue

        # Two-pointer sliding window:
        #   left  – index of the oldest event in the current window
        #   right – index of the event we are currently considering
        # We advance `right` one step at a time; whenever the span from
        # ev_list[left].timestamp to ev_list[right].timestamp exceeds the
        # allowed window we advance `left` to shrink the window.
        n = len(ev_list)
        left = 0
        triggered = False

        for right in range(n):
            # Shrink window from the left until it fits within window_delta
            while (ev_list[right].timestamp - ev_list[left].timestamp) > window_delta:
                left += 1

            window_size = right - left + 1
            if window_size >= rule.threshold:
                # Found a window that exceeds the threshold for this IP.
                window_events = ev_list[left : right + 1]

                # Collect every unique, non-empty username targeted in this window.
                targeted: list[str] = sorted({
                    e.username
                    for e in window_events
                    if e.username and e.username != "unknown"
                })

                description = rule.description.format(
                    count=window_size,
                    ip=ip,
                    window=rule.window_minutes,
                    threshold=rule.threshold,
                )
                alert = Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    source_ip=ip,
                    event_count=window_size,
                    first_seen=window_events[0].timestamp,
                    last_seen=window_events[-1].timestamp,
                    description=description,
                    usernames=Alert.encode_usernames(targeted),
                )
                alerts.append(alert)
                triggered = True
                break  # One alert per (rule, IP) is sufficient

        # `triggered` is unused after the loop but kept for readability.
        _ = triggered

    return alerts
