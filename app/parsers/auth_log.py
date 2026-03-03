"""
Parser for Linux auth.log / secure log files.

Handles common sshd patterns:
  - Failed password
  - Accepted password / publickey
  - Invalid user
  - Connection closed / reset
"""

import re
from datetime import datetime
from typing import Optional

from app.parsers.base import BaseParser, ParsedEvent

# ── Regex patterns ───────────────────────────────────────────────────────────
# Standard syslog prefix:  "Mon DD HH:MM:SS hostname sshd[PID]: ..."
_SYSLOG_PREFIX = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(?P<hostname>\S+)\s+"                                       # hostname
    r"sshd\[\d+\]:\s+"                                            # service
    r"(?P<message>.+)$"                                            # message body
)

_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_CONNECTION_CLOSED = re.compile(
    r"Connection (?:closed|reset) by (?:authenticating user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+)"
)


class AuthLogParser(BaseParser):
    """Parses Linux auth.log / secure SSHD entries."""

    # Year is not in syslog timestamps — we assume current year.
    _current_year: int = datetime.now().year

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse a single auth.log line into a structured event."""
        prefix_match = _SYSLOG_PREFIX.match(line)
        if not prefix_match:
            return None

        timestamp = self._parse_timestamp(prefix_match.group("timestamp"))
        message = prefix_match.group("message")

        # Try each pattern in priority order
        if (m := _FAILED_PASSWORD.search(message)):
            return ParsedEvent(
                timestamp=timestamp,
                source_ip=m.group("ip"),
                username=m.group("user"),
                event_type="ssh_failed_login",
                log_source="auth",
                raw_line=line,
            )

        if (m := _ACCEPTED_PASSWORD.search(message)):
            return ParsedEvent(
                timestamp=timestamp,
                source_ip=m.group("ip"),
                username=m.group("user"),
                event_type="ssh_accepted_login",
                log_source="auth",
                raw_line=line,
            )

        if (m := _INVALID_USER.search(message)):
            return ParsedEvent(
                timestamp=timestamp,
                source_ip=m.group("ip"),
                username=m.group("user"),
                event_type="ssh_invalid_user",
                log_source="auth",
                raw_line=line,
            )

        if (m := _CONNECTION_CLOSED.search(message)):
            return ParsedEvent(
                timestamp=timestamp,
                source_ip=m.group("ip"),
                username=None,
                event_type="ssh_connection_closed",
                log_source="auth",
                raw_line=line,
            )

        # Generic SSHD line we couldn't classify specifically
        return ParsedEvent(
            timestamp=timestamp,
            source_ip=None,
            username=None,
            event_type="ssh_other",
            log_source="auth",
            raw_line=line,
        )

    # ── helpers ──────────────────────────────────────────────────────────────
    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Convert syslog-style timestamp to datetime (assumes current year)."""
        try:
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
            return dt.replace(year=self._current_year)
        except ValueError:
            return datetime.now()
