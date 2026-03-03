"""
Parser for Nginx combined/common access log format.

Expected format (combined):
  <ip> - <user> [<timestamp>] "<method> <path> <proto>" <status> <bytes> "<referer>" "<ua>"
"""

import re
from datetime import datetime
from typing import Optional

from app.parsers.base import BaseParser, ParsedEvent

# ── Regex ────────────────────────────────────────────────────────────────────
_NGINX_COMBINED = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'           # client IP
    r'(?P<ident>\S+)\s+'                           # ident (usually -)
    r'(?P<user>\S+)\s+'                            # remote user
    r'\[(?P<timestamp>[^\]]+)\]\s+'                # [dd/Mon/yyyy:HH:MM:SS +/-zone]
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+' # "METHOD /path HTTP/x.x"
    r'(?P<status>\d{3})\s+'                        # status code
    r'(?P<bytes>\d+|-)\s*'                         # bytes sent
    r'(?:"(?P<referer>[^"]*)"\s*)?'                # referer (optional)
    r'(?:"(?P<ua>[^"]*)")?'                        # user agent (optional)
)

_TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S %z"


class NginxAccessParser(BaseParser):
    """Parses Nginx combined / common access log entries."""

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse a single access-log line into a structured event."""
        m = _NGINX_COMBINED.match(line)
        if not m:
            return None

        timestamp = self._parse_timestamp(m.group("timestamp"))
        status = int(m.group("status"))
        user_raw = m.group("user")
        username = user_raw if user_raw != "-" else None

        event_type = self._classify_status(status)

        return ParsedEvent(
            timestamp=timestamp,
            source_ip=m.group("ip"),
            username=username,
            event_type=event_type,
            log_source="nginx",
            raw_line=line,
        )

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        """Parse Nginx timestamp into a timezone-aware datetime."""
        try:
            return datetime.strptime(ts_str, _TIMESTAMP_FMT).replace(tzinfo=None)
        except ValueError:
            return datetime.now()

    @staticmethod
    def _classify_status(status: int) -> str:
        """Map HTTP status code to a human-friendly event type."""
        if status < 400:
            return "http_ok"
        if status < 500:
            return "http_client_error"
        return "http_server_error"
