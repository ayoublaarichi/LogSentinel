"""
Abstract base class for all log parsers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class ParsedEvent:
    """Intermediate representation of a parsed log line."""

    timestamp: datetime
    source_ip: Optional[str]
    username: Optional[str]
    event_type: str
    log_source: str  # "auth" or "nginx"
    raw_line: str


class BaseParser(ABC):
    """Interface that every log parser must implement."""

    @abstractmethod
    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse a single log line. Returns None if the line is not recognised."""
        ...

    def parse_file(self, content: str) -> list[ParsedEvent]:
        """Parse an entire file and return a list of events, skipping bad lines."""
        events: list[ParsedEvent] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            event = self.parse_line(line)
            if event is not None:
                events.append(event)
        return events
