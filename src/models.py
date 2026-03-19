"""Core data models for SentinelLog."""

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum


class ThreatLevel(IntEnum):
    """Severity levels for detected threats, ordered low to high."""

    INFO = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class LogEntry:
    """A single parsed log line."""

    timestamp: datetime
    source_ip: str | None
    username: str | None
    message: str
    raw_line: str


@dataclass(frozen=True)
class Threat:
    """A detected threat pattern aggregated from one or more log entries."""

    level: ThreatLevel
    threat_type: str
    source_ip: str | None
    description: str
    count: int
    first_seen: datetime
    last_seen: datetime
    username: str | None = None
