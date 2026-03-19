"""Parser for /var/log/auth.log format (Debian/Ubuntu SSH + sudo)."""

import re
from datetime import datetime

from src.models import LogEntry
from src.parsers.base import BaseParser

# Matches: "Jan 15 10:00:01 hostname process[pid]: message"
_HEADER_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+\S+:\s+(?P<message>.+)$"
)

# SSH: "Failed password for [invalid user] <user> from <ip> port <port> ..."
_SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port"
)

# SSH: "Accepted (password|publickey) for <user> from <ip> ..."
_SSH_ACCEPT_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)"
)

# SSH: "Invalid user <user> from <ip>"
_SSH_INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)

# sudo: "authentication failure; ... user=<user>"
_SUDO_FAIL_RE = re.compile(
    r"authentication failure;.*\buser=(?P<user>\S+)"
)

# sudo: "<user> : ... COMMAND=..."
_SUDO_CMD_RE = re.compile(
    r"^(?P<user>\S+)\s+:\s+TTY="
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_PATTERNS = [
    _SSH_FAIL_RE,
    _SSH_ACCEPT_RE,
    _SSH_INVALID_RE,
    _SUDO_FAIL_RE,
    _SUDO_CMD_RE,
]


class AuthLogParser(BaseParser):
    """Parser for the auth.log format used by Debian/Ubuntu systems."""

    def __init__(self, year: int | None = None) -> None:
        """Initialise the parser.

        Args:
            year: The calendar year to use when constructing timestamps
                  (auth.log omits the year). Defaults to the current year.
        """
        self._year = year or datetime.now().year

    def parse_line(self, line: str) -> LogEntry | None:
        """Parse a single auth.log line.

        Args:
            line: A raw auth.log line.

        Returns:
            A LogEntry if the line matches a known pattern, else None.
        """
        if not line.strip():
            return None

        header = _HEADER_RE.match(line)
        if not header:
            return None

        message = header.group("message")

        # Check if message matches any interesting pattern
        matched = any(p.search(message) for p in _PATTERNS)
        if not matched:
            return None

        timestamp = self._parse_timestamp(
            header.group("month"),
            header.group("day"),
            header.group("time"),
        )

        source_ip, username = self._extract_fields(message)

        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            username=username,
            message=message,
            raw_line=line,
        )

    def _parse_timestamp(self, month_str: str, day_str: str, time_str: str) -> datetime:
        """Build a datetime from auth.log header components."""
        month = _MONTH_MAP.get(month_str, 1)
        day = int(day_str)
        h, m, s = (int(x) for x in time_str.split(":"))
        return datetime(self._year, month, day, h, m, s)

    def _extract_fields(self, message: str) -> tuple[str | None, str | None]:
        """Extract source IP and username from a message string."""
        for pattern in [_SSH_FAIL_RE, _SSH_ACCEPT_RE, _SSH_INVALID_RE]:
            m = pattern.search(message)
            if m:
                return m.group("ip"), m.group("user")

        m = _SUDO_FAIL_RE.search(message)
        if m:
            return None, m.group("user")

        m = _SUDO_CMD_RE.search(message)
        if m:
            return None, m.group("user")

        return None, None
