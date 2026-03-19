"""Abstract base class for threat detectors."""

import ipaddress
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from src.config import Config
from src.models import LogEntry, Threat


class BaseDetector(ABC):
    """Abstract base detector — subclasses implement specific threat patterns."""

    def __init__(self, config: Config) -> None:
        """Initialise with shared configuration.

        Args:
            config: Loaded SentinelLog configuration.
        """
        self._config = config

    @abstractmethod
    def analyze(self, entries: list[LogEntry]) -> list[Threat]:
        """Analyze log entries and return any detected threats.

        Args:
            entries: Parsed log entries to analyze.

        Returns:
            List of Threat objects (empty if none detected).
        """

    @staticmethod
    def _max_in_window(
        entries: list[LogEntry],
        window: timedelta,
    ) -> tuple[int, datetime | None, datetime | None]:
        """Sliding-window count over timestamp-sorted entries.

        Uses an inclusive window: events exactly ``window`` seconds apart are
        both counted (i.e. the window is [t_left, t_left + window]).

        Args:
            entries: Log entries sorted by timestamp ascending. Callers are
                     responsible for sorting — passing unsorted input produces
                     incorrect results.
            window: Maximum time span of the window.

        Returns:
            A (max_count, first_seen, last_seen) triple for the window that
            contained the most entries. first_seen and last_seen are None only
            when entries is empty.
        """
        if not entries:
            return 0, None, None

        max_count = 0
        first_seen: datetime | None = None
        last_seen: datetime | None = None
        left = 0

        for right in range(len(entries)):
            while entries[right].timestamp - entries[left].timestamp > window:
                left += 1
            count = right - left + 1
            if count > max_count:
                max_count = count
                first_seen = entries[left].timestamp
                last_seen = entries[right].timestamp

        return max_count, first_seen, last_seen

    @staticmethod
    def _is_whitelisted_ip(ip: str, whitelist: list[str]) -> bool:
        """Check whether an IP address is covered by the whitelist.

        Supports both exact IP strings (``"10.0.0.1"``) and CIDR notation
        (``"192.168.1.0/24"``). Invalid entries in the whitelist are silently
        skipped.

        Args:
            ip: The source IP address to check.
            whitelist: List of exact IPs or CIDR ranges from config.

        Returns:
            True if the IP matches any whitelist entry.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for entry in whitelist:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue

        return False
