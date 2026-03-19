"""Detector for SSH/login brute-force attempts."""

import re
from collections import defaultdict
from datetime import timedelta

from src.config import Config
from src.detectors.base import BaseDetector
from src.models import LogEntry, Threat, ThreatLevel

_FAILURE_PATTERNS = re.compile(
    r"Failed password|authentication failure|Invalid user",
    re.IGNORECASE,
)


class BruteForceDetector(BaseDetector):
    """Detects repeated authentication failures from a single IP."""

    def analyze(self, entries: list[LogEntry]) -> list[Threat]:
        """Detect brute-force login attempts.

        Args:
            entries: Parsed log entries.

        Returns:
            A Threat for each IP that exceeds the failure threshold within the window.
        """
        window = timedelta(seconds=self._config.brute_force_window_seconds)
        threshold = self._config.brute_force_max_failures

        # Group failure entries by source IP
        failures: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.source_ip is None:
                continue
            if entry.source_ip in self._config.whitelist_ips:
                continue
            if _FAILURE_PATTERNS.search(entry.message):
                failures[entry.source_ip].append(entry)

        threats: list[Threat] = []
        for ip, ip_entries in failures.items():
            ip_entries = sorted(ip_entries, key=lambda e: e.timestamp)
            max_window_count = self._max_in_window(ip_entries, window)
            if max_window_count >= threshold:
                level = (
                    ThreatLevel.CRITICAL
                    if max_window_count >= threshold * 2
                    else ThreatLevel.HIGH
                )
                threats.append(
                    Threat(
                        level=level,
                        threat_type="brute_force",
                        source_ip=ip,
                        description=(
                            f"{max_window_count} failed login attempts within "
                            f"{self._config.brute_force_window_seconds}s"
                        ),
                        count=max_window_count,
                        first_seen=ip_entries[0].timestamp,
                        last_seen=ip_entries[-1].timestamp,
                    )
                )
        return threats

    @staticmethod
    def _max_in_window(entries: list[LogEntry], window: timedelta) -> int:
        """Sliding-window count: return the maximum number of entries within any window."""
        if not entries:
            return 0
        max_count = 0
        left = 0
        for right in range(len(entries)):
            while entries[right].timestamp - entries[left].timestamp > window:
                left += 1
            max_count = max(max_count, right - left + 1)
        return max_count
