"""Detector for SSH/login brute-force attempts."""

import re
from collections import defaultdict
from datetime import timedelta

from src.detectors.base import BaseDetector
from src.models import LogEntry, Threat, ThreatLevel

# Match SSH-specific failure messages only — sudo failures are handled by
# FailedSudoDetector and must not be double-counted here.
_FAILURE_PATTERNS = re.compile(
    r"Failed password|Invalid user",
    re.IGNORECASE,
)


class BruteForceDetector(BaseDetector):
    """Detects repeated SSH authentication failures from a single IP."""

    def analyze(self, entries: list[LogEntry]) -> list[Threat]:
        """Detect brute-force login attempts.

        Args:
            entries: Parsed log entries.

        Returns:
            A Threat for each IP that exceeds the failure threshold within the window.
        """
        window = timedelta(seconds=self._config.brute_force_window_seconds)
        threshold = self._config.brute_force_max_failures

        failures: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.source_ip is None:
                continue
            if self._is_whitelisted_ip(entry.source_ip, self._config.whitelist_ips):
                continue
            if _FAILURE_PATTERNS.search(entry.message):
                failures[entry.source_ip].append(entry)

        threats: list[Threat] = []
        for ip, ip_entries in failures.items():
            sorted_entries = sorted(ip_entries, key=lambda e: e.timestamp)
            max_count, first_seen, last_seen = self._max_in_window(sorted_entries, window)
            if max_count >= threshold:
                assert first_seen is not None and last_seen is not None
                level = (
                    ThreatLevel.CRITICAL
                    if max_count >= threshold * 2
                    else ThreatLevel.HIGH
                )
                threats.append(
                    Threat(
                        level=level,
                        threat_type="brute_force",
                        source_ip=ip,
                        description=(
                            f"{max_count} failed login attempts within "
                            f"{self._config.brute_force_window_seconds}s"
                        ),
                        count=max_count,
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                )
        return threats
