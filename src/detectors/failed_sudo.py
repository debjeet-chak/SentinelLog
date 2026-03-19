"""Detector for repeated failed sudo attempts."""

import re
from collections import defaultdict
from datetime import timedelta

from src.detectors.base import BaseDetector
from src.models import LogEntry, Threat, ThreatLevel

_SUDO_FAIL_RE = re.compile(r"authentication failure", re.IGNORECASE)


class FailedSudoDetector(BaseDetector):
    """Detects repeated sudo authentication failures for a single user."""

    def analyze(self, entries: list[LogEntry]) -> list[Threat]:
        """Detect repeated failed sudo attempts.

        Args:
            entries: Parsed log entries.

        Returns:
            A Threat for each user exceeding the sudo failure threshold.
        """
        window = timedelta(seconds=self._config.failed_sudo_window_seconds)
        threshold = self._config.failed_sudo_max_failures

        failures: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.username is None:
                continue
            if entry.username in self._config.whitelist_users:
                continue
            if _SUDO_FAIL_RE.search(entry.message):
                failures[entry.username].append(entry)

        threats: list[Threat] = []
        for username, user_entries in failures.items():
            user_entries = sorted(user_entries, key=lambda e: e.timestamp)
            max_count = self._max_in_window(user_entries, window)
            if max_count >= threshold:
                threats.append(
                    Threat(
                        level=ThreatLevel.MEDIUM,
                        threat_type="failed_sudo",
                        source_ip=None,
                        description=(
                            f"{max_count} failed sudo attempts by '{username}' "
                            f"within {self._config.failed_sudo_window_seconds}s"
                        ),
                        count=max_count,
                        first_seen=user_entries[0].timestamp,
                        last_seen=user_entries[-1].timestamp,
                        username=username,
                    )
                )
        return threats

    @staticmethod
    def _max_in_window(entries: list[LogEntry], window: timedelta) -> int:
        """Sliding-window count: max entries within any window-length span."""
        if not entries:
            return 0
        max_count = 0
        left = 0
        for right in range(len(entries)):
            while entries[right].timestamp - entries[left].timestamp > window:
                left += 1
            max_count = max(max_count, right - left + 1)
        return max_count
