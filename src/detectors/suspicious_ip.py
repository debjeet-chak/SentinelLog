"""Detector for high-frequency activity from a single IP."""

from collections import defaultdict
from datetime import timedelta

from src.detectors.base import BaseDetector
from src.models import LogEntry, Threat, ThreatLevel


class SuspiciousIPDetector(BaseDetector):
    """Detects IPs that generate an unusually high number of log entries."""

    def analyze(self, entries: list[LogEntry]) -> list[Threat]:
        """Detect IPs with request frequency above the configured threshold.

        Args:
            entries: Parsed log entries.

        Returns:
            A Threat for each IP exceeding the request-rate threshold.
        """
        window = timedelta(seconds=self._config.suspicious_ip_window_seconds)
        threshold = self._config.suspicious_ip_max_requests

        by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.source_ip is None:
                continue
            if entry.source_ip in self._config.whitelist_ips:
                continue
            by_ip[entry.source_ip].append(entry)

        threats: list[Threat] = []
        for ip, ip_entries in by_ip.items():
            ip_entries = sorted(ip_entries, key=lambda e: e.timestamp)
            max_count = self._max_in_window(ip_entries, window)
            if max_count >= threshold:
                threats.append(
                    Threat(
                        level=ThreatLevel.MEDIUM,
                        threat_type="suspicious_ip",
                        source_ip=ip,
                        description=(
                            f"{max_count} requests from {ip} within "
                            f"{self._config.suspicious_ip_window_seconds}s"
                        ),
                        count=max_count,
                        first_seen=ip_entries[0].timestamp,
                        last_seen=ip_entries[-1].timestamp,
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
