"""Detector for high-frequency activity from a single IP.

Note: This detector counts all log entries from an IP regardless of message
content — including successful requests. It is intended to surface IPs that
are unusually noisy (scrapers, scanners, misbehaving clients). Legitimate
high-volume sources (load balancers, monitoring agents) should be whitelisted
in the config.
"""

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
            if self._is_whitelisted_ip(entry.source_ip, self._config.whitelist_ips):
                continue
            by_ip[entry.source_ip].append(entry)

        threats: list[Threat] = []
        for ip, ip_entries in by_ip.items():
            sorted_entries = sorted(ip_entries, key=lambda e: e.timestamp)
            max_count, first_seen, last_seen = self._max_in_window(sorted_entries, window)
            if max_count >= threshold:
                assert first_seen is not None and last_seen is not None
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
                        first_seen=first_seen,
                        last_seen=last_seen,
                    )
                )
        return threats
