"""Detector for port scanning patterns."""

import re
from collections import defaultdict
from datetime import timedelta

from src.detectors.base import BaseDetector
from src.models import LogEntry, Threat, ThreatLevel

_PORT_RE = re.compile(r"\bport[=\s]+(\d+)", re.IGNORECASE)


class PortScanDetector(BaseDetector):
    """Detects IPs hitting many distinct ports in a short time window."""

    def analyze(self, entries: list[LogEntry]) -> list[Threat]:
        """Detect port scanning behaviour.

        Args:
            entries: Parsed log entries.

        Returns:
            A Threat for each IP hitting >= min_distinct_ports unique ports in the window.
        """
        window = timedelta(seconds=self._config.port_scan_window_seconds)
        threshold = self._config.port_scan_min_distinct_ports

        by_ip: dict[str, list[tuple[int, LogEntry]]] = defaultdict(list)
        for entry in entries:
            if entry.source_ip is None:
                continue
            if entry.source_ip in self._config.whitelist_ips:
                continue
            port = self._extract_port(entry.raw_line)
            if port is not None:
                by_ip[entry.source_ip].append((port, entry))

        threats: list[Threat] = []
        for ip, port_entries in by_ip.items():
            port_entries = sorted(port_entries, key=lambda x: x[1].timestamp)
            max_ports, span = self._max_distinct_ports_in_window(port_entries, window)
            if max_ports >= threshold and span:
                first, last = span
                threats.append(
                    Threat(
                        level=ThreatLevel.HIGH,
                        threat_type="port_scan",
                        source_ip=ip,
                        description=(
                            f"{max_ports} distinct ports probed by {ip} within "
                            f"{self._config.port_scan_window_seconds}s"
                        ),
                        count=max_ports,
                        first_seen=first,
                        last_seen=last,
                    )
                )
        return threats

    @staticmethod
    def _extract_port(text: str) -> int | None:
        """Extract a port number from a raw log line."""
        m = _PORT_RE.search(text)
        return int(m.group(1)) if m else None

    @staticmethod
    def _max_distinct_ports_in_window(
        port_entries: list[tuple[int, LogEntry]],
        window: timedelta,
    ) -> tuple[int, tuple | None]:
        """Sliding-window: find max distinct ports within any window span.

        Returns:
            Tuple of (max_distinct_port_count, (first_ts, last_ts)) or (0, None).
        """
        if not port_entries:
            return 0, None

        best = 0
        best_span: tuple | None = None
        left = 0

        for right in range(len(port_entries)):
            while (
                port_entries[right][1].timestamp - port_entries[left][1].timestamp > window
            ):
                left += 1
            window_ports = {p for p, _ in port_entries[left : right + 1]}
            if len(window_ports) > best:
                best = len(window_ports)
                best_span = (
                    port_entries[left][1].timestamp,
                    port_entries[right][1].timestamp,
                )

        return best, best_span
