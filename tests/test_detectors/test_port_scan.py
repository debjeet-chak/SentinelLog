"""Tests for the port scan detector."""

from datetime import datetime, timedelta

import pytest

from src.config import Config
from src.detectors.port_scan import PortScanDetector
from src.models import LogEntry, ThreatLevel


def make_entry(
    ip: str,
    port: int,
    offset_seconds: int = 0,
    base: datetime | None = None,
) -> LogEntry:
    base = base or datetime(2024, 1, 15, 8, 0, 0)
    return LogEntry(
        timestamp=base + timedelta(seconds=offset_seconds),
        source_ip=ip,
        username=None,
        message=f"Connection attempt from {ip} port {port}",
        raw_line=f"raw port={port}",
    )


def make_config(min_ports: int = 5, window: int = 60) -> Config:
    return Config(
        brute_force_max_failures=5,
        brute_force_window_seconds=60,
        suspicious_ip_max_requests=100,
        suspicious_ip_window_seconds=300,
        failed_sudo_max_failures=3,
        failed_sudo_window_seconds=120,
        port_scan_min_distinct_ports=min_ports,
        port_scan_window_seconds=window,
        whitelist_ips=[],
        whitelist_users=[],
    )


class TestPortScanDetector:
    def test_detects_port_scan(self) -> None:
        """Flags an IP hitting >= min_distinct_ports unique ports in the window."""
        config = make_config(min_ports=5, window=60)
        detector = PortScanDetector(config)
        entries = [make_entry("3.3.3.3", port=1000 + i, offset_seconds=i * 5) for i in range(5)]
        threats = detector.analyze(entries)
        assert len(threats) == 1
        assert threats[0].source_ip == "3.3.3.3"
        assert threats[0].threat_type == "port_scan"
        assert threats[0].level == ThreatLevel.HIGH

    def test_no_threat_few_ports(self) -> None:
        """Does not flag an IP hitting fewer ports than the threshold."""
        detector = PortScanDetector(make_config(min_ports=5))
        entries = [make_entry("4.4.4.4", port=2000 + i, offset_seconds=i * 5) for i in range(4)]
        assert detector.analyze(entries) == []

    def test_repeated_same_port_not_counted(self) -> None:
        """Hitting the same port many times does not count as port scanning."""
        detector = PortScanDetector(make_config(min_ports=5))
        entries = [make_entry("8.8.8.8", port=80, offset_seconds=i) for i in range(10)]
        assert detector.analyze(entries) == []

    def test_whitelisted_ip_ignored(self) -> None:
        """Whitelisted IPs are not flagged for port scanning."""
        config = Config(
            brute_force_max_failures=5,
            brute_force_window_seconds=60,
            suspicious_ip_max_requests=100,
            suspicious_ip_window_seconds=300,
            failed_sudo_max_failures=3,
            failed_sudo_window_seconds=120,
            port_scan_min_distinct_ports=3,
            port_scan_window_seconds=60,
            whitelist_ips=["2.2.2.2"],
            whitelist_users=[],
        )
        detector = PortScanDetector(config)
        entries = [make_entry("2.2.2.2", port=100 + i, offset_seconds=i) for i in range(10)]
        assert detector.analyze(entries) == []

    def test_port_extracted_from_message(self) -> None:
        """Detector extracts port number from the message text."""
        detector = PortScanDetector(make_config(min_ports=3, window=60))
        entries = [make_entry("9.9.9.1", port=3000 + i, offset_seconds=i * 2) for i in range(3)]
        threats = detector.analyze(entries)
        assert len(threats) == 1

    def test_empty_input(self) -> None:
        """Returns empty list for empty input."""
        assert PortScanDetector(make_config()).analyze([]) == []
