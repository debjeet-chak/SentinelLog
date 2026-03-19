"""Tests for the suspicious IP detector."""

from datetime import datetime, timedelta

import pytest

from src.config import Config
from src.detectors.suspicious_ip import SuspiciousIPDetector
from src.models import LogEntry, ThreatLevel


def make_entry(
    ip: str,
    offset_seconds: int = 0,
    message: str = "some log message",
    base: datetime | None = None,
) -> LogEntry:
    base = base or datetime(2024, 1, 15, 9, 0, 0)
    return LogEntry(
        timestamp=base + timedelta(seconds=offset_seconds),
        source_ip=ip,
        username=None,
        message=message,
        raw_line="raw",
    )


def make_config(max_requests: int = 10, window: int = 300) -> Config:
    return Config(
        brute_force_max_failures=5,
        brute_force_window_seconds=60,
        suspicious_ip_max_requests=max_requests,
        suspicious_ip_window_seconds=window,
        failed_sudo_max_failures=3,
        failed_sudo_window_seconds=120,
        port_scan_min_distinct_ports=10,
        port_scan_window_seconds=60,
        whitelist_ips=[],
        whitelist_users=[],
    )


class TestSuspiciousIPDetector:
    def test_detects_high_frequency_ip(self) -> None:
        """Flags an IP exceeding the request-frequency threshold."""
        config = make_config(max_requests=5, window=300)
        detector = SuspiciousIPDetector(config)
        entries = [make_entry("5.5.5.5", offset_seconds=i * 10) for i in range(6)]
        threats = detector.analyze(entries)
        assert len(threats) == 1
        assert threats[0].source_ip == "5.5.5.5"
        assert threats[0].threat_type == "suspicious_ip"

    def test_no_threat_below_threshold(self) -> None:
        """Does not flag an IP below the request threshold."""
        detector = SuspiciousIPDetector(make_config(max_requests=10))
        entries = [make_entry("6.6.6.6", offset_seconds=i * 10) for i in range(9)]
        assert detector.analyze(entries) == []

    def test_whitelisted_ip_not_flagged(self) -> None:
        """Whitelisted IPs are never flagged."""
        config = Config(
            brute_force_max_failures=5,
            brute_force_window_seconds=60,
            suspicious_ip_max_requests=5,
            suspicious_ip_window_seconds=300,
            failed_sudo_max_failures=3,
            failed_sudo_window_seconds=120,
            port_scan_min_distinct_ports=10,
            port_scan_window_seconds=60,
            whitelist_ips=["7.7.7.7"],
            whitelist_users=[],
        )
        detector = SuspiciousIPDetector(config)
        entries = [make_entry("7.7.7.7", offset_seconds=i) for i in range(20)]
        assert detector.analyze(entries) == []

    def test_entries_without_ip_skipped(self) -> None:
        """Entries with no source IP are skipped."""
        detector = SuspiciousIPDetector(make_config(max_requests=3))
        entries = [
            LogEntry(
                timestamp=datetime.now() + timedelta(seconds=i),
                source_ip=None,
                username="bob",
                message="sudo failure",
                raw_line="raw",
            )
            for i in range(10)
        ]
        assert detector.analyze(entries) == []

    def test_empty_input(self) -> None:
        """Returns empty list for empty input."""
        assert SuspiciousIPDetector(make_config()).analyze([]) == []
