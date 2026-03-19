"""Tests for the failed sudo detector."""

from datetime import datetime, timedelta

import pytest

from src.config import Config
from src.detectors.failed_sudo import FailedSudoDetector
from src.models import LogEntry, ThreatLevel


def make_sudo_entry(
    username: str,
    offset_seconds: int = 0,
    message: str = "authentication failure",
    base: datetime | None = None,
) -> LogEntry:
    base = base or datetime(2024, 1, 15, 12, 0, 0)
    return LogEntry(
        timestamp=base + timedelta(seconds=offset_seconds),
        source_ip=None,
        username=username,
        message=message,
        raw_line="raw",
    )


def make_config(max_failures: int = 3, window: int = 120) -> Config:
    return Config(
        brute_force_max_failures=5,
        brute_force_window_seconds=60,
        suspicious_ip_max_requests=100,
        suspicious_ip_window_seconds=300,
        failed_sudo_max_failures=max_failures,
        failed_sudo_window_seconds=window,
        port_scan_min_distinct_ports=10,
        port_scan_window_seconds=60,
        whitelist_ips=[],
        whitelist_users=[],
    )


class TestFailedSudoDetector:
    def test_detects_failed_sudo(self) -> None:
        """Flags user with >= max_failures sudo failures in the window."""
        config = make_config(max_failures=3, window=120)
        detector = FailedSudoDetector(config)
        entries = [
            make_sudo_entry("bob", offset_seconds=i * 20)
            for i in range(3)
        ]
        threats = detector.analyze(entries)
        assert len(threats) == 1
        assert threats[0].username == "bob"
        assert threats[0].threat_type == "failed_sudo"
        assert threats[0].level == ThreatLevel.MEDIUM

    def test_no_threat_below_threshold(self) -> None:
        """Does not flag users below the failure threshold."""
        detector = FailedSudoDetector(make_config(max_failures=3))
        entries = [make_sudo_entry("alice", offset_seconds=i * 20) for i in range(2)]
        assert detector.analyze(entries) == []

    def test_ignores_whitelisted_user(self) -> None:
        """Does not flag users in the whitelist."""
        config = Config(
            brute_force_max_failures=5,
            brute_force_window_seconds=60,
            suspicious_ip_max_requests=100,
            suspicious_ip_window_seconds=300,
            failed_sudo_max_failures=3,
            failed_sudo_window_seconds=120,
            port_scan_min_distinct_ports=10,
            port_scan_window_seconds=60,
            whitelist_ips=[],
            whitelist_users=["admin"],
        )
        detector = FailedSudoDetector(config)
        entries = [make_sudo_entry("admin", offset_seconds=i * 10) for i in range(5)]
        assert detector.analyze(entries) == []

    def test_ignores_non_sudo_messages(self) -> None:
        """Does not count SSH or other non-sudo messages."""
        detector = FailedSudoDetector(make_config(max_failures=3))
        entries = [
            make_sudo_entry("carol", offset_seconds=i, message="Failed password ssh")
            for i in range(5)
        ]
        assert detector.analyze(entries) == []

    def test_entries_without_username_skipped(self) -> None:
        """Entries with no username are skipped gracefully."""
        detector = FailedSudoDetector(make_config())
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="1.2.3.4",
            username=None,
            message="authentication failure",
            raw_line="raw",
        )
        assert detector.analyze([entry]) == []

    def test_empty_input(self) -> None:
        """Returns empty list for empty input."""
        assert FailedSudoDetector(make_config()).analyze([]) == []
