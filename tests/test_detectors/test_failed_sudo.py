"""Tests for the failed sudo detector."""

from datetime import datetime, timedelta

from src.config import Config
from src.detectors.failed_sudo import FailedSudoDetector
from src.models import LogEntry, ThreatLevel

# Realistic sudo failure message matching the tightened regex
_SUDO_MSG = "pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 user=bob"


def make_sudo_entry(
    username: str,
    offset_seconds: int = 0,
    message: str = _SUDO_MSG,
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

    def test_ignores_ssh_failure_messages(self) -> None:
        """Does not count SSH 'Failed password' messages — only sudo-specific patterns."""
        detector = FailedSudoDetector(make_config(max_failures=3))
        entries = [
            make_sudo_entry("carol", offset_seconds=i, message="Failed password for carol from 1.2.3.4 port 22 ssh2")
            for i in range(5)
        ]
        assert detector.analyze(entries) == []

    def test_ignores_bare_auth_failure_without_sudo_context(self) -> None:
        """A bare 'authentication failure' without pam_unix(sudo) does not trigger."""
        detector = FailedSudoDetector(make_config(max_failures=3))
        entries = [
            make_sudo_entry("dave", offset_seconds=i, message="authentication failure")
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
            message=_SUDO_MSG,
            raw_line="raw",
        )
        assert detector.analyze([entry]) == []

    def test_first_last_seen_reflect_triggering_window(self) -> None:
        """first_seen and last_seen bound the burst window, not the full user history."""
        base = datetime(2024, 1, 15, 12, 0, 0)
        config = make_config(max_failures=3, window=120)
        detector = FailedSudoDetector(config)
        # 2 old failures that won't trigger on their own
        old = [make_sudo_entry("eve", offset_seconds=i * 10, base=base) for i in range(2)]
        # 10-minute gap, then a burst of 3 within 30 seconds
        burst_base = base + timedelta(minutes=10)
        burst = [make_sudo_entry("eve", offset_seconds=i * 15, base=burst_base) for i in range(3)]
        threats = detector.analyze(old + burst)
        assert len(threats) == 1
        assert threats[0].first_seen >= burst_base
        assert threats[0].last_seen == burst_base + timedelta(seconds=30)

    def test_empty_input(self) -> None:
        """Returns empty list for empty input."""
        assert FailedSudoDetector(make_config()).analyze([]) == []
