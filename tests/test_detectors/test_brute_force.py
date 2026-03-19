"""Tests for the brute-force login detector."""

from datetime import datetime, timedelta

from src.config import Config
from src.detectors.brute_force import BruteForceDetector
from src.models import LogEntry, ThreatLevel


def make_entry(
    ip: str,
    username: str = "alice",
    message: str = "Failed password",
    offset_seconds: int = 0,
    base: datetime | None = None,
) -> LogEntry:
    base = base or datetime(2024, 1, 15, 10, 0, 0)
    return LogEntry(
        timestamp=base + timedelta(seconds=offset_seconds),
        source_ip=ip,
        username=username,
        message=message,
        raw_line="raw",
    )


def make_config(max_failures: int = 5, window: int = 60) -> Config:
    return Config(
        brute_force_max_failures=max_failures,
        brute_force_window_seconds=window,
        suspicious_ip_max_requests=100,
        suspicious_ip_window_seconds=300,
        failed_sudo_max_failures=3,
        failed_sudo_window_seconds=120,
        port_scan_min_distinct_ports=10,
        port_scan_window_seconds=60,
        whitelist_ips=[],
        whitelist_users=[],
    )


class TestBruteForceDetector:
    def test_detects_brute_force(self) -> None:
        """Flags an IP with >= max_failures failed logins within the window."""
        config = make_config(max_failures=5, window=60)
        detector = BruteForceDetector(config)
        entries = [
            make_entry("10.0.0.1", offset_seconds=i * 10, message="Failed password")
            for i in range(5)
        ]
        threats = detector.analyze(entries)
        assert len(threats) == 1
        assert threats[0].source_ip == "10.0.0.1"
        assert threats[0].level == ThreatLevel.HIGH
        assert threats[0].threat_type == "brute_force"
        assert threats[0].count == 5

    def test_no_threat_below_threshold(self) -> None:
        """Does not flag an IP below the failure threshold."""
        config = make_config(max_failures=5, window=60)
        detector = BruteForceDetector(config)
        entries = [
            make_entry("10.0.0.2", offset_seconds=i * 10, message="Failed password")
            for i in range(4)
        ]
        threats = detector.analyze(entries)
        assert threats == []

    def test_no_threat_outside_window(self) -> None:
        """Does not flag failures spread beyond the time window."""
        config = make_config(max_failures=5, window=60)
        detector = BruteForceDetector(config)
        entries = [
            make_entry("10.0.0.3", offset_seconds=i * 30, message="Failed password")
            for i in range(5)
        ]
        # Spread over 120 seconds — beyond 60s window
        threats = detector.analyze(entries)
        assert threats == []

    def test_ignores_non_failure_messages(self) -> None:
        """Only counts messages that look like authentication failures."""
        config = make_config(max_failures=5, window=60)
        detector = BruteForceDetector(config)
        entries = [
            make_entry("10.0.0.4", offset_seconds=i, message="Accepted password")
            for i in range(10)
        ]
        threats = detector.analyze(entries)
        assert threats == []

    def test_sudo_auth_failure_does_not_trigger_brute_force(self) -> None:
        """sudo 'authentication failure' messages do not count as SSH brute force."""
        detector = BruteForceDetector(make_config(max_failures=3, window=60))
        entries = [
            make_entry(
                "10.0.0.6",
                offset_seconds=i * 5,
                message="pam_unix(sudo:auth): authentication failure; user=alice",
            )
            for i in range(5)
        ]
        # The BruteForceDetector should not fire on sudo-specific messages
        threats = detector.analyze(entries)
        assert threats == []

    def test_whitelisted_ip_ignored(self) -> None:
        """Does not flag IPs in the whitelist."""
        config = Config(
            brute_force_max_failures=5,
            brute_force_window_seconds=60,
            suspicious_ip_max_requests=100,
            suspicious_ip_window_seconds=300,
            failed_sudo_max_failures=3,
            failed_sudo_window_seconds=120,
            port_scan_min_distinct_ports=10,
            port_scan_window_seconds=60,
            whitelist_ips=["10.0.0.5"],
            whitelist_users=[],
        )
        detector = BruteForceDetector(config)
        entries = [
            make_entry("10.0.0.5", offset_seconds=i * 5, message="Failed password")
            for i in range(10)
        ]
        threats = detector.analyze(entries)
        assert threats == []

    def test_cidr_whitelisted_ip_ignored(self) -> None:
        """IPs within a whitelisted CIDR range are not flagged."""
        config = Config(
            brute_force_max_failures=3,
            brute_force_window_seconds=60,
            suspicious_ip_max_requests=100,
            suspicious_ip_window_seconds=300,
            failed_sudo_max_failures=3,
            failed_sudo_window_seconds=120,
            port_scan_min_distinct_ports=10,
            port_scan_window_seconds=60,
            whitelist_ips=["10.0.0.0/24"],
            whitelist_users=[],
        )
        detector = BruteForceDetector(config)
        entries = [
            make_entry("10.0.0.50", offset_seconds=i * 5, message="Failed password")
            for i in range(5)
        ]
        assert detector.analyze(entries) == []

    def test_multiple_ips_independent(self) -> None:
        """Each IP is assessed independently; only those over threshold flagged."""
        config = make_config(max_failures=3, window=60)
        detector = BruteForceDetector(config)
        entries = (
            [make_entry("1.1.1.1", offset_seconds=i * 5, message="Failed password") for i in range(3)]
            + [make_entry("2.2.2.2", offset_seconds=i * 5, message="Failed password") for i in range(2)]
        )
        threats = detector.analyze(entries)
        flagged_ips = {t.source_ip for t in threats}
        assert "1.1.1.1" in flagged_ips
        assert "2.2.2.2" not in flagged_ips

    def test_critical_level_at_double_threshold(self) -> None:
        """Escalates to CRITICAL when failures reach 2x the threshold."""
        config = make_config(max_failures=5, window=120)
        detector = BruteForceDetector(config)
        entries = [
            make_entry("9.9.9.9", offset_seconds=i * 5, message="Failed password")
            for i in range(10)
        ]
        threats = detector.analyze(entries)
        assert len(threats) == 1
        assert threats[0].level == ThreatLevel.CRITICAL

    def test_first_last_seen_reflect_triggering_window(self) -> None:
        """first_seen and last_seen bound the burst window, not the full IP history."""
        base = datetime(2024, 1, 15, 10, 0, 0)
        config = make_config(max_failures=3, window=60)
        detector = BruteForceDetector(config)
        # 2 old failures — won't trigger on their own
        old = [make_entry("10.0.0.9", offset_seconds=i * 5, message="Failed password", base=base) for i in range(2)]
        # 5-minute gap, then a burst of 3 within 20 seconds
        burst_base = base + timedelta(minutes=5)
        burst = [make_entry("10.0.0.9", offset_seconds=i * 10, message="Failed password", base=burst_base) for i in range(3)]
        threats = detector.analyze(old + burst)
        assert len(threats) == 1
        assert threats[0].first_seen >= burst_base
        assert threats[0].last_seen == burst_base + timedelta(seconds=20)

    def test_empty_entries(self) -> None:
        """Returns empty list for empty input."""
        detector = BruteForceDetector(make_config())
        assert detector.analyze([]) == []
