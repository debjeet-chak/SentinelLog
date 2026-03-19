"""Tests for core data models."""

from datetime import datetime

import pytest

from src.models import LogEntry, Threat, ThreatLevel


class TestLogEntry:
    def test_create_log_entry(self) -> None:
        """LogEntry stores all required fields."""
        ts = datetime(2024, 1, 15, 10, 30, 0)
        entry = LogEntry(
            timestamp=ts,
            source_ip="192.168.1.10",
            username="alice",
            message="Failed password for alice from 192.168.1.10 port 22 ssh2",
            raw_line="Jan 15 10:30:00 host sshd[1234]: Failed password for alice",
        )
        assert entry.timestamp == ts
        assert entry.source_ip == "192.168.1.10"
        assert entry.username == "alice"
        assert "Failed password" in entry.message

    def test_log_entry_optional_fields(self) -> None:
        """LogEntry works with None for optional fields."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip=None,
            username=None,
            message="System rebooted",
            raw_line="Jan 15 10:00:00 host kernel: System rebooted",
        )
        assert entry.source_ip is None
        assert entry.username is None

    def test_log_entry_is_immutable(self) -> None:
        """LogEntry is a frozen dataclass."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="1.2.3.4",
            username="bob",
            message="test",
            raw_line="raw",
        )
        with pytest.raises(Exception):
            entry.source_ip = "5.6.7.8"  # type: ignore[misc]


class TestThreatLevel:
    def test_threat_levels_ordered(self) -> None:
        """ThreatLevel values are ordered by severity."""
        assert ThreatLevel.INFO.value < ThreatLevel.MEDIUM.value
        assert ThreatLevel.MEDIUM.value < ThreatLevel.HIGH.value
        assert ThreatLevel.HIGH.value < ThreatLevel.CRITICAL.value


class TestThreat:
    def test_create_threat(self) -> None:
        """Threat stores all required fields."""
        threat = Threat(
            level=ThreatLevel.HIGH,
            threat_type="brute_force",
            source_ip="10.0.0.5",
            description="5 failed SSH logins in 30 seconds",
            count=5,
            first_seen=datetime(2024, 1, 15, 10, 0, 0),
            last_seen=datetime(2024, 1, 15, 10, 0, 30),
        )
        assert threat.level == ThreatLevel.HIGH
        assert threat.threat_type == "brute_force"
        assert threat.count == 5

    def test_threat_optional_user(self) -> None:
        """Threat username is optional."""
        threat = Threat(
            level=ThreatLevel.MEDIUM,
            threat_type="suspicious_ip",
            source_ip="172.16.0.1",
            description="High request frequency",
            count=120,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            username=None,
        )
        assert threat.username is None
