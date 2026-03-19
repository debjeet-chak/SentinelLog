"""Tests for the Rich reporter module."""

import json
from datetime import datetime
from io import StringIO

import pytest

from src.models import Threat, ThreatLevel
from src.reporter import Reporter, format_threats_json


def make_threat(
    level: ThreatLevel = ThreatLevel.HIGH,
    threat_type: str = "brute_force",
    ip: str = "1.2.3.4",
    count: int = 7,
) -> Threat:
    return Threat(
        level=level,
        threat_type=threat_type,
        source_ip=ip,
        description=f"{count} failed logins from {ip}",
        count=count,
        first_seen=datetime(2024, 1, 15, 10, 0, 0),
        last_seen=datetime(2024, 1, 15, 10, 1, 0),
    )


class TestFormatThreatsJson:
    def test_returns_valid_json(self) -> None:
        """Output is valid JSON."""
        threats = [make_threat()]
        output = format_threats_json(threats)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_json_contains_expected_fields(self) -> None:
        """Each JSON object has the required fields."""
        threats = [make_threat(level=ThreatLevel.CRITICAL, count=20)]
        parsed = json.loads(format_threats_json(threats))
        item = parsed[0]
        assert "level" in item
        assert "threat_type" in item
        assert "source_ip" in item
        assert "description" in item
        assert "count" in item
        assert item["count"] == 20
        assert item["level"] == "CRITICAL"

    def test_empty_list(self) -> None:
        """Returns an empty JSON array for no threats."""
        output = format_threats_json([])
        assert json.loads(output) == []

    def test_multiple_threats(self) -> None:
        """Multiple threats are all included."""
        threats = [make_threat(ip="1.1.1.1"), make_threat(ip="2.2.2.2")]
        parsed = json.loads(format_threats_json(threats))
        assert len(parsed) == 2


class TestReporter:
    def test_reporter_instantiates(self) -> None:
        """Reporter can be created without error."""
        reporter = Reporter()
        assert reporter is not None

    def test_print_table_no_threats(self, capsys: pytest.CaptureFixture) -> None:
        """Printing an empty threat list produces output without errors."""
        reporter = Reporter()
        reporter.print_table([])  # Should not raise

    def test_print_table_with_threats(self, capsys: pytest.CaptureFixture) -> None:
        """Printing threats produces output without raising."""
        reporter = Reporter()
        reporter.print_table([make_threat(), make_threat(level=ThreatLevel.CRITICAL)])
