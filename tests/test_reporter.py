"""Tests for the Rich reporter module."""

import json
from datetime import datetime

from src.models import Threat, ThreatLevel
from src.reporter import render_json, render_table


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


class TestRenderTable:
    def test_contains_source_ips(self) -> None:
        """Output contains each threat's source IP."""
        threats = [
            make_threat(ip="10.0.0.1"),
            make_threat(ip="10.0.0.2"),
            make_threat(ip="10.0.0.3"),
        ]
        output = render_table(threats)
        assert "10.0.0.1" in output
        assert "10.0.0.2" in output
        assert "10.0.0.3" in output

    def test_empty_list_shows_no_threats(self) -> None:
        """Empty threat list outputs a 'No threats detected' message."""
        output = render_table([])
        assert "No threats detected" in output

    def test_critical_threat_shows_critical(self) -> None:
        """CRITICAL level threat shows 'CRITICAL' in output."""
        output = render_table([make_threat(level=ThreatLevel.CRITICAL)])
        assert "CRITICAL" in output

    def test_high_threat_shows_high(self) -> None:
        """HIGH level threat shows 'HIGH' in output."""
        output = render_table([make_threat(level=ThreatLevel.HIGH)])
        assert "HIGH" in output

    def test_returns_string(self) -> None:
        """render_table returns a str, not None."""
        result = render_table([make_threat()])
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_threat_type(self) -> None:
        """Output contains the threat type."""
        output = render_table([make_threat(threat_type="port_scan")])
        assert "port_scan" in output

    def test_contains_count(self) -> None:
        """Output contains the threat count."""
        output = render_table([make_threat(count=42)])
        assert "42" in output


class TestRenderJson:
    def test_returns_valid_json(self) -> None:
        """Output is valid JSON."""
        output = render_json([make_threat()])
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_empty_list_returns_empty_array(self) -> None:
        """Empty input returns a valid empty JSON array."""
        assert json.loads(render_json([])) == []

    def test_contains_required_fields(self) -> None:
        """Each JSON object contains all required fields."""
        parsed = json.loads(render_json([make_threat(level=ThreatLevel.CRITICAL, count=20)]))
        item = parsed[0]
        assert item["level"] == "CRITICAL"
        assert item["threat_type"] == "brute_force"
        assert item["source_ip"] == "1.2.3.4"
        assert "description" in item
        assert item["count"] == 20
        assert "first_seen" in item
        assert "last_seen" in item

    def test_multiple_threats_all_included(self) -> None:
        """All threats appear in the JSON output."""
        threats = [make_threat(ip="1.1.1.1"), make_threat(ip="2.2.2.2")]
        parsed = json.loads(render_json(threats))
        assert len(parsed) == 2
        ips = {item["source_ip"] for item in parsed}
        assert ips == {"1.1.1.1", "2.2.2.2"}

    def test_high_level_label(self) -> None:
        """HIGH level is serialised as the string 'HIGH'."""
        parsed = json.loads(render_json([make_threat(level=ThreatLevel.HIGH)]))
        assert parsed[0]["level"] == "HIGH"
