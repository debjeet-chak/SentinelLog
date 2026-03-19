"""Tests for auth.log parser."""

from datetime import datetime
from pathlib import Path

import pytest

from src.parsers.auth_log import AuthLogParser


FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestAuthLogParserParseLine:
    def setup_method(self) -> None:
        self.parser = AuthLogParser(year=2024)

    def test_parses_failed_password(self) -> None:
        """Parses a failed SSH password line."""
        line = "Jan 15 10:00:01 webserver sshd[1001]: Failed password for alice from 192.168.1.10 port 52001 ssh2"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.source_ip == "192.168.1.10"
        assert entry.username == "alice"
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 15
        assert entry.timestamp.hour == 10
        assert "Failed password" in entry.message

    def test_parses_invalid_user(self) -> None:
        """Parses a failed SSH attempt for an invalid user."""
        line = "Jan 15 10:06:01 webserver sshd[1012]: Failed password for invalid user admin from 198.51.100.7 port 22 ssh2"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.source_ip == "198.51.100.7"
        assert entry.username == "admin"

    def test_parses_accepted_password(self) -> None:
        """Parses a successful SSH login."""
        line = "Jan 15 10:01:00 webserver sshd[1006]: Accepted password for bob from 10.0.0.5 port 48000 ssh2"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.source_ip == "10.0.0.5"
        assert entry.username == "bob"

    def test_parses_failed_sudo(self) -> None:
        """Parses a sudo authentication failure."""
        line = "Jan 15 10:05:02 webserver sudo[1009]: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.username == "alice"
        assert "authentication failure" in entry.message

    def test_returns_none_for_unrecognised_line(self) -> None:
        """Returns None for lines that don't match any known pattern."""
        line = "Jan 15 10:00:00 webserver kernel: [1234.567] some kernel message"
        entry = self.parser.parse_line(line)
        assert entry is None

    def test_returns_none_for_empty_line(self) -> None:
        """Returns None for empty or whitespace-only lines."""
        assert self.parser.parse_line("") is None
        assert self.parser.parse_line("   ") is None

    def test_raw_line_preserved(self) -> None:
        """The original raw line is stored on the entry."""
        line = "Jan 15 10:00:01 webserver sshd[1001]: Failed password for alice from 192.168.1.10 port 52001 ssh2"
        entry = self.parser.parse_line(line)
        assert entry is not None
        assert entry.raw_line == line


class TestAuthLogParserParseFile:
    def test_parses_sample_file(self) -> None:
        """Parses all recognised lines from the sample log file."""
        parser = AuthLogParser(year=2024)
        entries = parser.parse_file(FIXTURES / "auth.log.sample")
        assert len(entries) > 0
        ips = {e.source_ip for e in entries if e.source_ip}
        assert "192.168.1.10" in ips
        assert "203.0.113.42" in ips

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        """Raises FileNotFoundError for a missing log file."""
        parser = AuthLogParser(year=2024)
        with pytest.raises(FileNotFoundError):
            parser.parse_file(tmp_path / "no_such_file.log")
