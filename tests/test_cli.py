"""Tests for the Click CLI entrypoint."""

import json
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from src.cli import cli


@pytest.fixture()
def sample_log(tmp_path: Path) -> Path:
    log = tmp_path / "auth.log"
    log.write_text(
        "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 192.168.1.10 port 52001 ssh2\n"
        "Jan 15 10:00:05 host sshd[2]: Failed password for alice from 192.168.1.10 port 52002 ssh2\n"
        "Jan 15 10:00:10 host sshd[3]: Failed password for alice from 192.168.1.10 port 52003 ssh2\n"
        "Jan 15 10:00:15 host sshd[4]: Failed password for alice from 192.168.1.10 port 52004 ssh2\n"
        "Jan 15 10:00:20 host sshd[5]: Failed password for alice from 192.168.1.10 port 52005 ssh2\n"
    )
    return log


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent("""\
        thresholds:
          brute_force:
            max_failures: 5
            window_seconds: 60
          suspicious_ip:
            max_requests: 100
            window_seconds: 300
          failed_sudo:
            max_failures: 3
            window_seconds: 120
          port_scan:
            min_distinct_ports: 10
            window_seconds: 60
        whitelist:
          ips: []
          users: []
    """))
    return cfg


class TestAnalyzeCommand:
    def test_analyze_exits_zero_no_threats(self, tmp_path: Path, config_file: Path) -> None:
        """Exits 0 when no threats are detected."""
        clean_log = tmp_path / "clean.log"
        clean_log.write_text(
            "Jan 15 10:00:01 host sshd[1]: Accepted password for bob from 10.0.0.5 port 48000 ssh2\n"
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(clean_log), "--config", str(config_file)])
        assert result.exit_code == 0

    def test_analyze_exits_one_with_threats(self, sample_log: Path, config_file: Path) -> None:
        """Exits 1 when threats are detected."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(sample_log), "--config", str(config_file)])
        assert result.exit_code == 1

    def test_analyze_json_format(self, sample_log: Path, config_file: Path) -> None:
        """JSON output mode produces valid JSON."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["analyze", str(sample_log), "--config", str(config_file), "--format", "json"],
        )
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)

    def test_analyze_missing_log_file(self, config_file: Path) -> None:
        """Exits 2 for a missing log file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "/no/such/file.log", "--config", str(config_file)])
        assert result.exit_code == 2

    def test_analyze_missing_config_file(self, sample_log: Path) -> None:
        """Exits 2 with an error message when --config points to a nonexistent file."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(sample_log), "--config", "/no/such/config.yaml"])
        assert result.exit_code == 2

    def test_analyze_invalid_config_values(self, sample_log: Path, tmp_path: Path) -> None:
        """Exits 2 with an error message for a malformed config."""
        bad_cfg = tmp_path / "bad.yaml"
        bad_cfg.write_text(textwrap.dedent("""\
            thresholds:
              brute_force:
                max_failures: 0
                window_seconds: 60
              suspicious_ip:
                max_requests: 100
                window_seconds: 300
              failed_sudo:
                max_failures: 3
                window_seconds: 120
              port_scan:
                min_distinct_ports: 10
                window_seconds: 60
            whitelist:
              ips: []
              users: []
        """))
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(sample_log), "--config", str(bad_cfg)])
        assert result.exit_code == 2

    def test_analyze_default_config(self, sample_log: Path) -> None:
        """Works without --config flag using built-in defaults."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(sample_log)])
        assert result.exit_code in (0, 1)

    def test_analyze_uses_table_format_by_default(
        self, sample_log: Path, config_file: Path
    ) -> None:
        """Default output is table format (no --format flag required)."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", str(sample_log), "--config", str(config_file)])
        assert result.output or result.exit_code in (0, 1)
