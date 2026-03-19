"""Tests for config loading and validation."""

import textwrap
from pathlib import Path

import pytest

from src.config import Config, load_config


class TestLoadConfig:
    def test_load_valid_config(self, tmp_path: Path) -> None:
        """Loads a valid YAML config file."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(textwrap.dedent("""\
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
        config = load_config(cfg_file)
        assert config.brute_force_max_failures == 5
        assert config.brute_force_window_seconds == 60
        assert config.suspicious_ip_max_requests == 100
        assert config.failed_sudo_max_failures == 3
        assert config.port_scan_min_distinct_ports == 10

    def test_load_config_with_whitelist(self, tmp_path: Path) -> None:
        """Loads whitelisted IPs and users."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(textwrap.dedent("""\
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
              ips:
                - 10.0.0.1
                - 192.168.1.0/24
              users:
                - admin
        """))
        config = load_config(cfg_file)
        assert "10.0.0.1" in config.whitelist_ips
        assert "192.168.1.0/24" in config.whitelist_ips
        assert "admin" in config.whitelist_users

    def test_load_missing_file_raises(self, tmp_path: Path) -> None:
        """Raises FileNotFoundError for missing config file."""
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_default_config(self) -> None:
        """Config.default() returns sensible defaults."""
        config = Config.default()
        assert config.brute_force_max_failures > 0
        assert config.brute_force_window_seconds > 0
        assert config.whitelist_ips == []
        assert config.whitelist_users == []
