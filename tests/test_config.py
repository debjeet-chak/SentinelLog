"""Tests for config loading and validation."""

import textwrap
from pathlib import Path

import pytest

from src.config import Config, load_config

VALID_YAML = textwrap.dedent("""\
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
""")


class TestLoadConfig:
    def test_load_valid_config(self, tmp_path: Path) -> None:
        """Loads a valid YAML config file."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(VALID_YAML)
        config = load_config(cfg_file)
        assert config.brute_force_max_failures == 5
        assert config.brute_force_window_seconds == 60
        assert config.suspicious_ip_max_requests == 100
        assert config.failed_sudo_max_failures == 3
        assert config.port_scan_min_distinct_ports == 10

    def test_load_config_with_exact_ip_whitelist(self, tmp_path: Path) -> None:
        """Loads whitelisted exact IPs and users."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(VALID_YAML.replace("ips: []", "ips:\n        - 10.0.0.1")
                                      .replace("users: []", "users:\n        - admin"))
        config = load_config(cfg_file)
        assert "10.0.0.1" in config.whitelist_ips
        assert "admin" in config.whitelist_users

    def test_load_config_with_cidr_whitelist(self, tmp_path: Path) -> None:
        """Loads CIDR notation in whitelist IPs."""
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(VALID_YAML.replace("ips: []", "ips:\n        - 192.168.1.0/24"))
        config = load_config(cfg_file)
        assert "192.168.1.0/24" in config.whitelist_ips

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

    def test_zero_max_failures_raises(self, tmp_path: Path) -> None:
        """Raises ValueError when max_failures is zero."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(VALID_YAML.replace("max_failures: 5", "max_failures: 0"))
        with pytest.raises(ValueError, match="brute_force.max_failures"):
            load_config(cfg)

    def test_negative_window_raises(self, tmp_path: Path) -> None:
        """Raises ValueError when window_seconds is negative."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(textwrap.dedent("""\
            thresholds:
              brute_force:
                max_failures: 5
                window_seconds: -1
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
        with pytest.raises(ValueError, match="brute_force.window_seconds"):
            load_config(cfg)

    def test_wrong_type_raises(self, tmp_path: Path) -> None:
        """Raises ValueError when a threshold is not an integer."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(VALID_YAML.replace("max_failures: 5", 'max_failures: "five"'))
        with pytest.raises(ValueError, match="brute_force.max_failures"):
            load_config(cfg)

    def test_missing_section_raises(self, tmp_path: Path) -> None:
        """Raises ValueError with a clear message when a required section is missing."""
        cfg = tmp_path / "config.yaml"
        # Remove the brute_force section entirely
        cfg.write_text(textwrap.dedent("""\
            thresholds:
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
        with pytest.raises(ValueError, match="brute_force"):
            load_config(cfg)
