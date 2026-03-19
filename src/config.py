"""Configuration loading and validation for SentinelLog."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Config:
    """Parsed and validated SentinelLog configuration."""

    brute_force_max_failures: int
    brute_force_window_seconds: int
    suspicious_ip_max_requests: int
    suspicious_ip_window_seconds: int
    failed_sudo_max_failures: int
    failed_sudo_window_seconds: int
    port_scan_min_distinct_ports: int
    port_scan_window_seconds: int
    whitelist_ips: list[str]
    whitelist_users: list[str]

    @classmethod
    def default(cls) -> "Config":
        """Return sensible default thresholds."""
        return cls(
            brute_force_max_failures=5,
            brute_force_window_seconds=60,
            suspicious_ip_max_requests=100,
            suspicious_ip_window_seconds=300,
            failed_sudo_max_failures=3,
            failed_sudo_window_seconds=120,
            port_scan_min_distinct_ports=10,
            port_scan_window_seconds=60,
            whitelist_ips=[],
            whitelist_users=[],
        )


def load_config(path: Path) -> Config:
    """Load and parse a YAML config file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        A validated Config instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        KeyError: If required config keys are missing.
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open() as f:
        data = yaml.safe_load(f)

    thresholds = data.get("thresholds", {})
    bf = thresholds.get("brute_force", {})
    si = thresholds.get("suspicious_ip", {})
    fs = thresholds.get("failed_sudo", {})
    ps = thresholds.get("port_scan", {})
    whitelist = data.get("whitelist", {})

    return Config(
        brute_force_max_failures=bf["max_failures"],
        brute_force_window_seconds=bf["window_seconds"],
        suspicious_ip_max_requests=si["max_requests"],
        suspicious_ip_window_seconds=si["window_seconds"],
        failed_sudo_max_failures=fs["max_failures"],
        failed_sudo_window_seconds=fs["window_seconds"],
        port_scan_min_distinct_ports=ps["min_distinct_ports"],
        port_scan_window_seconds=ps["window_seconds"],
        whitelist_ips=whitelist.get("ips", []),
        whitelist_users=whitelist.get("users", []),
    )
