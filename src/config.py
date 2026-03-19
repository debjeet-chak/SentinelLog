"""Configuration loading and validation for SentinelLog."""

import ipaddress
import warnings
from dataclasses import dataclass
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


def _require_positive_int(value: object, name: str) -> int:
    """Validate that value is a positive integer.

    Args:
        value: The raw value from YAML.
        name: Dotted config key name for error messages (e.g. "brute_force.max_failures").

    Returns:
        The value as an int.

    Raises:
        ValueError: If value is not a positive integer.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(
            f"Config '{name}' must be a positive integer, got: {value!r}"
        )
    if value < 1:
        raise ValueError(
            f"Config '{name}' must be >= 1, got: {value}"
        )
    return value


def _validate_whitelist_ips(raw: list[object]) -> list[str]:
    """Validate whitelist IP entries, warning on any that are not valid IPs or CIDRs.

    Args:
        raw: Raw list of values from the YAML whitelist.ips field.

    Returns:
        List of entries that are valid IP addresses or CIDR ranges. Invalid
        entries are skipped and a UserWarning is emitted for each one.
    """
    valid: list[str] = []
    for entry in raw:
        entry_str = str(entry)
        try:
            if "/" in entry_str:
                ipaddress.ip_network(entry_str, strict=False)
            else:
                ipaddress.ip_address(entry_str)
            valid.append(entry_str)
        except ValueError:
            warnings.warn(
                f"Invalid whitelist IP entry ignored: {entry_str!r}",
                UserWarning,
                stacklevel=3,
            )
    return valid


def load_config(path: Path) -> Config:
    """Load and parse a YAML config file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        A validated Config instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If required keys are missing or values are invalid.
    """
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open() as f:
        data = yaml.safe_load(f)

    thresholds = data.get("thresholds", {})

    try:
        bf = thresholds["brute_force"]
        si = thresholds["suspicious_ip"]
        fs = thresholds["failed_sudo"]
        ps = thresholds["port_scan"]
    except KeyError as exc:
        raise ValueError(f"Missing required config section: {exc}") from exc

    whitelist = data.get("whitelist", {})
    whitelist_ips = _validate_whitelist_ips(whitelist.get("ips", []))

    return Config(
        brute_force_max_failures=_require_positive_int(bf.get("max_failures"), "brute_force.max_failures"),
        brute_force_window_seconds=_require_positive_int(bf.get("window_seconds"), "brute_force.window_seconds"),
        suspicious_ip_max_requests=_require_positive_int(si.get("max_requests"), "suspicious_ip.max_requests"),
        suspicious_ip_window_seconds=_require_positive_int(si.get("window_seconds"), "suspicious_ip.window_seconds"),
        failed_sudo_max_failures=_require_positive_int(fs.get("max_failures"), "failed_sudo.max_failures"),
        failed_sudo_window_seconds=_require_positive_int(fs.get("window_seconds"), "failed_sudo.window_seconds"),
        port_scan_min_distinct_ports=_require_positive_int(ps.get("min_distinct_ports"), "port_scan.min_distinct_ports"),
        port_scan_window_seconds=_require_positive_int(ps.get("window_seconds"), "port_scan.window_seconds"),
        whitelist_ips=whitelist_ips,
        whitelist_users=whitelist.get("users", []),
    )
