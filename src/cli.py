"""Click CLI entrypoint for SentinelLog."""

import sys
from pathlib import Path

import click

from src.config import Config, load_config
from src.detectors.brute_force import BruteForceDetector
from src.detectors.failed_sudo import FailedSudoDetector
from src.detectors.port_scan import PortScanDetector
from src.detectors.suspicious_ip import SuspiciousIPDetector
from src.parsers.auth_log import AuthLogParser
from src.reporter import render_json, render_table


@click.group()
def cli() -> None:
    """SentinelLog — defensive log analyzer and threat detector."""


@cli.command()
@click.argument("logfile", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to a YAML config file. Uses built-in defaults if omitted.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
def analyze(logfile: Path, config_path: str | None, output_format: str) -> None:
    """Analyze LOGFILE for threats and report results.

    Exits with code 0 if no threats found, 1 if threats detected, 2 on error.
    """
    # Load config
    if config_path:
        try:
            config: Config = load_config(Path(config_path))
        except (FileNotFoundError, ValueError) as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(2)
    else:
        config = Config.default()

    # Parse
    parser = AuthLogParser()
    entries = parser.parse_file(logfile)

    # Detect
    detectors = [
        BruteForceDetector(config),
        FailedSudoDetector(config),
        SuspiciousIPDetector(config),
        PortScanDetector(config),
    ]
    threats = []
    for detector in detectors:
        threats.extend(detector.analyze(entries))

    # Report
    if output_format == "json":
        click.echo(render_json(threats))
    else:
        click.echo(render_table(threats), nl=False)

    sys.exit(1 if threats else 0)
