"""Rich terminal reporter for SentinelLog threat output."""

import json

from rich.console import Console
from rich.table import Table
from rich import box

from src.models import Threat, ThreatLevel

_LEVEL_STYLES = {
    ThreatLevel.CRITICAL: "bold red",
    ThreatLevel.HIGH: "yellow",
    ThreatLevel.MEDIUM: "cyan",
    ThreatLevel.INFO: "white",
}

_LEVEL_LABELS = {
    ThreatLevel.CRITICAL: "CRITICAL",
    ThreatLevel.HIGH: "HIGH",
    ThreatLevel.MEDIUM: "MEDIUM",
    ThreatLevel.INFO: "INFO",
}


def format_threats_json(threats: list[Threat]) -> str:
    """Serialize threats to a JSON string.

    Args:
        threats: List of detected threats.

    Returns:
        A JSON array string with one object per threat.
    """
    records = [
        {
            "level": _LEVEL_LABELS[t.level],
            "threat_type": t.threat_type,
            "source_ip": t.source_ip,
            "username": t.username,
            "description": t.description,
            "count": t.count,
            "first_seen": t.first_seen.isoformat(),
            "last_seen": t.last_seen.isoformat(),
        }
        for t in threats
    ]
    return json.dumps(records, indent=2)


class Reporter:
    """Renders threat results to the terminal using Rich."""

    def __init__(self) -> None:
        """Initialise with a Rich console."""
        self._console = Console()

    def print_table(self, threats: list[Threat]) -> None:
        """Print a formatted threat table to the terminal.

        Args:
            threats: Detected threats to display.
        """
        if not threats:
            self._console.print("[green]No threats detected.[/green]")
            return

        table = Table(
            title="SentinelLog Threat Report",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("Level", style="bold", min_width=8)
        table.add_column("Type", min_width=14)
        table.add_column("Source IP", min_width=16)
        table.add_column("Count", justify="right", min_width=6)
        table.add_column("Description")
        table.add_column("Last Seen", min_width=19)

        sorted_threats = sorted(threats, key=lambda t: t.level, reverse=True)
        for threat in sorted_threats:
            style = _LEVEL_STYLES[threat.level]
            table.add_row(
                f"[{style}]{_LEVEL_LABELS[threat.level]}[/{style}]",
                threat.threat_type,
                threat.source_ip or "—",
                str(threat.count),
                threat.description,
                threat.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            )

        self._console.print(table)
