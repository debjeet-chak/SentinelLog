"""Rich terminal reporter for SentinelLog threat output."""

import io
import json

from rich.console import Console
from rich.table import Table
from rich import box

from src.models import Threat, ThreatLevel

_LEVEL_LABELS = {
    ThreatLevel.CRITICAL: "CRITICAL",
    ThreatLevel.HIGH: "HIGH",
    ThreatLevel.MEDIUM: "MEDIUM",
    ThreatLevel.INFO: "INFO",
}


def render_table(threats: list[Threat]) -> str:
    """Render threats as a Rich table and return the result as a plain string.

    Args:
        threats: Detected threats to display.

    Returns:
        A string containing the formatted table, or a 'No threats detected'
        message if the list is empty.
    """
    buf = io.StringIO()
    console = Console(file=buf, highlight=False, no_color=True)

    if not threats:
        console.print("No threats detected.")
        return buf.getvalue()

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

    for threat in sorted(threats, key=lambda t: t.level, reverse=True):
        table.add_row(
            _LEVEL_LABELS[threat.level],
            threat.threat_type,
            threat.source_ip or "—",
            str(threat.count),
            threat.description,
            threat.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        )

    console.print(table)
    return buf.getvalue()


def render_json(threats: list[Threat]) -> str:
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
