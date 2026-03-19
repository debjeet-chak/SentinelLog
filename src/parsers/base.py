"""Abstract base class for log parsers."""

from abc import ABC, abstractmethod
from pathlib import Path

from src.models import LogEntry


class BaseParser(ABC):
    """Abstract base parser — subclasses parse a specific log format."""

    @abstractmethod
    def parse_line(self, line: str) -> LogEntry | None:
        """Parse a single log line into a LogEntry.

        Args:
            line: A single raw log line.

        Returns:
            A LogEntry if the line is recognised, otherwise None.
        """

    def parse_file(self, path: Path) -> list[LogEntry]:
        """Parse all recognised lines from a log file.

        Args:
            path: Path to the log file.

        Returns:
            List of parsed LogEntry objects (unrecognised lines skipped).

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        entries: list[LogEntry] = []
        with path.open(errors="replace") as f:
            for raw_line in f:
                entry = self.parse_line(raw_line.rstrip("\n"))
                if entry is not None:
                    entries.append(entry)
        return entries
