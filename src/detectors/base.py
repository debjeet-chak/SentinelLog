"""Abstract base class for threat detectors."""

from abc import ABC, abstractmethod

from src.config import Config
from src.models import LogEntry, Threat


class BaseDetector(ABC):
    """Abstract base detector — subclasses implement specific threat patterns."""

    def __init__(self, config: Config) -> None:
        """Initialise with shared configuration.

        Args:
            config: Loaded SentinelLog configuration.
        """
        self._config = config

    @abstractmethod
    def analyze(self, entries: list[LogEntry]) -> list[Threat]:
        """Analyze log entries and return any detected threats.

        Args:
            entries: Parsed log entries to analyze.

        Returns:
            List of Threat objects (empty if none detected).
        """
