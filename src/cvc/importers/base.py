"""Importer abstract base. Each source implements `parse(path) -> list[Item]`."""
from __future__ import annotations

from abc import ABC, abstractmethod

from .normalize import Item


class Importer(ABC):
    #: short source label recorded on each Item (e.g. "chrome", "keychain")
    source: str = "unknown"

    @abstractmethod
    def parse(self, path: str) -> list[Item]:
        """Parse an explicit export file into normalized Items. No auto-discovery."""
        raise NotImplementedError
