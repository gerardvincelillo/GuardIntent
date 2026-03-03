from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from guardintent.models import Event


class BaseParser(ABC):
    @abstractmethod
    def parse(self, path: str | Path) -> list[Event]:
        raise NotImplementedError
