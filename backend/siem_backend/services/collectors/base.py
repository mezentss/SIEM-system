from __future__ import annotations

from abc import ABC, abstractmethod

from siem_backend.services.normalization import NormalizedEvent


class LogCollector(ABC):
    @abstractmethod
    def collect(self) -> list[NormalizedEvent]:
        raise NotImplementedError
