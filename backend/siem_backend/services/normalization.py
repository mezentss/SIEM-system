from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedEvent:
    ts: str
    source_os: str
    event_type: str
    severity: str
    message: str
    raw_data: dict[str, Any]
