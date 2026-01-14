from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class IncidentCandidate:
    incident_type: str
    severity: str
    description: str
    detected_at: dt.datetime
    event_id: Optional[int]
    details: Dict[str, Any]
