from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from siem_backend.services.normalization import NormalizedEvent


@dataclass(frozen=True)
class AnalysisResult:
    is_incident: bool
    incident_type: Optional[str]
    severity: str
    recommendation: Optional[str]


class AnalysisEngine:
    def analyze(self, event: NormalizedEvent) -> AnalysisResult:
        return AnalysisResult(
            is_incident=False,
            incident_type=None,
            severity=event.severity,
            recommendation=None,
        )
