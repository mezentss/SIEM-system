from __future__ import annotations

import datetime as dt
import socket
from typing import Any, Dict, List, Optional

from siem_backend.services.collectors.base import LogCollector
from siem_backend.services.normalization import NormalizedEvent


class MockLogCollector(LogCollector):
    def __init__(self, event_count: int = 18, host: Optional[str] = None) -> None:
        if event_count < 1:
            raise ValueError("Invalid event_count")

        self._event_count = event_count
        self._host = host or socket.gethostname()

    def collect(self) -> List[NormalizedEvent]:
        count = self._event_count
        now = dt.datetime.utcnow()

        # Demo scenario: event mix chosen so default analysis rules will detect incidents.
        # - failed logins >= 5
        # - network errors >= 10
        # - service crash/restart >= 1
        templates: List[tuple[str, str, str]] = []
        templates.extend(
            [
                ("auth", "high", "Failed login attempt for user admin"),
                ("auth", "high", "Login failed for user admin"),
                ("auth", "high", "Authentication failure for user admin"),
                ("auth", "high", "Failed login attempt for user admin"),
                ("auth", "high", "Login failed for user admin"),
                ("auth", "high", "Failed login attempt for user admin"),
            ]
        )
        templates.extend(
            [
                ("network", "medium", "Network timeout while connecting to host"),
                ("network", "medium", "Network timeout while connecting to host"),
                ("network", "high", "DNS lookup failed for host"),
                ("network", "medium", "Network timeout while connecting to host"),
                ("network", "high", "Connection refused while connecting to host"),
                ("network", "medium", "Socket error: timeout while connecting"),
                ("network", "medium", "Network unreachable"),
                ("network", "high", "DNS lookup failed for host"),
                ("network", "medium", "Network timeout while connecting to host"),
                ("network", "medium", "Network timeout while connecting to host"),
            ]
        )
        templates.extend(
            [
                ("service", "critical", "Service nginx crashed"),
                ("service", "critical", "launchd: service terminated unexpectedly"),
            ]
        )

        events: List[NormalizedEvent] = []
        for i in range(count):
            category, severity, message = templates[i % len(templates)]
            ts = (now - dt.timedelta(seconds=(count - i))).replace(microsecond=0).isoformat() + "Z"

            raw_data: Dict[str, Any] = {
                "source": "mock",
                "host": self._host,
                "level": severity,
                "category": category,
            }

            events.append(
                NormalizedEvent(
                    ts=ts,
                    source_os="mock",
                    event_type=category,
                    severity=severity,
                    message=message,
                    raw_data=raw_data,
                )
            )

        return events
