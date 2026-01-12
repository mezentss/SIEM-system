from __future__ import annotations

import datetime as dt
import json
import subprocess
from dataclasses import asdict
from typing import Any, Optional

from siem_backend.services.normalization import NormalizedEvent
from siem_backend.services.collectors.base import LogCollector



class MacOSLogCollector(LogCollector):
    def __init__(
        self,
        last: str = "2m",
        max_entries: int = 200,
        predicate: Optional[str] = None,
    ) -> None:
        self._last = last
        self._max_entries = max_entries
        self._predicate = predicate

    def collect(self) -> list[NormalizedEvent]:
        cmd = [
            "log",
            "show",
            "--style",
            "json",
            "--last",
            self._last,
            "--info",
        ]

        if self._predicate:
            cmd.extend(["--predicate", self._predicate])

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "macOS log command failed")

        events: list[NormalizedEvent] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            normalized = self._normalize_record(record)
            if normalized is None:
                continue

            events.append(normalized)
            if len(events) >= self._max_entries:
                break

        return events

    def _normalize_record(self, record: dict[str, Any]) -> Optional[NormalizedEvent]:
        ts = record.get("timestamp")
        if ts is None:
            return None

        msg = record.get("eventMessage") or record.get("message") or ""
        level = (record.get("messageType") or "").lower()

        severity = "low"
        if level in {"error"}:
            severity = "high"
        elif level in {"fault"}:
            severity = "critical"

        ts_iso = self._to_iso(ts)

        return NormalizedEvent(
            ts=ts_iso,
            source_os="macos",
            event_type="macos_unified_log",
            severity=severity,
            message=msg,
            raw_data=record,
        )

    def _to_iso(self, ts: Any) -> str:
        if isinstance(ts, str):
            try:
                parsed = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return parsed.isoformat()
            except ValueError:
                return ts
        return str(ts)


def normalized_event_to_dict(event: NormalizedEvent) -> dict[str, Any]:
    return asdict(event)
