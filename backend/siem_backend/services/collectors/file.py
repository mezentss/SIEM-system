from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from siem_backend.services.collectors.base import LogCollector
from siem_backend.services.normalization import EventClassifier, NormalizedEvent


class FileLogCollector(LogCollector):
    def __init__(self, file_path: Optional[str] = None, max_lines: int = 100) -> None:
        self._file_path = file_path or "./logs/system.log"
        self._max_lines = max_lines

    def collect(self) -> List[NormalizedEvent]:
        path = Path(self._file_path)
        if not path.exists() or not path.is_file():
            return []

        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return []

        selected = [ln.rstrip("\n") for ln in lines[-self._max_lines :] if ln.strip()]

        events: List[NormalizedEvent] = []
        for line in selected:
            ts, msg = self._parse_line(line)
            raw_data: Dict[str, Any] = {
                "source": "file",
                "file_path": str(path),
                "raw_line": line,
            }

            event_type = EventClassifier.classify_event_type(msg, raw_data)
            source_category = EventClassifier.classify_source_category(msg, raw_data, "macos")
            severity = self._determine_severity(msg)

            events.append(
                NormalizedEvent(
                    ts=ts,
                    source_os="macos",
                    source_category=source_category,
                    event_type=event_type,
                    severity=severity,
                    message=msg,
                    raw_data=raw_data,
                )
            )

        return events

    def _determine_severity(self, message: str) -> str:
        """Определяет уровень важности на основе сообщения."""
        msg_lower = message.lower()
        if any(kw in msg_lower for kw in ["error", "failed", "failure", "denied", "refused"]):
            return "high"
        if any(kw in msg_lower for kw in ["warning", "warn", "timeout"]):
            return "medium"
        if any(kw in msg_lower for kw in ["critical", "panic", "crash", "fatal"]):
            return "critical"
        return "low"

    def _parse_line(self, line: str) -> Tuple[str, str]:
        # Supported formats (best-effort):
        # - ISO: 2026-01-16T12:34:56Z message
        # - syslog-like: Jan 16 12:34:56 hostname process[pid]: message

        iso_match = re.match(
            r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<msg>.*)$",
            line,
        )
        if iso_match:
            ts = iso_match.group("ts").replace(" ", "T")
            msg = iso_match.group("msg")
            return self._to_iso_utc(ts), msg

        syslog_match = re.match(
            r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<msg>.*)$",
            line,
        )
        if syslog_match:
            mon = syslog_match.group("mon")
            day = int(syslog_match.group("day"))
            time_part = syslog_match.group("time")
            msg = syslog_match.group("msg")

            ts = self._syslog_to_iso(mon, day, time_part)
            return ts, msg

        return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z", line

    def _syslog_to_iso(self, mon: str, day: int, time_part: str) -> str:
        months = {
            "Jan": 1,
            "Feb": 2,
            "Mar": 3,
            "Apr": 4,
            "May": 5,
            "Jun": 6,
            "Jul": 7,
            "Aug": 8,
            "Sep": 9,
            "Oct": 10,
            "Nov": 11,
            "Dec": 12,
        }

        year = dt.datetime.utcnow().year
        month = months.get(mon)
        if month is None:
            return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

        try:
            hour, minute, second = [int(x) for x in time_part.split(":")]
            parsed = dt.datetime(year, month, day, hour, minute, second)
            return parsed.replace(microsecond=0).isoformat() + "Z"
        except ValueError:
            return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    def _to_iso_utc(self, ts: str) -> str:
        try:
            parsed = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

        if parsed.tzinfo is None:
            return parsed.replace(microsecond=0).isoformat() + "Z"

        return parsed.astimezone(dt.timezone.utc).replace(tzinfo=None, microsecond=0).isoformat() + "Z"
