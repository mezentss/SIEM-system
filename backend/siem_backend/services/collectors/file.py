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
            proc_name = self._extract_process_name(line, msg)
            raw_data: Dict[str, Any] = {
                "source": "file",
                "file_path": str(path),
                "raw_line": line,
            }
            if proc_name:
                raw_data["process"] = proc_name
                raw_data["service"] = proc_name
                raw_data["application"] = proc_name

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

    def _extract_process_name(self, raw_line: str, msg: str) -> str:
        def is_meaningful(value: str) -> bool:
            v = (value or "").strip()
            if not v:
                return False
            if v.isdigit():
                return False
            return re.search(r"[A-Za-zА-Яа-я]", v) is not None

        text = raw_line or msg or ""

        # Check for service name in message (e.g., "nginx.service:" in systemd logs)
        service_in_msg_match = re.search(r"\b([a-zA-Z0-9_-]+)\.service:", msg or "")
        if service_in_msg_match:
            service_name = service_in_msg_match.group(1)
            if is_meaningful(service_name):
                return service_name

        # Format: "2026-02-21 12:00:00,000 ERROR zoom[1234]: message"
        iso_format_match = re.match(
            r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+\s+\w+\s+(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s+.*$",
            text,
        )
        if iso_format_match:
            proc = iso_format_match.group("proc")
            if is_meaningful(proc):
                return proc

        # Full syslog line: "Jan 16 12:34:56 host process[pid]: message"
        m_full = re.match(
            r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?(?P<host>\S+)\s+(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s+.*$",
            text,
        )
        if m_full:
            proc = m_full.group("proc")
            if is_meaningful(proc):
                return proc

        # Msg without timestamp: "host process[pid]: message"
        m_msg = re.match(
            r"^(?P<host>\S+)\s+(?P<proc>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s+.*$",
            msg or "",
        )
        if m_msg:
            proc = m_msg.group("proc")
            if is_meaningful(proc):
                return proc

        # Fallback: "proc[pid]: message" or "proc: message"
        m_proc = re.match(r"^\s*(?P<proc>[^\s:]+?)(?:\[\d+\])?:\s+.*$", text)
        if m_proc:
            proc = m_proc.group("proc")
            if is_meaningful(proc):
                return proc

        return ""

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
