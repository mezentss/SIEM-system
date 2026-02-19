from __future__ import annotations

import re

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedEvent:
    ts: str
    source_os: str
    source_category: str
    event_type: str
    severity: str
    message: str
    raw_data: dict[str, Any]


class EventClassifier:
    """Классификатор событий по типу и источнику."""

    AUTH_KEYWORDS = [
        "login", "logout", "authentication", "auth", "password", "credential",
        "session", "user", "access denied", "unauthorized", "failed login",
        "authentication failure", "invalid password", "login failed",
    ]

    NETWORK_KEYWORDS = [
        "network", "dns", "connection", "socket", "timeout", "unreachable",
        "refused", "tcp", "udp", "http", "https", "ssl", "tls", "ip",
        "packet", "interface", "ethernet", "wifi", "bluetooth",
    ]

    SERVICE_KEYWORDS = [
        "service", "daemon", "launchd", "systemd", "crash", "terminated",
        "restart", "started", "stopped", "failed to start", "exited",
        "panic", "kernel", "system",
    ]

    PROCESS_KEYWORDS = [
        "process", "pid", "exec", "fork", "thread", "memory", "cpu",
        "application", "app", "program", "binary",
    ]

    @classmethod
    def classify_event_type(cls, message: str, raw_data: dict[str, Any]) -> str:
        """Определяет тип события на основе сообщения и сырых данных."""
        msg_lower = (message or "").lower()

        if any(kw in msg_lower for kw in cls.AUTH_KEYWORDS):
            return "authentication"
        if any(kw in msg_lower for kw in cls.NETWORK_KEYWORDS):
            return "network"
        if any(kw in msg_lower for kw in cls.SERVICE_KEYWORDS):
            return "service"
        if any(kw in msg_lower for kw in cls.PROCESS_KEYWORDS):
            return "process"

        event_type = raw_data.get("event_type") or raw_data.get("category") or raw_data.get("type")
        if event_type:
            event_type_lower = str(event_type).lower()
            if any(kw in event_type_lower for kw in ["auth", "login", "session"]):
                return "authentication"
            if any(kw in event_type_lower for kw in ["network", "dns", "connection"]):
                return "network"
            if any(kw in event_type_lower for kw in ["service", "daemon", "system"]):
                return "service"
            if any(kw in event_type_lower for kw in ["process", "app", "application"]):
                return "process"

        return "system"

    @classmethod
    def classify_source_category(cls, message: str, raw_data: dict[str, Any], source_os: str) -> str:
        """Определяет категорию источника события."""
        # First check explicit fields from raw_data
        process = raw_data.get("process") or raw_data.get("service") or raw_data.get("application") or ""
        process_lower = str(process).lower()

        # Known system services
        system_services = ["systemd", "launchd", "kernel", "init", "sshd", "cron", "rsyslog", "journald", "networkd", "udev", "dbus", "polkit", "network"]
        if process_lower in system_services or process_lower.startswith("system"):
            return "service"

        subsystem = raw_data.get("subsystem") or raw_data.get("category") or ""
        subsystem_lower = str(subsystem).lower()

        if any(kw in subsystem_lower for kw in ["system", "kernel", "launchd", "systemd", "daemon"]):
            return "service"

        if any(kw in subsystem_lower for kw in ["user", "app", "application", "process"]):
            return "user_process"

        msg_lower = (message or "").lower()
        
        # Check for .service pattern (systemd services like nginx.service)
        if re.search(r"\b[a-zA-Z0-9_-]+\.service", msg_lower):
            return "user_process"
        
        if any(kw in msg_lower for kw in ["launchd", "systemd", "daemon", "service"]):
            return "service"
        if any(kw in msg_lower for kw in ["app", "application", "user process"]):
            return "user_process"

        return "os"
