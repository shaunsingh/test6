"""Audit log tailer, real-time security event monitoring

Monitors /var/log/audit/audit.log and other security-relevant logs,
detecting critical events and streaming them to the MCP server.
"""

from __future__ import annotations

import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Iterator


@dataclass(slots=True)
class SecurityEvent:
    """Parsed security event from audit logs."""

    event_type: str
    severity: str  # critical, high, medium, low, info
    timestamp: str
    source_file: str
    raw_line: str
    parsed_data: dict[str, Any] = field(default_factory=dict)
    iso_control: str | None = None


# Audit event types mapped to severity and ISO controls
AUDIT_EVENT_MAP: dict[str, tuple[str, str, str]] = {
    # (severity, iso_control, description)
    "USER_LOGIN": ("info", "A.9.4.2", "User login event"),
    "USER_LOGOUT": ("info", "A.9.4.2", "User logout event"),
    "USER_AUTH": ("info", "A.9.4.2", "User authentication"),
    "USER_ACCT": ("info", "A.9.4.2", "User account change"),
    "USER_CHAUTHTOK": ("medium", "A.9.4.3", "Password change"),
    "USER_ERR": ("high", "A.9.4.2", "User error"),
    "USER_MGMT": ("medium", "A.9.2.1", "User management action"),
    "USER_CMD": ("low", "A.9.2.3", "User command execution"),
    "ADD_USER": ("high", "A.9.2.1", "New user added"),
    "DEL_USER": ("high", "A.9.2.1", "User deleted"),
    "ADD_GROUP": ("medium", "A.9.2.1", "New group added"),
    "DEL_GROUP": ("medium", "A.9.2.1", "Group deleted"),
    "CHGRP_ID": ("medium", "A.9.2.1", "Group ID changed"),
    "CHUSER_ID": ("medium", "A.9.2.1", "User ID changed"),
    "GRP_MGMT": ("medium", "A.9.2.1", "Group management"),
    "CRED_ACQ": ("info", "A.9.4.2", "Credentials acquired"),
    "CRED_DISP": ("info", "A.9.4.2", "Credentials disposed"),
    "CRED_REFR": ("info", "A.9.4.2", "Credentials refreshed"),
    "LOGIN": ("info", "A.9.4.2", "Login event"),
    "ANOM_LOGIN_FAILURES": ("critical", "A.9.4.2", "Multiple login failures"),
    "ANOM_LOGIN_SESSIONS": ("high", "A.9.4.2", "Anomalous login sessions"),
    "ANOM_LOGIN_TIME": ("medium", "A.9.4.2", "Login at unusual time"),
    "ANOM_LOGIN_LOCATION": ("high", "A.9.4.2", "Login from unusual location"),
    "ANOM_PROMISCUOUS": ("critical", "A.13.1.1", "Network interface promiscuous mode"),
    "ANOM_ABEND": ("high", "A.12.4.1", "Abnormal program termination"),
    "ANOM_EXEC": ("critical", "A.12.4.1", "Anomalous program execution"),
    "ANOM_ROOT_TRANS": ("critical", "A.9.2.3", "Anomalous root transition"),
    "MAC_POLICY_LOAD": ("high", "A.14.2.5", "SELinux policy loaded"),
    "MAC_CONFIG_CHANGE": ("high", "A.14.2.5", "MAC configuration changed"),
    "MAC_STATUS": ("medium", "A.14.2.5", "MAC status change"),
    "AVC": ("high", "A.14.2.5", "SELinux access denial"),
    "SELINUX_ERR": ("high", "A.14.2.5", "SELinux error"),
    "EXECVE": ("low", "A.12.4.1", "Program execution"),
    "SYSCALL": ("info", "A.12.4.1", "System call"),
    "PATH": ("info", "A.12.4.1", "File path access"),
    "CWD": ("info", "A.12.4.1", "Current working directory"),
    "SOCKADDR": ("low", "A.13.1.1", "Socket address"),
    "PROCTITLE": ("info", "A.12.4.1", "Process title"),
    "CONFIG_CHANGE": ("high", "A.12.4.1", "Audit configuration changed"),
    "SYSTEM_BOOT": ("info", "A.12.4.1", "System boot"),
    "SYSTEM_SHUTDOWN": ("info", "A.12.4.1", "System shutdown"),
    "SERVICE_START": ("low", "A.12.4.1", "Service started"),
    "SERVICE_STOP": ("low", "A.12.4.1", "Service stopped"),
    "DAEMON_START": ("low", "A.12.4.1", "Audit daemon started"),
    "DAEMON_END": ("low", "A.12.4.1", "Audit daemon stopped"),
    "DAEMON_CONFIG": ("high", "A.12.4.1", "Audit daemon reconfigured"),
    "NETFILTER_CFG": ("high", "A.13.1.1", "Firewall configuration changed"),
    "NETFILTER_PKT": ("low", "A.13.1.1", "Firewall packet event"),
    "CRYPTO_KEY_USER": ("medium", "A.10.1.1", "Cryptographic key event"),
    "CRYPTO_SESSION": ("low", "A.10.1.1", "Cryptographic session"),
    "TTY": ("info", "A.12.4.1", "TTY input"),
    "EOE": ("info", "A.12.4.1", "End of event"),
}

# Pre-compiled regexes for faster parsing
TYPE_RE = re.compile(r"type=(\w+)")
TIMESTAMP_RE = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\)")
COMMON_PATTERNS = [
    (re.compile(r"pid=(\d+)"), "pid"),
    (re.compile(r"ppid=(\d+)"), "ppid"),
    (re.compile(r"uid=(\d+)"), "uid"),
    (re.compile(r"auid=(\d+)"), "auid"),
    (re.compile(r"ses=(\d+)"), "ses"),
    (re.compile(r'exe="([^"]*)"'), "exe"),
    (re.compile(r'comm="([^"]*)"'), "comm"),
    (re.compile(r"res=(\w+)"), "res"),
    (re.compile(r'acct="([^"]*)"'), "acct"),
    (re.compile(r'addr="?([^\s"]+)"?'), "addr"),
    (re.compile(r"success=(\w+)"), "success"),
    (re.compile(r'name="([^"]*)"'), "name"),
    (re.compile(r'op="([^"]*)"'), "op"),
]

# Critical patterns that should trigger immediate alerts
CRITICAL_PATTERNS = [
    (re.compile(r"auid=0\b.*success=yes", re.IGNORECASE), "Root action detected"),
    (re.compile(r"ANOM_LOGIN_FAILURES", re.IGNORECASE), "Multiple failed logins"),
    (re.compile(r"ANOM_ROOT_TRANS", re.IGNORECASE), "Anomalous root access"),
    (re.compile(r"type=AVC.*denied", re.IGNORECASE), "SELinux denial"),
    (re.compile(r"USER_AUTH.*res=failed", re.IGNORECASE), "Failed authentication"),
    (re.compile(r"CONFIG_CHANGE", re.IGNORECASE), "Audit config change"),
    (re.compile(r"MAC_POLICY_LOAD", re.IGNORECASE), "Security policy change"),
    (
        re.compile(r'exe="/usr/bin/sudo".*res=failed', re.IGNORECASE),
        "Failed sudo attempt",
    ),
]


def _parse_audit_line(line: str) -> dict[str, str]:
    """Parse audit log line into key-value pairs."""
    result: dict[str, str] = {}

    # Extract type
    type_match = TYPE_RE.search(line)
    if type_match:
        result["type"] = type_match.group(1)

    # Extract timestamp
    ts_match = TIMESTAMP_RE.search(line)
    if ts_match:
        result["timestamp"] = ts_match.group(1)
        result["serial"] = ts_match.group(2)

    # Extract common fields
    for pattern, key in COMMON_PATTERNS:
        match = pattern.search(line)
        if match:
            result[key] = match.group(1)

    return result


def _determine_severity(event_type: str, parsed: dict[str, str], line: str) -> str:
    """Determine event severity based on type and content."""
    # Check critical patterns first
    for pattern, _ in CRITICAL_PATTERNS:
        if pattern.search(line):
            return "critical"

    # Check event map
    if event_type in AUDIT_EVENT_MAP:
        return AUDIT_EVENT_MAP[event_type][0]

    # Check for failures
    if parsed.get("res") == "failed" or parsed.get("success") == "no":
        return "high"

    # Default based on auid (audit user ID)
    if parsed.get("auid") == "0":
        return "medium"

    return "low"


class AuditLogTailer:
    """Tails audit logs and emits security events."""

    def __init__(
        self,
        log_paths: list[str] | None = None,
        buffer_size: int = 1000,
        poll_interval: float = 1.0,
    ):
        self.log_paths = log_paths or [
            "/var/log/audit/audit.log",
            "/var/log/secure",
            "/var/log/auth.log",
        ]
        self.buffer_size = buffer_size
        self.poll_interval = poll_interval
        self._file_positions: dict[str, int] = {}
        self._event_buffer: deque[SecurityEvent] = deque(maxlen=buffer_size)
        self._callbacks: list[Callable[[SecurityEvent], None]] = []
        self._running = False

    def register_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for new security events."""
        self._callbacks.append(callback)

    def _emit_event(self, event: SecurityEvent) -> None:
        """Emit event to buffer and callbacks."""
        self._event_buffer.append(event)
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass  # Don't let callback errors stop processing

    def _tail_file(self, filepath: str) -> Iterator[SecurityEvent]:
        """Tail a single log file and yield events."""
        if not os.path.exists(filepath):
            return

        try:
            with open(filepath, "r") as f:
                # Seek to last known position or end of file
                if filepath in self._file_positions:
                    f.seek(self._file_positions[filepath])
                else:
                    f.seek(0, 2)  # End of file
                    self._file_positions[filepath] = f.tell()

                while True:
                    line = f.readline()
                    if not line:
                        self._file_positions[filepath] = f.tell()
                        break

                    line = line.strip()
                    if not line:
                        continue

                    event = self._parse_line(line, filepath)
                    if event:
                        yield event

        except PermissionError:
            pass  # Can't read file
        except OSError:
            pass  # File doesn't exist or other OS error

    def _parse_line(self, line: str, source_file: str) -> SecurityEvent | None:
        """Parse a log line into a SecurityEvent."""
        parsed = _parse_audit_line(line)
        event_type = parsed.get("type", "UNKNOWN")

        # Skip noise events
        if event_type in ("EOE", "PROCTITLE", "CWD"):
            return None

        severity = _determine_severity(event_type, parsed, line)
        iso_control = AUDIT_EVENT_MAP.get(event_type, (None, None, None))[1]

        # Parse timestamp
        if "timestamp" in parsed:
            try:
                ts = float(parsed["timestamp"])
                timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                timestamp = datetime.now(timezone.utc).isoformat()
        else:
            timestamp = datetime.now(timezone.utc).isoformat()

        return SecurityEvent(
            event_type=event_type,
            severity=severity,
            timestamp=timestamp,
            source_file=source_file,
            raw_line=line,
            parsed_data=parsed,
            iso_control=iso_control,
        )

    def scan_once(self) -> list[SecurityEvent]:
        """Perform a single scan of all log files."""
        events: list[SecurityEvent] = []
        for filepath in self.log_paths:
            for event in self._tail_file(filepath):
                events.append(event)
                self._emit_event(event)
        return events

    def get_recent_events(
        self,
        count: int = 100,
        severity_filter: str | None = None,
        event_type_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get recent events from buffer."""
        events_iter: Iterator[SecurityEvent] = reversed(self._event_buffer)

        if severity_filter:
            events_iter = (e for e in events_iter if e.severity == severity_filter)

        if event_type_filter:
            events_iter = (e for e in events_iter if e.event_type == event_type_filter)

        # Collect up to `count` newest events, then restore chronological order.
        limited = list(islice(events_iter, count))
        limited.reverse()

        return [
            {
                "event_type": e.event_type,
                "severity": e.severity,
                "timestamp": e.timestamp,
                "source_file": e.source_file,
                "iso_control": e.iso_control,
                "parsed_data": e.parsed_data,
            }
            for e in limited
        ]

    def get_critical_events(self, since_minutes: int = 5) -> list[dict[str, Any]]:
        """Get critical events from the last N minutes."""
        cutoff = datetime.now(timezone.utc).timestamp() - (since_minutes * 60)
        critical: list[dict[str, Any]] = []

        for event in self._event_buffer:
            if event.severity != "critical":
                continue

            try:
                event_ts = datetime.fromisoformat(
                    event.timestamp.replace("Z", "+00:00")
                ).timestamp()
                if event_ts >= cutoff:
                    critical.append(
                        {
                            "event_type": event.event_type,
                            "severity": event.severity,
                            "timestamp": event.timestamp,
                            "iso_control": event.iso_control,
                            "parsed_data": event.parsed_data,
                        }
                    )
            except (ValueError, AttributeError):
                continue

        return critical

    def run_continuous(self, stop_event=None) -> None:
        """Run continuous log monitoring."""
        import threading

        self._running = True
        stop = stop_event or threading.Event()

        while not stop.is_set() and self._running:
            self.scan_once()
            stop.wait(self.poll_interval)

    def stop(self) -> None:
        """Stop continuous monitoring."""
        self._running = False


def main():
    """Test the log tailer."""
    import json

    tailer = AuditLogTailer()

    # Do initial scan
    print("Scanning audit logs...")
    events = tailer.scan_once()

    print(f"Found {len(events)} events")
    for event in events[:10]:
        print(
            json.dumps(
                {
                    "type": event.event_type,
                    "severity": event.severity,
                    "timestamp": event.timestamp,
                    "iso_control": event.iso_control,
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
