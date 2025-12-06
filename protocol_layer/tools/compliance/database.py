"""Compliance Database, SQLite storage for compliance data

Provides persistent storage for:
- Scan results and compliance status
- Security events and alerts
- Compliance reports and history
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    scan_data TEXT NOT NULL,
    compliance_score REAL,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    event_type TEXT,
    severity TEXT,
    message TEXT,
    event_data TEXT,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    events TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_hostname ON alerts(hostname);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id TEXT UNIQUE NOT NULL,
    report_type TEXT NOT NULL,
    hostname TEXT,
    content TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'json',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_hostname ON reports(hostname);
"""


class ComplianceDB:
    """SQLite database for compliance data storage."""

    __slots__ = ("db_path", "_local")

    def __init__(self, db_path: str = "compliance.db") -> None:
        self.db_path = Path(db_path)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=3000")
            self._local.conn = conn
        return self._local.conn  # type: ignore[attr-defined]

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    def store_scan(self, hostname: str, scan_data: dict[str, Any]) -> int:
        """Store a compliance scan result. Returns the scan ID."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        score = scan_data.get("summary", {}).get("compliance_percentage")
        if score is None:
            controls = scan_data.get("controls", [])
            if controls:
                passed = sum(1 for c in controls if c.get("status") == "pass")
                score = (passed / len(controls)) * 100

        if "timestamp" not in scan_data:
            scan_data["timestamp"] = now

        cursor = conn.execute(
            "INSERT INTO scans (hostname, scan_data, compliance_score, timestamp, created_at) VALUES (?, ?, ?, ?, ?)",
            (hostname, json.dumps(scan_data), score, scan_data["timestamp"], now),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def store_events(self, hostname: str, events: list[dict[str, Any]]) -> int:
        """Store security events. Returns the count of events stored."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        conn.executemany(
            "INSERT INTO events (hostname, event_type, severity, message, event_data, timestamp, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    hostname,
                    e.get("type", e.get("event_type", "unknown")),
                    e.get("severity", "info"),
                    e.get("message", ""),
                    json.dumps(e),
                    e.get("timestamp", now),
                    now,
                )
                for e in events
            ],
        )
        conn.commit()
        return len(events)

    def store_critical_alert(
        self, hostname: str, alert_type: str, events: list[dict[str, Any]]
    ) -> int:
        """Store a critical security alert. Returns the alert ID."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        cursor = conn.execute(
            "INSERT INTO alerts (hostname, alert_type, events, timestamp, created_at) VALUES (?, ?, ?, ?, ?)",
            (hostname, alert_type, json.dumps(events), now, now),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def get_latest_scan(self, hostname: str) -> dict[str, Any] | None:
        """Get the most recent scan for a hostname."""
        row = (
            self._get_conn()
            .execute(
                "SELECT scan_data, timestamp FROM scans WHERE hostname = ? ORDER BY timestamp DESC LIMIT 1",
                (hostname,),
            )
            .fetchone()
        )

        if row:
            data = json.loads(row["scan_data"])
            data["timestamp"] = row["timestamp"]
            return data
        return None

    def get_failing_controls(self, hostname: str) -> list[dict[str, Any]]:
        """Get list of failing controls for a hostname."""
        scan = self.get_latest_scan(hostname)
        if not scan:
            return []

        failing = [
            {
                "control_id": c.get("control_id", ""),
                "control_name": c.get("control_name", c.get("name", "")),
                "severity": c.get("severity", "medium"),
                "details": c.get("details", ""),
                "iso_clause": c.get("iso_clause", ""),
                "remediation": c.get("remediation", ""),
            }
            for c in scan.get("controls", [])
            if c.get("status") in ("fail", "warning")
        ]

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(failing, key=lambda x: severity_order.get(x["severity"], 4))

    def get_fleet_summary(self) -> dict[str, Any]:
        """Get summary of compliance status across all machines."""
        rows = (
            self._get_conn()
            .execute(
                """
            SELECT s.hostname, s.compliance_score, s.timestamp, s.scan_data
            FROM scans s
            INNER JOIN (
                SELECT hostname, MAX(timestamp) as max_ts FROM scans GROUP BY hostname
            ) latest ON s.hostname = latest.hostname AND s.timestamp = latest.max_ts
        """
            )
            .fetchall()
        )

        machines = []
        total_score = 0
        compliant_count = 0
        machines_with_critical = 0

        for row in rows:
            scan_data = json.loads(row["scan_data"])
            score = row["compliance_score"] or 0
            controls = scan_data.get("controls", [])

            failed_controls = sum(1 for c in controls if c.get("status") == "fail")
            critical_findings = sum(
                1
                for c in controls
                if c.get("status") == "fail" and c.get("severity") == "critical"
            )

            if critical_findings > 0:
                machines_with_critical += 1
            if score >= 80:
                compliant_count += 1

            total_score += score
            machines.append(
                {
                    "hostname": row["hostname"],
                    "score": score,
                    "last_scan": row["timestamp"],
                    "failed_controls": failed_controls,
                    "critical_findings": critical_findings,
                }
            )

        total_machines = len(machines)
        return {
            "total_machines": total_machines,
            "compliant_machines": compliant_count,
            "non_compliant_machines": total_machines - compliant_count,
            "average_score": (
                round(total_score / total_machines, 1) if total_machines > 0 else 0
            ),
            "machines_with_critical": machines_with_critical,
            "machines": machines,
        }

    def get_recent_events(
        self,
        hostname: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get recent security events with optional filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []

        if hostname:
            query += " AND hostname = ?"
            params.append(hostname)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        return [
            {
                **(json.loads(row["event_data"]) if row["event_data"] else {}),
                "id": row["id"],
                "hostname": row["hostname"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "message": row["message"],
                "timestamp": row["timestamp"],
            }
            for row in self._get_conn().execute(query, params).fetchall()
        ]

    def get_unacknowledged_alerts(
        self, hostname: str | None = None
    ) -> list[dict[str, Any]]:
        """Get all unacknowledged critical alerts."""
        query = "SELECT * FROM alerts WHERE acknowledged = 0"
        params: list[Any] = []

        if hostname:
            query += " AND hostname = ?"
            params.append(hostname)

        query += " ORDER BY timestamp DESC"

        return [
            {
                "id": row["id"],
                "hostname": row["hostname"],
                "alert_type": row["alert_type"],
                "events": json.loads(row["events"]),
                "timestamp": row["timestamp"],
            }
            for row in self._get_conn().execute(query, params).fetchall()
        ]

    def acknowledge_alert(self, alert_id: int, acknowledged_by: str) -> bool:
        """Acknowledge a critical alert. Returns True if alert was found and acknowledged."""
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ? WHERE id = ? AND acknowledged = 0",
            (acknowledged_by, datetime.now(timezone.utc).isoformat(), alert_id),
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_compliance_trend(self, hostname: str, days: int = 30) -> dict[str, Any]:
        """Get compliance score trend over time."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        rows = (
            self._get_conn()
            .execute(
                "SELECT DATE(timestamp) as date, AVG(compliance_score) as avg_score FROM scans WHERE hostname = ? AND timestamp >= ? GROUP BY DATE(timestamp) ORDER BY date",
                (hostname, cutoff),
            )
            .fetchall()
        )

        trend_data = [
            {"date": row["date"], "score": round(row["avg_score"], 1)} for row in rows
        ]

        direction = "insufficient_data"
        if len(trend_data) >= 2:
            delta = trend_data[-1]["score"] - trend_data[0]["score"]
            direction = (
                "improving" if delta > 5 else "declining" if delta < -5 else "stable"
            )

        return {
            "hostname": hostname,
            "period_days": days,
            "direction": direction,
            "data_points": trend_data,
        }

    def get_scan_history(self, hostname: str, limit: int = 30) -> list[dict[str, Any]]:
        """Get scan history for a hostname."""
        return [
            {
                "scan_id": row["id"],
                "score": row["compliance_score"],
                "timestamp": row["timestamp"],
            }
            for row in self._get_conn()
            .execute(
                "SELECT id, compliance_score, timestamp FROM scans WHERE hostname = ? ORDER BY timestamp DESC LIMIT ?",
                (hostname, limit),
            )
            .fetchall()
        ]

    def get_event_stats(self, hostname: str, hours: int = 24) -> dict[str, Any]:
        """Get event statistics for a hostname over the specified period."""
        conn = self._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        by_severity = {
            row["severity"]: row["count"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) as count FROM events WHERE hostname = ? AND timestamp >= ? GROUP BY severity",
                (hostname, cutoff),
            ).fetchall()
        }

        by_type = {
            row["event_type"]: row["count"]
            for row in conn.execute(
                "SELECT event_type, COUNT(*) as count FROM events WHERE hostname = ? AND timestamp >= ? GROUP BY event_type ORDER BY count DESC LIMIT 10",
                (hostname, cutoff),
            ).fetchall()
        }

        return {
            "hostname": hostname,
            "period_hours": hours,
            "total_events": sum(by_severity.values()),
            "by_severity": by_severity,
            "by_type": by_type,
        }

    def store_report(
        self,
        report_id: str,
        report_type: str,
        content: str,
        format: str = "json",
        hostname: str | None = None,
    ) -> None:
        """Store a generated compliance report."""
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO reports (report_id, report_type, hostname, content, format, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                report_id,
                report_type,
                hostname,
                content,
                format,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        """Retrieve a stored report by ID."""
        row = (
            self._get_conn()
            .execute("SELECT * FROM reports WHERE report_id = ?", (report_id,))
            .fetchone()
        )

        if row:
            return {
                "report_id": row["report_id"],
                "report_type": row["report_type"],
                "hostname": row["hostname"],
                "content": (
                    json.loads(row["content"])
                    if row["format"] == "json"
                    else row["content"]
                ),
                "format": row["format"],
                "created_at": row["created_at"],
            }
        return None

    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, "conn"):
            self._local.conn.close()
            del self._local.conn
