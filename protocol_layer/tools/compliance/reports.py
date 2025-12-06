from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .database import ComplianceDB
from .iso_rules import ISO27001RuleBook

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class ReportGenerator:
    """Generates compliance reports."""

    __slots__ = ("db", "rule_book")

    def __init__(self, db: ComplianceDB | None = None) -> None:
        self.db = db or ComplianceDB()
        self.rule_book = ISO27001RuleBook()

    def _generate_report_id(self, report_type: str, hostname: str | None) -> str:
        """Generate unique report ID."""
        content = f"{report_type}-{hostname or 'fleet'}-{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _store_json_report(
        self,
        *,
        report_id: str,
        report_type: str,
        content: dict[str, Any],
        hostname: str | None = None,
    ) -> None:
        """Persist a JSON report without duplicating serialization logic."""
        self.db.store_report(
            report_id=report_id,
            report_type=report_type,
            hostname=hostname,
            content=json.dumps(content),
            format="json",
        )

    def _get_status_label(self, score: float) -> str:
        """Get compliance status label from score."""
        if score >= 90:
            return "Compliant"
        if score >= 70:
            return "Partially Compliant"
        if score >= 50:
            return "Non-Compliant"
        return "Critical"

    def _calculate_risk_level(
        self,
        compliance_summary: dict[str, Any],
        event_stats: dict[str, Any],
        alerts: list[dict[str, Any]],
    ) -> str:
        """Calculate overall risk level."""
        score = compliance_summary.get("compliance_percentage", 0)
        critical_events = event_stats.get("by_severity", {}).get("critical", 0)

        if len(alerts) > 5 or critical_events > 10:
            return "Critical"
        if score < 50 or len(alerts) > 2:
            return "High"
        if score < 70 or len(alerts) > 0:
            return "Medium"
        return "Low"

    def _generate_remediation_plan(
        self, failing_controls: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Generate prioritized remediation plan."""
        sorted_controls = sorted(
            failing_controls,
            key=lambda x: _SEVERITY_ORDER.get(x.get("severity", "low"), 4),
        )

        return [
            {
                "priority": i + 1,
                "control_id": c.get("control_id", ""),
                "control_name": c.get("control_name", ""),
                "iso_clause": c.get("iso_clause", ""),
                "severity": c.get("severity", ""),
                "remediation": c.get("remediation", ""),
            }
            for i, c in enumerate(sorted_controls[:20])
        ]

    def generate_machine_report(
        self, hostname: str, include_history: bool = True
    ) -> dict[str, Any]:
        """Generate compliance report for a single machine."""
        report_id = self._generate_report_id("machine", hostname)
        now = datetime.now(timezone.utc)

        latest_scan = self.db.get_latest_scan(hostname)
        if not latest_scan:
            return {
                "report_id": report_id,
                "report_type": "machine",
                "hostname": hostname,
                "generated_at": now.isoformat(),
                "status": "no_data",
                "message": f"No compliance data found for {hostname}",
            }

        failing_controls = self.db.get_failing_controls(hostname)
        event_stats = self.db.get_event_stats(hostname, hours=24)
        alerts = self.db.get_unacknowledged_alerts(hostname)

        control_status = self.rule_book.evaluate_scan_results(latest_scan)
        compliance_summary = self.rule_book.get_compliance_summary(control_status)

        report: dict[str, Any] = {
            "report_id": report_id,
            "report_type": "machine",
            "hostname": hostname,
            "generated_at": now.isoformat(),
            "status": "complete",
            "executive_summary": {
                "compliance_status": self._get_status_label(
                    compliance_summary["compliance_percentage"]
                ),
                "compliance_score": compliance_summary["compliance_percentage"],
                "risk_level": self._calculate_risk_level(
                    compliance_summary, event_stats, alerts
                ),
                "controls_evaluated": compliance_summary["total_controls"],
                "controls_passed": compliance_summary["passed"],
                "controls_failed": compliance_summary["failed"],
                "controls_warning": compliance_summary["warnings"],
                "active_alerts": len(alerts),
                "events_24h": event_stats["total_events"],
            },
            "iso_compliance": {
                "by_category": compliance_summary["by_category"],
                "non_compliant_controls": compliance_summary["non_compliant_controls"],
                "control_details": {
                    clause: {
                        "name": status["name"],
                        "category": status["category"],
                        "status": status["overall_status"],
                        "checks": status["checks"],
                    }
                    for clause, status in control_status.items()
                },
            },
            "findings": {
                sev: [c for c in failing_controls if c["severity"] == sev]
                for sev in ("critical", "high", "medium", "low")
            },
            "remediation_plan": self._generate_remediation_plan(failing_controls),
            "security_events": {
                "summary": event_stats,
                "critical_events": event_stats.get("by_severity", {}).get(
                    "critical", 0
                ),
            },
            "alerts": {"unacknowledged": len(alerts), "details": alerts[:10]},
        }

        if include_history:
            report["compliance_trend"] = self.db.get_compliance_trend(hostname, days=30)
            report["scan_history"] = self.db.get_scan_history(hostname, limit=10)

        self._store_json_report(
            report_id=report_id,
            report_type="machine",
            hostname=hostname,
            content=report,
        )

        return report

    def generate_fleet_report(self) -> dict[str, Any]:
        """Generate compliance report for entire fleet."""
        report_id = self._generate_report_id("fleet", None)
        now = datetime.now(timezone.utc)

        fleet_summary = self.db.get_fleet_summary()

        if fleet_summary["total_machines"] == 0:
            return {
                "report_id": report_id,
                "report_type": "fleet",
                "generated_at": now.isoformat(),
                "status": "no_data",
                "message": "No machines registered in the system",
            }

        # Aggregate compliance by control across fleet
        control_compliance: dict[str, dict[str, int]] = {}
        for machine in fleet_summary["machines"]:
            scan = self.db.get_latest_scan(machine["hostname"])
            if not scan:
                continue

            for control in scan.get("controls", []):
                cid = control.get("control_id", "")
                if cid not in control_compliance:
                    control_compliance[cid] = {
                        "pass": 0,
                        "fail": 0,
                        "warning": 0,
                        "total": 0,
                    }
                control_compliance[cid]["total"] += 1
                status = control.get("status", "unknown")
                if status in control_compliance[cid]:
                    control_compliance[cid][status] += 1

        common_failures = sorted(
            [
                {
                    "control_id": cid,
                    "fail_rate": round((stats["fail"] / stats["total"]) * 100, 1),
                    "machines_affected": stats["fail"],
                }
                for cid, stats in control_compliance.items()
                if stats["fail"] > 0
            ],
            key=lambda x: x["fail_rate"],
            reverse=True,
        )[:10]

        def get_fleet_health() -> str:
            score = fleet_summary.get("average_score", 0)
            critical = fleet_summary.get("machines_with_critical", 0)
            if critical > 0:
                return "Critical"
            if score >= 80:
                return "Healthy"
            if score >= 60:
                return "Needs Attention"
            return "At Risk"

        def generate_recommendations() -> list[str]:
            recommendations = []
            if fleet_summary.get("machines_with_critical", 0) > 0:
                recommendations.append(
                    "CRITICAL: Address critical findings on affected machines immediately"
                )
            if fleet_summary.get("average_score", 100) < 70:
                recommendations.append(
                    "Fleet compliance score is below threshold - initiate remediation program"
                )
            if common_failures:
                top = common_failures[0]
                recommendations.append(
                    f"Most common failure ({top['control_id']}): affects {top['machines_affected']} machines - consider fleet-wide fix"
                )
            if (
                fleet_summary.get("non_compliant_machines", 0)
                > fleet_summary.get("total_machines", 1) / 2
            ):
                recommendations.append(
                    "More than 50% of fleet is non-compliant - review baseline configurations"
                )
            return recommendations or ["Fleet is in good compliance standing"]

        report = {
            "report_id": report_id,
            "report_type": "fleet",
            "generated_at": now.isoformat(),
            "status": "complete",
            "executive_summary": {
                "total_machines": fleet_summary["total_machines"],
                "compliant_machines": fleet_summary["compliant_machines"],
                "non_compliant_machines": fleet_summary["non_compliant_machines"],
                "machines_with_critical": fleet_summary["machines_with_critical"],
                "average_compliance_score": fleet_summary["average_score"],
                "fleet_health": get_fleet_health(),
            },
            "machines": [
                {
                    "hostname": m["hostname"],
                    "compliance_score": m["score"],
                    "status": self._get_status_label(m["score"] or 0),
                    "failed_controls": m["failed_controls"],
                    "critical_findings": m["critical_findings"],
                    "last_scan": m["last_scan"],
                }
                for m in fleet_summary["machines"]
            ],
            "common_failures": common_failures,
            "control_compliance": control_compliance,
            "recommendations": generate_recommendations(),
        }

        self._store_json_report(
            report_id=report_id,
            report_type="fleet",
            content=report,
        )
        return report

    def generate_daily_report(self) -> dict[str, Any]:
        """Generate automated daily compliance report."""
        report_id = self._generate_report_id("daily", None)
        now = datetime.now(timezone.utc)

        fleet_summary = self.db.get_fleet_summary()
        all_alerts = self.db.get_unacknowledged_alerts()
        all_events = self.db.get_recent_events(limit=1000)
        critical_events = [e for e in all_events if e.get("severity") == "critical"]

        def generate_daily_actions() -> list[str]:
            actions = []
            if all_alerts:
                actions.append(
                    f"Review and acknowledge {len(all_alerts)} unacknowledged security alerts"
                )

            non_compliant = [
                m
                for m in fleet_summary.get("machines", [])
                if (m.get("score") or 0) < 80
            ]
            if non_compliant:
                machines = ", ".join(m["hostname"] for m in non_compliant[:3])
                if len(non_compliant) > 3:
                    machines += f" (+{len(non_compliant) - 3} more)"
                actions.append(f"Address compliance issues on: {machines}")

            critical_machines = [
                m
                for m in fleet_summary.get("machines", [])
                if (m.get("critical_findings") or 0) > 0
            ]
            if critical_machines:
                actions.append(
                    f"PRIORITY: Resolve critical findings on {len(critical_machines)} machine(s)"
                )

            return actions or ["No immediate actions required - maintain monitoring"]

        report = {
            "report_id": report_id,
            "report_type": "daily",
            "generated_at": now.isoformat(),
            "report_date": now.strftime("%Y-%m-%d"),
            "status": "complete",
            "summary": {
                "fleet_compliance_score": fleet_summary["average_score"],
                "total_machines": fleet_summary["total_machines"],
                "compliant_machines": fleet_summary["compliant_machines"],
                "machines_requiring_attention": fleet_summary["non_compliant_machines"],
                "unacknowledged_alerts": len(all_alerts),
                "critical_events_24h": len(
                    [
                        e
                        for e in critical_events
                        if e.get("timestamp", "").startswith(now.strftime("%Y-%m-%d"))
                    ]
                ),
            },
            "machines_status": [
                {
                    "hostname": m["hostname"],
                    "score": m["score"],
                    "status": self._get_status_label(m["score"] or 0),
                    "needs_attention": (m["score"] or 0) < 80
                    or (m["critical_findings"] or 0) > 0,
                }
                for m in fleet_summary["machines"]
            ],
            "priority_alerts": all_alerts[:20],
            "action_items": generate_daily_actions(),
        }

        self._store_json_report(
            report_id=report_id,
            report_type="daily",
            content=report,
        )
        return report

    def generate_html_report(self, report_data: dict[str, Any]) -> str:
        """Generate HTML version of a report."""
        report_type = report_data.get("report_type", "unknown")
        generated_at = report_data.get("generated_at", "")

        def status_class(score: float) -> str:
            return (
                "status-compliant"
                if score >= 80
                else "status-warning" if score >= 60 else "status-critical"
            )

        def risk_class(risk: str) -> str:
            return (
                "status-critical"
                if risk.lower() in ("critical", "high")
                else (
                    "status-warning" if risk.lower() == "medium" else "status-compliant"
                )
            )

        def badge_class(status: str) -> str:
            s = status.lower()
            return (
                "badge-pass"
                if s == "compliant"
                else (
                    "badge-fail"
                    if s in ("non-compliant", "critical")
                    else "badge-warning"
                )
            )

        def render_card(title: str, value: Any, value_class: str = "") -> str:
            value_cls = f" {value_class}" if value_class else ""
            return (
                '<div class="card">'
                f'<div class="card-title">{title}</div>'
                f'<div class="card-value{value_cls}">{value}</div>'
                "</div>"
            )

        def render_grid(cards: list[str]) -> str:
            return f'<div class="grid">{"".join(cards)}</div>'

        html_parts = [
            f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ISO 27001 Compliance Report - {report_type.title()}</title>
    <style>
        :root {{
            --bg:#161616;
            --panel:#262626;
            --text:#f2f4f8;
            --muted:#c1c7cd;
            --border:#393939;
            --green:#42be65;
            --red:#ee5396;
            --yellow:#ff7eb6;
            --blue:#33b1ff;
        }}
        *{{box-sizing:border-box;margin:0;padding:0;}}
        body{{font-family:ui-sans-serif,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);line-height:1.45;padding:20px;}}
        .container{{max-width:1180px;margin:0 auto;}}
        header{{margin-bottom:18px;}}
        h1{{font-size:1.75rem;font-weight:700;margin-bottom:4px;}}
        .subtitle{{color:var(--muted);font-size:0.9rem;}}
        .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:14px;}}
        .card{{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:12px;}}
        .card-title{{font-size:0.72rem;letter-spacing:0.3px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;}}
        .card-value{{font-size:1.8rem;font-weight:700;}}
        .status-compliant{{color:var(--green);}}
        .status-warning{{color:var(--yellow);}}
        .status-critical{{color:var(--red);}}
        .status-info{{color:var(--blue);}}
        .section{{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:12px;margin-top:10px;}}
        .section-title{{font-size:1rem;font-weight:700;margin-bottom:8px;}}
        table{{width:100%;border-collapse:collapse;font-size:0.95rem;}}
        th,td{{padding:9px 6px;border-bottom:1px solid var(--border);}}
        th{{color:var(--muted);font-size:0.78rem;text-transform:uppercase;font-weight:600;}}
        .badge{{display:inline-block;padding:3px 7px;border-radius:4px;font-size:0.72rem;font-weight:650;background:rgba(255,92,92,0.12);color:var(--red);}}
        .badge-pass{{background:rgba(62,207,142,0.12);color:var(--green);}}
        .badge-warning{{background:rgba(247,201,72,0.12);color:var(--yellow);}}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ISO 27001 Compliance Report</h1>
            <p class="subtitle">Type: {report_type.title()} | Generated: {generated_at}</p>
        </header>
"""
        ]

        if report_type == "machine":
            summary = report_data.get("executive_summary", {})
            score = summary.get("compliance_score", 0)
            findings = report_data.get("findings", {})

            html_parts.extend(
                [
                    render_grid(
                        [
                            render_card(
                                "Hostname",
                                report_data.get("hostname", "Unknown"),
                                "status-info",
                            ),
                            render_card(
                                "Compliance Score", f"{score}%", status_class(score)
                            ),
                            render_card(
                                "Status",
                                summary.get("compliance_status", "Unknown"),
                                status_class(score),
                            ),
                            render_card(
                                "Risk Level",
                                summary.get("risk_level", "Unknown"),
                                risk_class(summary.get("risk_level", "Unknown")),
                            ),
                        ]
                    ),
                    render_grid(
                        [
                            render_card(
                                "Controls Passed",
                                summary.get("controls_passed", 0),
                                "status-compliant",
                            ),
                            render_card(
                                "Controls Failed",
                                summary.get("controls_failed", 0),
                                "status-critical",
                            ),
                            render_card(
                                "Active Alerts",
                                summary.get("active_alerts", 0),
                                "status-warning",
                            ),
                            render_card(
                                "Events (24h)",
                                summary.get("events_24h", 0),
                                "status-info",
                            ),
                        ]
                    ),
                    """
        <div class="section">
            <h2 class="section-title">Critical Findings</h2>
            <table>
                <thead><tr><th>Control</th><th>ISO Clause</th><th>Severity</th><th>Details</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>""".format(
                        rows="".join(
                            f'<tr><td>{f.get("control_name","")}</td>'
                            f'<td>{f.get("iso_clause","")}</td>'
                            f'<td><span class="badge badge-fail">{f.get("severity","")}</span></td>'
                            f'<td>{f.get("details","")[:100]}...</td></tr>'
                            for f in (
                                findings.get("critical", []) + findings.get("high", [])
                            )[:10]
                        )
                        or '<tr><td colspan="4">No critical findings</td></tr>'
                    ),
                ]
            )

        elif report_type == "fleet":
            summary = report_data.get("executive_summary", {})
            html_parts.extend(
                [
                    render_grid(
                        [
                            render_card(
                                "Total Machines",
                                summary.get("total_machines", 0),
                                "status-info",
                            ),
                            render_card(
                                "Compliant",
                                summary.get("compliant_machines", 0),
                                "status-compliant",
                            ),
                            render_card(
                                "Non-Compliant",
                                summary.get("non_compliant_machines", 0),
                                "status-critical",
                            ),
                            render_card(
                                "Avg Score",
                                f"{summary.get('average_compliance_score', 0)}%",
                                status_class(
                                    summary.get("average_compliance_score", 0)
                                ),
                            ),
                        ]
                    ),
                    """
        <div class="section">
            <h2 class="section-title">Machine Status</h2>
            <table>
                <thead><tr><th>Hostname</th><th>Score</th><th>Status</th><th>Failed Controls</th><th>Last Scan</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>""".format(
                        rows="".join(
                            f'<tr><td>{m.get("hostname","")}</td>'
                            f'<td>{m.get("compliance_score",0)}%</td>'
                            f'<td><span class="badge {badge_class(m.get("status",""))}">{m.get("status","")}</span></td>'
                            f'<td>{m.get("failed_controls",0)}</td>'
                            f'<td>{m.get("last_scan","")[:10]}</td></tr>'
                            for m in report_data.get("machines", [])[:20]
                        )
                    ),
                ]
            )

        elif report_type == "daily":
            summary = report_data.get("summary", {})
            html_parts.extend(
                [
                    render_grid(
                        [
                            render_card(
                                "Fleet Score",
                                f"{summary.get('fleet_compliance_score', 0)}%",
                                status_class(summary.get("fleet_compliance_score", 0)),
                            ),
                            render_card(
                                "Machines Requiring Attention",
                                summary.get("machines_requiring_attention", 0),
                                "status-warning",
                            ),
                            render_card(
                                "Unacknowledged Alerts",
                                summary.get("unacknowledged_alerts", 0),
                                "status-critical",
                            ),
                            render_card(
                                "Critical Events (24h)",
                                summary.get("critical_events_24h", 0),
                                "status-critical",
                            ),
                        ]
                    ),
                    """
        <div class="section">
            <h2 class="section-title">Action Items</h2>
            <ul style="list-style:none;padding:0;">{items}</ul>
        </div>""".format(
                        items="".join(
                            f'<li style="padding:0.5rem 0;border-bottom:1px solid var(--border);">• {action}</li>'
                            for action in report_data.get("action_items", [])[:10]
                        )
                        or "<li>No immediate actions required</li>"
                    ),
                ]
            )

        html_parts.append(
            """
    </div>
</body>
</html>"""
        )

        return "".join(html_parts)
