"""MCP Tools for ISO 27001 Compliance Monitoring.

Provides tools for:
- Ingesting compliance scan data from sensors
- Ingesting security events
- Handling critical alerts
- Generating compliance reports
- Querying compliance status
"""

from __future__ import annotations

import logging
import os
from functools import wraps
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from .database import ComplianceDB
from .evaluator import ComplianceEvaluator
from .iso_rules import ISO27001RuleBook, ISOControl
from .reports import ReportGenerator

load_dotenv()
log = logging.getLogger(__name__)

__all__ = [
    "ISO27001RuleBook",
    "ISOControl",
    "ComplianceDB",
    "ComplianceEvaluator",
    "ReportGenerator",
    "register_compliance_tools",
]

# Lazy-initialized singletons
_db: ComplianceDB | None = None
_rule_book: ISO27001RuleBook | None = None
_evaluator: ComplianceEvaluator | None = None
_report_gen: ReportGenerator | None = None


def _get_db() -> ComplianceDB:
    global _db
    if _db is None:
        _db = ComplianceDB(os.getenv("COMPLIANCE_DB_PATH", "compliance.db"))
    return _db


def _get_rule_book() -> ISO27001RuleBook:
    global _rule_book
    if _rule_book is None:
        _rule_book = ISO27001RuleBook()
    return _rule_book


def _get_evaluator() -> ComplianceEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = ComplianceEvaluator()
    return _evaluator


def _get_report_gen() -> ReportGenerator:
    global _report_gen
    if _report_gen is None:
        _report_gen = ReportGenerator(_get_db())
    return _report_gen


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool_handler(fn):
    """Wrap tool handlers with consistent error handling."""

    @wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except Exception as e:  # pragma: no cover - defensive
            log.exception("Tool %s failed", fn.__name__)
            return {"status": "error", "message": str(e)}

    return wrapper


# Pydantic Models


class IngestScanRequest(BaseModel):
    hostname: str = Field(..., description="Hostname of the scanned machine")
    scan_data: dict[str, Any] = Field(
        ..., description="Complete scan results from sensor"
    )


class IngestEventsRequest(BaseModel):
    hostname: str = Field(..., description="Hostname source of events")
    events: list[dict[str, Any]] = Field(
        ..., description="List of security events to ingest"
    )


class IngestAlertRequest(BaseModel):
    hostname: str = Field(..., description="Hostname source of alert")
    alert_type: str = Field(..., description="Type of alert (e.g., security_critical)")
    events: list[dict[str, Any]] = Field(..., description="Events triggering the alert")
    timestamp: str | None = Field(None, description="Alert timestamp (ISO format)")


class ComplianceQueryRequest(BaseModel):
    hostname: str = Field(..., description="Hostname to query")


class FleetQueryRequest(BaseModel):
    pass


class ReportRequest(BaseModel):
    hostname: str | None = Field(None, description="Hostname (None for fleet report)")
    report_type: str = Field(
        "machine", description="Report type: machine, fleet, or daily"
    )
    format: str = Field("json", description="Output format: json or html")


class EventQueryRequest(BaseModel):
    hostname: str | None = Field(None, description="Filter by hostname")
    severity: str | None = Field(None, description="Filter by severity")
    limit: int = Field(100, description="Maximum events to return")


class AlertAckRequest(BaseModel):
    alert_id: int = Field(..., description="Alert ID to acknowledge")
    acknowledged_by: str = Field(..., description="User acknowledging the alert")


class AIAnalysisRequest(BaseModel):
    hostname: str = Field(..., description="Hostname to analyze")
    analysis_type: str = Field("compliance", description="Type: compliance or events")


class HistoryRequest(BaseModel):
    hostname: str = Field(..., description="Hostname to get history for")
    days: int = Field(30, description="Number of days of history")


class ISOControlQuery(BaseModel):
    clause: str | None = Field(None, description="Specific clause to query")
    category: str | None = Field(None, description="Filter by category")


def register_compliance_tools(mcp: FastMCP) -> None:
    """Register all compliance monitoring tools with MCP server."""

    @mcp.tool()
    @_tool_handler
    async def ingest_compliance_scan(params: IngestScanRequest) -> dict[str, Any]:
        """Ingest compliance scan results from a sensor."""
        scan_id = _get_db().store_scan(params.hostname, params.scan_data)
        control_status = _get_rule_book().evaluate_scan_results(params.scan_data)
        summary = _get_rule_book().get_compliance_summary(control_status)

        log.info(
            "Ingested scan %s from %s: score=%.1f%%",
            scan_id,
            params.hostname,
            summary["compliance_percentage"],
        )

        return {
            "status": "success",
            "scan_id": scan_id,
            "hostname": params.hostname,
            "compliance_score": summary["compliance_percentage"],
            "controls_passed": summary["passed"],
            "controls_failed": summary["failed"],
            "timestamp": _now_iso(),
        }

    @mcp.tool()
    @_tool_handler
    async def ingest_security_events(params: IngestEventsRequest) -> dict[str, Any]:
        """Ingest security events from a sensor."""
        count = _get_db().store_events(params.hostname, params.events)
        log.info("Ingested %d events from %s", count, params.hostname)
        return {
            "status": "success",
            "hostname": params.hostname,
            "events_ingested": count,
            "timestamp": _now_iso(),
        }

    @mcp.tool()
    @_tool_handler
    async def ingest_critical_alert(params: IngestAlertRequest) -> dict[str, Any]:
        """Ingest a critical security alert requiring immediate attention."""
        alert_id = _get_db().store_critical_alert(
            params.hostname, params.alert_type, params.events
        )
        log.warning(
            "CRITICAL ALERT from %s: type=%s, events=%d, id=%d",
            params.hostname,
            params.alert_type,
            len(params.events),
            alert_id,
        )
        return {
            "status": "success",
            "alert_id": alert_id,
            "hostname": params.hostname,
            "alert_type": params.alert_type,
            "event_count": len(params.events),
            "timestamp": _now_iso(),
            "message": "Critical alert recorded - requires acknowledgment",
        }

    @mcp.tool()
    @_tool_handler
    async def get_compliance_status(params: ComplianceQueryRequest) -> dict[str, Any]:
        """Get current compliance status for a machine."""
        db, rb = _get_db(), _get_rule_book()
        latest_scan = db.get_latest_scan(params.hostname)
        if not latest_scan:
            return {"status": "error", "message": f"No scan data for {params.hostname}"}

        failing_controls = db.get_failing_controls(params.hostname)
        control_status = rb.evaluate_scan_results(latest_scan)
        summary = rb.get_compliance_summary(control_status)

        return {
            "status": "success",
            "hostname": params.hostname,
            "compliance_score": summary["compliance_percentage"],
            "assessment": (
                "Compliant"
                if summary["compliance_percentage"] >= 80
                else "Non-Compliant"
            ),
            "total_controls": summary["total_controls"],
            "passed": summary["passed"],
            "failed": summary["failed"],
            "warnings": summary["warnings"],
            "failing_controls": failing_controls[:10],
            "by_category": summary["by_category"],
            "last_scan": latest_scan.get("timestamp"),
        }

    @mcp.tool()
    @_tool_handler
    async def get_fleet_status(params: FleetQueryRequest) -> dict[str, Any]:
        """Get compliance status across all monitored machines."""
        fleet_summary = _get_db().get_fleet_summary()
        return {"status": "success", **fleet_summary}

    @mcp.tool()
    @_tool_handler
    async def get_security_events(params: EventQueryRequest) -> dict[str, Any]:
        """Query security events from the compliance database."""
        events = _get_db().get_recent_events(
            hostname=params.hostname, severity=params.severity, limit=params.limit
        )
        return {
            "status": "success",
            "event_count": len(events),
            "filters": {"hostname": params.hostname, "severity": params.severity},
            "events": events,
        }

    @mcp.tool()
    @_tool_handler
    async def get_unacknowledged_alerts(
        params: ComplianceQueryRequest | None = None,
    ) -> dict[str, Any]:
        """Get all unacknowledged critical alerts."""
        hostname = params.hostname if params else None
        alerts = _get_db().get_unacknowledged_alerts(hostname)
        return {"status": "success", "alert_count": len(alerts), "alerts": alerts}

    @mcp.tool()
    @_tool_handler
    async def acknowledge_alert(params: AlertAckRequest) -> dict[str, Any]:
        """Acknowledge a critical alert."""
        success = _get_db().acknowledge_alert(params.alert_id, params.acknowledged_by)
        if success:
            log.info(
                "Alert %d acknowledged by %s",
                params.alert_id,
                params.acknowledged_by,
            )
            return {
                "status": "success",
                "alert_id": params.alert_id,
                "acknowledged_by": params.acknowledged_by,
                "timestamp": _now_iso(),
            }
        return {"status": "error", "message": f"Alert {params.alert_id} not found"}

    @mcp.tool()
    @_tool_handler
    async def get_compliance_history(params: HistoryRequest) -> dict[str, Any]:
        """Get compliance score history and trends for a machine."""
        db = _get_db()
        return {
            "status": "success",
            "hostname": params.hostname,
            "period_days": params.days,
            "trend": db.get_compliance_trend(params.hostname, params.days),
            "scan_history": db.get_scan_history(params.hostname, limit=params.days),
        }

    @mcp.tool()
    @_tool_handler
    async def generate_compliance_report(params: ReportRequest) -> dict[str, Any]:
        """Generate a compliance report."""
        rg = _get_report_gen()
        if params.report_type == "daily":
            report = rg.generate_daily_report()
        elif params.report_type == "fleet":
            report = rg.generate_fleet_report()
        elif params.hostname:
            report = rg.generate_machine_report(params.hostname)
        else:
            return {
                "status": "error",
                "message": "hostname required for machine reports",
            }

        if params.format == "html":
            return {
                "status": "success",
                "report_id": report.get("report_id"),
                "format": "html",
                "content": rg.generate_html_report(report),
            }
        return {
            "status": "success",
            "report_id": report.get("report_id"),
            "format": "json",
            "report": report,
        }

    @mcp.tool()
    @_tool_handler
    async def analyze_compliance_ai(params: AIAnalysisRequest) -> dict[str, Any]:
        """Use AI to analyze compliance status and provide recommendations."""
        db, evaluator = _get_db(), _get_evaluator()

        if params.analysis_type == "compliance":
            scan_data = db.get_latest_scan(params.hostname)
            if not scan_data:
                return {
                    "status": "error",
                    "message": f"No scan data for {params.hostname}",
                }

            assessment = await evaluator.evaluate_scan(scan_data)
            return {
                "status": "success",
                "hostname": params.hostname,
                "analysis_type": "compliance",
                "assessment": assessment.assessment,
                "risk_level": assessment.risk_level,
                "compliance_score": assessment.compliance_score,
                "summary": assessment.summary,
                "key_findings": list(assessment.key_findings),
                "remediation_priorities": list(assessment.remediation_priorities),
                "gaps_by_clause": assessment.gaps_by_clause,
                "generated_at": assessment.generated_at,
            }

        if params.analysis_type == "events":
            events = db.get_recent_events(hostname=params.hostname, limit=100)
            if not events:
                return {
                    "status": "success",
                    "hostname": params.hostname,
                    "analysis_type": "events",
                    "threat_level": "None",
                    "summary": "No recent events to analyze",
                }

            analysis = await evaluator.analyze_events(events, minutes=60)
            return {
                "status": "success",
                "hostname": params.hostname,
                "analysis_type": "events",
                "threat_level": analysis.threat_level,
                "indicators_of_compromise": list(analysis.indicators_of_compromise),
                "policy_violations": list(analysis.policy_violations),
                "anomalies_detected": list(analysis.anomalies_detected),
                "recommended_actions": list(analysis.recommended_actions),
                "summary": analysis.summary,
                "generated_at": analysis.generated_at,
            }

        return {
            "status": "error",
            "message": f"Unknown analysis type: {params.analysis_type}",
        }

    @mcp.tool()
    @_tool_handler
    async def get_iso_control_info(params: ISOControlQuery) -> dict[str, Any]:
        """Get information about ISO 27001 controls."""
        rb = _get_rule_book()

        if params.clause:
            control = rb.get_control(params.clause)
            if not control:
                return {
                    "status": "error",
                    "message": f"Control {params.clause} not found",
                }
            return {
                "status": "success",
                "control": {
                    "clause": control.clause,
                    "name": control.name,
                    "description": control.description,
                    "category": control.category,
                    "control_type": control.control_type,
                    "requirements": list(control.requirements),
                    "evidence_required": list(control.evidence_required),
                    "remediation_guidance": control.remediation_guidance,
                    "technical_checks": list(control.technical_checks),
                },
            }

        if params.category:
            controls = rb.get_controls_by_category(params.category)
            return {
                "status": "success",
                "category": params.category,
                "controls": [
                    {
                        "clause": c.clause,
                        "name": c.name,
                        "control_type": c.control_type,
                    }
                    for c in controls
                ],
            }

        return {
            "status": "success",
            "available_clauses": rb.get_all_clauses(),
            "categories": list({c.category for c in rb.controls.values()}),
        }

    @mcp.tool()
    @_tool_handler
    async def get_failing_controls_detail(
        params: ComplianceQueryRequest,
    ) -> dict[str, Any]:
        """Get detailed information about failing controls for a machine."""
        db, rb = _get_db(), _get_rule_book()
        failing = db.get_failing_controls(params.hostname)

        detailed = [
            {
                "check_id": ctrl["control_id"],
                "check_name": ctrl["control_name"],
                "severity": ctrl["severity"],
                "details": ctrl["details"],
                "iso_clause": iso.clause,
                "iso_name": iso.name,
                "iso_requirements": list(iso.requirements),
                "remediation": iso.remediation_guidance,
            }
            for ctrl in failing
            for iso in rb.get_controls_for_check(ctrl["control_id"])
        ]

        return {
            "status": "success",
            "hostname": params.hostname,
            "failing_count": len(detailed),
            "failing_controls": detailed,
        }
