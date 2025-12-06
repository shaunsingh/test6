from __future__ import annotations

from datetime import datetime, timezone

from protocol_layer.tools.compliance import (
    ComplianceDB,
    ISO27001RuleBook,
    ReportGenerator,
)


def _sample_scan() -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "hostname": "edge-1",
        "timestamp": now,
        "summary": {
            "compliance_percentage": 75.0,
            "total_controls": 2,
            "passed": 1,
            "failed": 1,
            "warnings": 0,
            "critical_findings": 1,
        },
        "controls": [
            {
                "control_id": "A.9.2.3-1",
                "control_name": "SSH Root Login Disabled",
                "iso_clause": "A.9.2.3",
                "status": "fail",
                "severity": "critical",
                "details": "Root login enabled",
                "remediation": "Disable PermitRootLogin or switch to key auth.",
            },
            {
                "control_id": "A.9.4.3-1",
                "control_name": "Password Complexity",
                "iso_clause": "A.9.4.3",
                "status": "pass",
                "severity": "high",
                "details": "Meets policy",
                "remediation": "",
            },
        ],
    }


def test_compliance_pipeline_end_to_end() -> None:
    db = ComplianceDB(":memory:")
    scan = _sample_scan()

    scan_id = db.store_scan("edge-1", scan)
    assert scan_id > 0

    latest = db.get_latest_scan("edge-1")
    assert latest is not None
    assert latest["summary"]["compliance_percentage"] == 75.0

    rule_book = ISO27001RuleBook()
    control_status = rule_book.evaluate_scan_results(scan)
    summary = rule_book.get_compliance_summary(control_status)

    clauses = {item["clause"] for item in summary["non_compliant_controls"]}
    assert "A.9.2.3" in clauses

    # events + alerts feed downstream reporting logic
    db.store_events(
        "edge-1",
        [
            {
                "event_type": "USER_LOGIN",
                "severity": "info",
                "message": "sshd accepted publickey",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            {
                "event_type": "FAILED_LOGINS",
                "severity": "critical",
                "message": "5 failed logins in 60 seconds",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        ],
    )
    alert_id = db.store_critical_alert(
        "edge-1",
        "security_critical",
        [{"event": "Root login enabled"}],
    )
    assert alert_id > 0
    assert db.get_unacknowledged_alerts()

    reports = ReportGenerator(db)
    machine_report = reports.generate_machine_report("edge-1", include_history=False)
    assert machine_report["status"] == "complete"
    score = machine_report["executive_summary"]["compliance_score"]
    assert 0 <= score <= 100
    assert machine_report["executive_summary"]["controls_failed"] >= 1

    fleet_report = reports.generate_fleet_report()
    assert fleet_report["executive_summary"]["total_machines"] == 1

    daily_report = reports.generate_daily_report()
    assert daily_report["status"] == "complete"
    assert daily_report["summary"]["total_machines"] >= 1
