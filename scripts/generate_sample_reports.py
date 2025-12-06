from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPLIANCE_DIR = REPO_ROOT / "protocol_layer" / "tools" / "compliance"
OUTPUT_DIR = REPO_ROOT / "out" / "sample_reports"


def load_report_generator():
    """Load ReportGenerator without triggering heavy package imports."""
    protocol_layer_pkg = types.ModuleType("protocol_layer")
    protocol_layer_pkg.__path__ = [str(REPO_ROOT / "protocol_layer")]
    tools_pkg = types.ModuleType("protocol_layer.tools")
    tools_pkg.__path__ = [str(REPO_ROOT / "protocol_layer" / "tools")]
    compliance_pkg = types.ModuleType("protocol_layer.tools.compliance")
    compliance_pkg.__path__ = [str(COMPLIANCE_DIR)]

    sys.modules["protocol_layer"] = protocol_layer_pkg
    sys.modules["protocol_layer.tools"] = tools_pkg
    sys.modules["protocol_layer.tools.compliance"] = compliance_pkg

    spec = importlib.util.spec_from_file_location(
        "protocol_layer.tools.compliance.reports", COMPLIANCE_DIR / "reports.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load reports.py for ReportGenerator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ReportGenerator


def sample_machine_report() -> dict:
    return {
        "report_type": "machine",
        "generated_at": "2025-12-05T12:00:00Z",
        "hostname": "prod-app-01.example.corp",
        "executive_summary": {
            "compliance_status": "Compliant",
            "compliance_score": 96.2,
            "risk_level": "Medium",
            "controls_evaluated": 180,
            "controls_passed": 162,
            "controls_failed": 9,
            "controls_warning": 9,
            "active_alerts": 3,
            "events_24h": 128,
        },
        "findings": {
            "critical": [
                {
                    "control_name": "CVE Patch Policy",
                    "iso_clause": "A.12.6.1",
                    "severity": "critical",
                    "details": (
                        "Kernel CVE-2025-12345 remains unpatched on prod-app-01; "
                        "exploit code exists in the wild and provides privilege escalation."
                    ),
                },
                {
                    "control_name": "SSH Hardening",
                    "iso_clause": "A.9.4.2",
                    "severity": "critical",
                    "details": (
                        "SSH permits password authentication and root login from "
                        "untrusted networks; MFA not enforced for administrative users."
                    ),
                },
                {
                    "control_name": "Secrets Rotation",
                    "iso_clause": "A.10.1.2",
                    "severity": "critical",
                    "details": (
                        "Long-lived API keys used by deployment pipeline exceed 180 days; "
                        "no rotation policy applied and keys shared across services."
                    ),
                },
                {
                    "control_name": "Database Encryption",
                    "iso_clause": "A.18.1.4",
                    "severity": "critical",
                    "details": (
                        "Primary database volume lacks at-rest encryption; "
                        "snapshot replicas inherit the same weakness across regions."
                    ),
                },
                {
                    "control_name": "Backup Integrity",
                    "iso_clause": "A.12.3.1",
                    "severity": "critical",
                    "details": (
                        "No evidence of successful restore tests in the last 90 days; "
                        "backup chain for Q4 missing verification metadata."
                    ),
                },
                {
                    "control_name": "Network Segmentation",
                    "iso_clause": "A.13.1.3",
                    "severity": "critical",
                    "details": (
                        "Production and staging share overlapping security groups; "
                        "lateral movement possible due to permissive east-west rules."
                    ),
                },
            ],
            "high": [
                {
                    "control_name": "TLS Configuration",
                    "iso_clause": "A.13.2.1",
                    "severity": "high",
                    "details": (
                        "TLS endpoint supports deprecated ciphers (TLS_RSA_WITH_3DES) "
                        "and allows TLSv1.0 handshakes from legacy clients."
                    ),
                },
                {
                    "control_name": "Audit Logging",
                    "iso_clause": "A.12.4.1",
                    "severity": "high",
                    "details": (
                        "Syslog forwarding disabled for 2 agents; audit trails missing "
                        "for sudo events between 02:00-04:00 UTC on 2025-12-04."
                    ),
                },
                {
                    "control_name": "Container Image Provenance",
                    "iso_clause": "A.14.2.5",
                    "severity": "high",
                    "details": (
                        "Images lack signed provenance; admission controller permit lists "
                        "unsigned images from unverified registries."
                    ),
                },
                {
                    "control_name": "Privileged Containers",
                    "iso_clause": "A.9.1.2",
                    "severity": "high",
                    "details": (
                        "Two Kubernetes workloads run with privileged escalation; "
                        "host PID namespace exposed to application containers."
                    ),
                },
            ],
        },
    }


def sample_fleet_report() -> dict:
    machines = [
        {
            "hostname": "edge-gateway-01.example.corp",
            "compliance_score": 95,
            "status": "Compliant",
            "failed_controls": 1,
            "critical_findings": 0,
            "last_scan": "2025-12-05T09:45:00Z",
        },
        {
            "hostname": "edge-gateway-02.example.corp",
            "compliance_score": 91,
            "status": "Compliant",
            "failed_controls": 2,
            "critical_findings": 0,
            "last_scan": "2025-12-05T09:40:00Z",
        },
        {
            "hostname": "app-frontend-01.example.corp",
            "compliance_score": 88,
            "status": "Partially Compliant",
            "failed_controls": 4,
            "critical_findings": 0,
            "last_scan": "2025-12-05T09:30:00Z",
        },
        {
            "hostname": "app-frontend-02.example.corp",
            "compliance_score": 86,
            "status": "Partially Compliant",
            "failed_controls": 5,
            "critical_findings": 1,
            "last_scan": "2025-12-05T09:25:00Z",
        },
        {
            "hostname": "app-backend-01.example.corp",
            "compliance_score": 82,
            "status": "Partially Compliant",
            "failed_controls": 6,
            "critical_findings": 1,
            "last_scan": "2025-12-05T09:20:00Z",
        },
        {
            "hostname": "app-backend-02.example.corp",
            "compliance_score": 78,
            "status": "Partially Compliant",
            "failed_controls": 7,
            "critical_findings": 1,
            "last_scan": "2025-12-05T09:15:00Z",
        },
        {
            "hostname": "payments-01.example.corp",
            "compliance_score": 74,
            "status": "Partially Compliant",
            "failed_controls": 8,
            "critical_findings": 2,
            "last_scan": "2025-12-05T09:10:00Z",
        },
        {
            "hostname": "payments-02.example.corp",
            "compliance_score": 72,
            "status": "Partially Compliant",
            "failed_controls": 8,
            "critical_findings": 2,
            "last_scan": "2025-12-05T09:05:00Z",
        },
        {
            "hostname": "analytics-01.example.corp",
            "compliance_score": 69,
            "status": "Non-Compliant",
            "failed_controls": 10,
            "critical_findings": 2,
            "last_scan": "2025-12-05T08:55:00Z",
        },
        {
            "hostname": "analytics-02.example.corp",
            "compliance_score": 67,
            "status": "Non-Compliant",
            "failed_controls": 11,
            "critical_findings": 2,
            "last_scan": "2025-12-05T08:50:00Z",
        },
        {
            "hostname": "batch-01.example.corp",
            "compliance_score": 66,
            "status": "Non-Compliant",
            "failed_controls": 11,
            "critical_findings": 3,
            "last_scan": "2025-12-05T08:40:00Z",
        },
        {
            "hostname": "batch-02.example.corp",
            "compliance_score": 64,
            "status": "Non-Compliant",
            "failed_controls": 12,
            "critical_findings": 3,
            "last_scan": "2025-12-05T08:35:00Z",
        },
        {
            "hostname": "ml-serving-01.example.corp",
            "compliance_score": 62,
            "status": "Non-Compliant",
            "failed_controls": 12,
            "critical_findings": 3,
            "last_scan": "2025-12-05T08:25:00Z",
        },
        {
            "hostname": "ml-serving-02.example.corp",
            "compliance_score": 61,
            "status": "Non-Compliant",
            "failed_controls": 12,
            "critical_findings": 3,
            "last_scan": "2025-12-05T08:20:00Z",
        },
        {
            "hostname": "cache-01.example.corp",
            "compliance_score": 59,
            "status": "Non-Compliant",
            "failed_controls": 13,
            "critical_findings": 3,
            "last_scan": "2025-12-05T08:10:00Z",
        },
        {
            "hostname": "cache-02.example.corp",
            "compliance_score": 57,
            "status": "Non-Compliant",
            "failed_controls": 13,
            "critical_findings": 3,
            "last_scan": "2025-12-05T08:05:00Z",
        },
        {
            "hostname": "db-01.example.corp",
            "compliance_score": 55,
            "status": "Non-Compliant",
            "failed_controls": 14,
            "critical_findings": 4,
            "last_scan": "2025-12-05T07:55:00Z",
        },
        {
            "hostname": "db-02.example.corp",
            "compliance_score": 53,
            "status": "Non-Compliant",
            "failed_controls": 14,
            "critical_findings": 4,
            "last_scan": "2025-12-05T07:50:00Z",
        },
        {
            "hostname": "jump-host-01.example.corp",
            "compliance_score": 48,
            "status": "Critical",
            "failed_controls": 16,
            "critical_findings": 5,
            "last_scan": "2025-12-05T07:40:00Z",
        },
        {
            "hostname": "jump-host-02.example.corp",
            "compliance_score": 44,
            "status": "Critical",
            "failed_controls": 18,
            "critical_findings": 6,
            "last_scan": "2025-12-05T07:35:00Z",
        },
    ]

    return {
        "report_type": "fleet",
        "generated_at": "2025-12-05T12:00:00Z",
        "executive_summary": {
            "total_machines": len(machines),
            "compliant_machines": 8,
            "non_compliant_machines": 12,
            "machines_with_critical": 5,
            "average_compliance_score": 71.8,
        },
        "machines": machines,
        "common_failures": [
            {
                "control_id": "A.9.2.1",
                "fail_rate": 65.0,
                "machines_affected": 13,
            },
            {
                "control_id": "A.12.4.1",
                "fail_rate": 45.0,
                "machines_affected": 9,
            },
            {
                "control_id": "A.13.1.1",
                "fail_rate": 40.0,
                "machines_affected": 8,
            },
        ],
        "control_compliance": {},
        "recommendations": [
            "Prioritize remediation for jump hosts with critical findings.",
            "Roll out hardened SSH baseline to analytics and batch nodes.",
            "Schedule encryption-at-rest checks for database tiers this week.",
        ],
    }


def sample_daily_report() -> dict:
    return {
        "report_type": "daily",
        "generated_at": "2025-12-05T12:00:00Z",
        "summary": {
            "fleet_compliance_score": 74.2,
            "total_machines": 20,
            "compliant_machines": 8,
            "machines_requiring_attention": 12,
            "unacknowledged_alerts": 18,
            "critical_events_24h": 6,
        },
        "machines_status": [],
        "priority_alerts": [],
        "action_items": [
            "Acknowledge and triage 18 unacknowledged SOC alerts.",
            "Patch CVE-2025-12345 on prod-app-01 and jump hosts.",
            "Disable password SSH authentication for all edge gateways.",
            "Enable audit log forwarding for app-backend-02 and cache-02.",
            "Rotate deployment pipeline secrets older than 180 days.",
            "Backfill encryption enforcement for database snapshots.",
            "Review privileged container workloads in kube-system namespace.",
            "Re-segment staging and production security groups.",
            "Add admission control policy for signed container images only.",
            "Schedule restore test for Q4 backups and document results.",
        ],
    }


def main() -> None:
    ReportGenerator = load_report_generator()
    generator = ReportGenerator(db=object())
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    samples = {
        "sample_machine_report.html": sample_machine_report(),
        "sample_fleet_report.html": sample_fleet_report(),
        "sample_daily_report.html": sample_daily_report(),
    }

    for filename, payload in samples.items():
        html = generator.generate_html_report(payload)
        path = OUTPUT_DIR / filename
        path.write_text(html, encoding="utf-8")
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
