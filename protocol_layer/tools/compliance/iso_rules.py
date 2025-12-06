"""ISO 27001:2022 Annex A Control Mappings

Digitized rule book for ISO 27001 technical controls.
Maps technical checks to ISO clauses with descriptions and requirements
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ISOControl:
    """Single ISO 27001 control definition."""

    clause: str
    name: str
    description: str
    category: str
    control_type: str  # preventive, detective, corrective
    technical_checks: tuple[str, ...]
    requirements: tuple[str, ...]
    evidence_required: tuple[str, ...]
    remediation_guidance: str


# ISO 27001:2022 Annex A Controls - Technical subset relevant to Linux systems
ISO_27001_CONTROLS: dict[str, ISOControl] = {
    "A.5.15": ISOControl(
        clause="A.5.15",
        name="Access Control",
        description="Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
        category="Organizational",
        control_type="preventive",
        technical_checks=("A.9.2.3-1", "A.9.2.3-2"),
        requirements=(
            "Access control policy documented and approved",
            "Access rights based on business needs",
            "Regular review of access rights",
        ),
        evidence_required=(
            "Access control policy document",
            "User access matrix",
            "Access review logs",
        ),
        remediation_guidance="Implement role-based access control (RBAC), disable direct root access, use sudo with proper configuration.",
    ),
    "A.8.8": ISOControl(
        clause="A.8.8",
        name="Management of Technical Vulnerabilities",
        description="Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure to such vulnerabilities shall be evaluated, and appropriate measures shall be taken.",
        category="Asset Management",
        control_type="detective",
        technical_checks=("A.12.6.1-1",),
        requirements=(
            "Vulnerability scanning program",
            "Patch management process",
            "Vulnerability assessment schedule",
        ),
        evidence_required=(
            "Vulnerability scan reports",
            "Patch deployment records",
            "Risk assessment documentation",
        ),
        remediation_guidance="Enable automatic security updates, implement vulnerability scanning, establish patch management SLAs.",
    ),
    "A.9.2.1": ISOControl(
        clause="A.9.2.1",
        name="User Registration and Deregistration",
        description="A formal user registration and de-registration process shall be implemented to enable assignment of access rights.",
        category="Access Control",
        control_type="preventive",
        technical_checks=("A.9.4.3-2",),
        requirements=(
            "Formal user provisioning process",
            "Unique user identifiers",
            "Timely deprovisioning of accounts",
        ),
        evidence_required=(
            "User provisioning procedures",
            "Account creation/deletion logs",
            "User account inventory",
        ),
        remediation_guidance="Implement centralized identity management, ensure all accounts have strong passwords, maintain user lifecycle procedures.",
    ),
    "A.9.2.3": ISOControl(
        clause="A.9.2.3",
        name="Management of Privileged Access Rights",
        description="The allocation and use of privileged access rights shall be restricted and controlled.",
        category="Access Control",
        control_type="preventive",
        technical_checks=("A.9.2.3-1", "A.9.2.3-2"),
        requirements=(
            "Privileged access limited to minimum necessary",
            "Separate administrative accounts",
            "Privileged access logging enabled",
        ),
        evidence_required=(
            "List of privileged accounts",
            "Sudo/admin access logs",
            "Privileged access review records",
        ),
        remediation_guidance="Disable root login, use sudo with proper logging, implement privileged access management (PAM).",
    ),
    "A.9.4.2": ISOControl(
        clause="A.9.4.2",
        name="Secure Log-on Procedures",
        description="Where required by the access control policy, access to systems and applications shall be controlled by a secure log-on procedure.",
        category="Access Control",
        control_type="preventive",
        technical_checks=("A.9.2.3-1", "A.13.1.1-3"),
        requirements=(
            "Authentication failure limiting",
            "Session timeout configured",
            "Multi-factor authentication where appropriate",
        ),
        evidence_required=(
            "Authentication configuration",
            "Login failure logs",
            "Session management settings",
        ),
        remediation_guidance="Configure fail2ban or similar, implement SSH key authentication, enable session timeouts.",
    ),
    "A.9.4.3": ISOControl(
        clause="A.9.4.3",
        name="Password Management System",
        description="Password management systems shall be interactive and shall ensure quality passwords.",
        category="Access Control",
        control_type="preventive",
        technical_checks=("A.9.4.3-1", "A.9.4.3-2", "A.9.4.3-3"),
        requirements=(
            "Minimum password length >= 12 characters",
            "Password complexity enforced",
            "Password history maintained",
            "Regular password rotation",
        ),
        evidence_required=(
            "Password policy configuration",
            "PAM configuration files",
            "/etc/login.defs settings",
        ),
        remediation_guidance="Configure pwquality with minlen=12, enforce complexity, set PASS_MAX_DAYS in login.defs.",
    ),
    "A.12.4.1": ISOControl(
        clause="A.12.4.1",
        name="Event Logging",
        description="Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
        category="Operations Security",
        control_type="detective",
        technical_checks=("A.12.4.1-1", "A.12.4.1-2", "A.12.4.1-3"),
        requirements=(
            "Comprehensive logging enabled",
            "Logs protected from tampering",
            "Log retention policy implemented",
            "Regular log review process",
        ),
        evidence_required=(
            "Audit configuration files",
            "Sample log entries",
            "Log review records",
        ),
        remediation_guidance="Enable auditd, configure comprehensive audit rules, implement log forwarding to SIEM.",
    ),
    "A.12.4.3": ISOControl(
        clause="A.12.4.3",
        name="Administrator and Operator Logs",
        description="System administrator and system operator activities shall be logged and the logs protected and regularly reviewed.",
        category="Operations Security",
        control_type="detective",
        technical_checks=("A.12.4.3-1", "A.12.4.1-3"),
        requirements=(
            "Admin actions logged",
            "Logs protected (permissions)",
            "Regular review of admin logs",
        ),
        evidence_required=(
            "Admin activity logs",
            "Log file permissions",
            "Review sign-off records",
        ),
        remediation_guidance="Ensure log files have 640 permissions, monitor /etc/passwd, /etc/shadow, /etc/sudoers changes.",
    ),
    "A.12.6.1": ISOControl(
        clause="A.12.6.1",
        name="Management of Technical Vulnerabilities",
        description="Information about technical vulnerabilities of information systems in use shall be obtained, exposure evaluated, and appropriate measures taken.",
        category="Operations Security",
        control_type="detective",
        technical_checks=("A.12.6.1-1",),
        requirements=(
            "Vulnerability information sources identified",
            "Timely patch evaluation",
            "Patch deployment within defined timeframes",
        ),
        evidence_required=(
            "Vulnerability feed subscriptions",
            "Patch management records",
            "Update configuration",
        ),
        remediation_guidance="Enable unattended-upgrades (Debian) or dnf-automatic (RHEL), implement vulnerability scanning.",
    ),
    "A.13.1.1": ISOControl(
        clause="A.13.1.1",
        name="Network Controls",
        description="Networks shall be managed and controlled to protect information in systems and applications.",
        category="Communications Security",
        control_type="preventive",
        technical_checks=("A.13.1.1-1", "A.13.1.1-2", "A.13.1.1-3"),
        requirements=(
            "Network segmentation implemented",
            "Firewall rules documented",
            "Unnecessary services disabled",
            "Secure protocols enforced",
        ),
        evidence_required=(
            "Network diagram",
            "Firewall rule documentation",
            "Port scan results",
        ),
        remediation_guidance="Enable firewalld/iptables, close unnecessary ports, disable weak SSH ciphers, use TLS 1.2+.",
    ),
    "A.14.2.5": ISOControl(
        clause="A.14.2.5",
        name="Secure System Engineering Principles",
        description="Principles for engineering secure systems shall be established, documented, maintained and applied to any information system implementation activities.",
        category="System Development",
        control_type="preventive",
        technical_checks=("A.14.2.5-1", "A.14.2.5-2", "A.14.2.5-3"),
        requirements=(
            "Security hardening baseline",
            "Secure configuration standards",
            "Defense in depth approach",
        ),
        evidence_required=(
            "Hardening standards document",
            "System configuration baselines",
            "Security architecture documentation",
        ),
        remediation_guidance="Apply CIS benchmarks, enable SELinux/AppArmor, configure secure kernel parameters.",
    ),
}


class ISO27001RuleBook:
    """Digitized ISO 27001 rule book for compliance evaluation."""

    __slots__ = ("controls", "_check_to_control_map")

    def __init__(self) -> None:
        self.controls = ISO_27001_CONTROLS
        self._check_to_control_map = self._build_check_map()

    def _build_check_map(self) -> dict[str, tuple[str, ...]]:
        """Build reverse map from technical check IDs to control clauses."""
        check_map: dict[str, list[str]] = {}
        for clause, control in self.controls.items():
            for check_id in control.technical_checks:
                check_map.setdefault(check_id, []).append(clause)
        return {k: tuple(v) for k, v in check_map.items()}

    def get_control(self, clause: str) -> ISOControl | None:
        """Get control by clause ID."""
        return self.controls.get(clause)

    def get_controls_for_check(self, check_id: str) -> list[ISOControl]:
        """Get all controls related to a technical check."""
        clauses = self._check_to_control_map.get(check_id, ())
        return [self.controls[c] for c in clauses if c in self.controls]

    def get_all_clauses(self) -> list[str]:
        """Get all clause IDs."""
        return list(self.controls.keys())

    def get_controls_by_category(self, category: str) -> list[ISOControl]:
        """Get controls by category."""
        return [c for c in self.controls.values() if c.category == category]

    def evaluate_scan_results(
        self, scan_results: dict[str, Any]
    ) -> dict[str, dict[str, Any]]:
        """Evaluate scan results against ISO controls."""
        control_status: dict[str, dict[str, Any]] = {}

        for control_result in scan_results.get("controls", []):
            check_id = control_result.get("control_id", "")
            status = control_result.get("status", "unknown")

            for clause in self._check_to_control_map.get(check_id, ()):
                if clause not in control_status:
                    iso_control = self.controls[clause]
                    control_status[clause] = {
                        "clause": clause,
                        "name": iso_control.name,
                        "category": iso_control.category,
                        "checks": [],
                        "overall_status": "pass",
                        "requirements": iso_control.requirements,
                        "remediation": iso_control.remediation_guidance,
                    }

                control_status[clause]["checks"].append(
                    {
                        "check_id": check_id,
                        "status": status,
                        "details": control_result.get("details", ""),
                        "severity": control_result.get("severity", "unknown"),
                    }
                )

                # Update overall status (worst case wins)
                current = control_status[clause]["overall_status"]
                if status == "fail":
                    control_status[clause]["overall_status"] = "fail"
                elif status == "warning" and current != "fail":
                    control_status[clause]["overall_status"] = "warning"
                elif status == "error" and current not in ("fail", "warning"):
                    control_status[clause]["overall_status"] = "error"

        return control_status

    def get_compliance_summary(
        self, control_status: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """Generate compliance summary from evaluated controls."""
        total = len(control_status)
        passed = sum(
            1 for c in control_status.values() if c["overall_status"] == "pass"
        )
        failed = sum(
            1 for c in control_status.values() if c["overall_status"] == "fail"
        )
        warnings = sum(
            1 for c in control_status.values() if c["overall_status"] == "warning"
        )

        by_category: dict[str, dict[str, int]] = {}
        for control in control_status.values():
            cat = control["category"]
            if cat not in by_category:
                by_category[cat] = {"total": 0, "passed": 0, "failed": 0}
            by_category[cat]["total"] += 1
            if control["overall_status"] == "pass":
                by_category[cat]["passed"] += 1
            elif control["overall_status"] == "fail":
                by_category[cat]["failed"] += 1

        return {
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "compliance_percentage": (
                round((passed / total) * 100, 2) if total > 0 else 0
            ),
            "by_category": by_category,
            "non_compliant_controls": [
                {
                    "clause": c["clause"],
                    "name": c["name"],
                    "remediation": c["remediation"],
                }
                for c in control_status.values()
                if c["overall_status"] == "fail"
            ],
        }

    def to_context_string(self) -> str:
        """Convert rule book to string for LLM context."""
        lines = ["# ISO 27001:2022 Annex A Controls Reference", ""]

        for clause, control in sorted(self.controls.items()):
            lines.extend(
                [
                    f"## {clause}: {control.name}",
                    f"Category: {control.category}",
                    f"Type: {control.control_type}",
                    f"\n{control.description}\n",
                    "**Requirements:**",
                    *[f"- {req}" for req in control.requirements],
                    f"\n**Remediation:** {control.remediation_guidance}\n",
                    "---\n",
                ]
            )

        return "\n".join(lines)
