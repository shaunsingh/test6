"""ISO 27001 Compliance Scanner, Technical Controls Implementation

Monitors 15+ technical controls mapped to ISO 27001 Annex A:
- A.9 Access Control
- A.12.4 Logging and Monitoring
- A.13.1 Network Security
- A.14.2 Security in Development
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache, partial
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ControlResult:
    """Result of a single control check."""

    control_id: str
    control_name: str
    iso_clause: str
    status: str  # "pass", "fail", "warning", "error"
    severity: str  # "critical", "high", "medium", "low", "info"
    details: str
    remediation: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def _run_cmd(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Execute command and return stdout, stderr, returncode."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1


@lru_cache(maxsize=32)
def _read_file_safe(path: str) -> str | None:
    """Read file contents safely, return None on error. Cached per-process to avoid repeat I/O."""
    try:
        return Path(path).read_text()
    except (OSError, PermissionError):
        return None


def _parse_sshd_config(content: str) -> dict[str, str]:
    """Parse sshd_config into key-value pairs."""
    config: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1]
    return config


class ComplianceScanner:
    """Scans Linux systems for ISO 27001 compliance controls."""

    def __init__(self, hostname: str | None = None):
        self.hostname = hostname or socket.gethostname()
        self.scan_id = hashlib.sha256(
            f"{self.hostname}-{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]

    def _result(
        self,
        control_id: str,
        control_name: str,
        iso_clause: str,
        *,
        status: str,
        severity: str,
        details: str,
        remediation: str | None = None,
        raw_data: dict[str, Any] | None = None,
    ) -> ControlResult:
        """Small helper to build ControlResult consistently."""
        return ControlResult(
            control_id=control_id,
            control_name=control_name,
            iso_clause=iso_clause,
            status=status,
            severity=severity,
            details=details,
            remediation=remediation,
            raw_data=raw_data or {},
        )

    def _factory(self, control_id: str, control_name: str, iso_clause: str):
        """Return a partial builder for a given control."""
        return partial(self._result, control_id, control_name, iso_clause)

    def scan_all(self) -> dict[str, Any]:
        """Execute all compliance checks and return structured report."""
        checks = (
            # A.9 Access Control
            self._check_root_login,
            self._check_password_policy,
            self._check_sudo_config,
            self._check_empty_passwords,
            self._check_password_aging,
            # A.12.4 Logging and Monitoring
            self._check_auditd_status,
            self._check_syslog_config,
            self._check_log_permissions,
            self._check_audit_rules,
            # A.13.1 Network Security
            self._check_firewall_status,
            self._check_open_ports,
            self._check_ssh_protocol,
            # A.14.2 Secure Development / System Hardening
            self._check_kernel_parameters,
            self._check_file_permissions,
            self._check_selinux_apparmor,
            self._check_unattended_upgrades,
        )

        max_workers = min(len(checks), (os.cpu_count() or 4))
        result_map: dict[int, ControlResult] = {}

        # Run independent checks concurrently to reduce total scan time.
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {
                executor.submit(check): idx for idx, check in enumerate(checks)
            }
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    result_map[idx] = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    result_map[idx] = ControlResult(
                        control_id="internal",
                        control_name="Scan Execution Error",
                        iso_clause="A.0",
                        status="error",
                        severity="high",
                        details=f"check failed: {exc}",
                    )

        results = [result_map[i] for i in range(len(checks))]

        passed = failed = warnings = critical = 0
        controls_payload: list[dict[str, Any]] = []

        for r in results:
            if r.status == "pass":
                passed += 1
            elif r.status == "fail":
                failed += 1
                if r.severity == "critical":
                    critical += 1
            elif r.status == "warning":
                warnings += 1

            controls_payload.append(
                {
                    "control_id": r.control_id,
                    "control_name": r.control_name,
                    "iso_clause": r.iso_clause,
                    "status": r.status,
                    "severity": r.severity,
                    "details": r.details,
                    "remediation": r.remediation,
                    "raw_data": r.raw_data,
                    "timestamp": r.timestamp,
                }
            )

        total_controls = len(results)
        score = round((passed / total_controls) * 100, 2) if total_controls else 0.0

        return {
            "scan_id": self.scan_id,
            "hostname": self.hostname,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_controls": total_controls,
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "critical_findings": critical,
                "compliance_score": score,
            },
            "controls": controls_payload,
        }

    # =========================================================================
    # A.9 Access Control
    # =========================================================================

    def _check_root_login(self) -> ControlResult:
        """A.9.2.3 - Check if root login via SSH is disabled."""
        make = self._factory(
            "A.9.2.3-1",
            "SSH Root Login Disabled",
            "A.9.2.3 Management of privileged access rights",
        )
        sshd_config = _read_file_safe("/etc/ssh/sshd_config")
        if sshd_config is None:
            return make(
                status="error",
                severity="critical",
                details="Cannot read /etc/ssh/sshd_config",
                raw_data={"error": "file_not_readable"},
            )

        config = _parse_sshd_config(sshd_config)
        permit_root = config.get("permitrootlogin", "yes").lower()

        if permit_root in ("no", "prohibit-password", "without-password"):
            return make(
                status="pass",
                severity="critical",
                details=f"Root login is properly restricted: PermitRootLogin={permit_root}",
                raw_data={"permit_root_login": permit_root},
            )

        return make(
            status="fail",
            severity="critical",
            details=f"Root login is enabled: PermitRootLogin={permit_root}",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            raw_data={"permit_root_login": permit_root},
        )

    def _check_password_policy(self) -> ControlResult:
        """A.9.4.3 - Check password complexity requirements."""
        make = self._factory(
            "A.9.4.3-1",
            "Password Complexity Requirements",
            "A.9.4.3 Password management system",
        )
        pwquality = _read_file_safe("/etc/security/pwquality.conf")
        pam_pwquality = _read_file_safe(
            "/etc/pam.d/common-password"
        ) or _read_file_safe("/etc/pam.d/system-auth")

        findings: dict[str, Any] = {"minlen": None, "dcredit": None, "ucredit": None}

        if pwquality:
            for line in pwquality.splitlines():
                line = line.strip()
                if line.startswith("minlen"):
                    match = re.search(r"minlen\s*=\s*(\d+)", line)
                    if match:
                        findings["minlen"] = int(match.group(1))
                elif line.startswith("dcredit"):
                    match = re.search(r"dcredit\s*=\s*(-?\d+)", line)
                    if match:
                        findings["dcredit"] = int(match.group(1))
                elif line.startswith("ucredit"):
                    match = re.search(r"ucredit\s*=\s*(-?\d+)", line)
                    if match:
                        findings["ucredit"] = int(match.group(1))

        minlen = findings.get("minlen") or 0
        has_complexity = (
            findings.get("dcredit") is not None or findings.get("ucredit") is not None
        )

        if minlen >= 12 and has_complexity:
            return make(
                status="pass",
                severity="high",
                details=f"Password policy configured: minlen={minlen}",
                raw_data=findings,
            )

        if minlen >= 8:
            return make(
                status="warning",
                severity="high",
                details=f"Password policy weak: minlen={minlen}, recommend >= 12",
                remediation="Set minlen=12 in /etc/security/pwquality.conf",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="high",
            details="Password complexity not configured or too weak",
            remediation="Configure /etc/security/pwquality.conf with minlen=12, dcredit=-1, ucredit=-1",
            raw_data=findings,
        )

    def _check_sudo_config(self) -> ControlResult:
        """A.9.2.3 - Check sudo configuration security."""
        make = self._factory(
            "A.9.2.3-2",
            "Sudo Configuration Security",
            "A.9.2.3 Management of privileged access rights",
        )
        sudoers = _read_file_safe("/etc/sudoers")
        findings: dict[str, Any] = {
            "nopasswd_users": [],
            "requiretty": False,
            "env_reset": False,
        }

        if sudoers is None:
            # Try visudo -c
            stdout, _, rc = _run_cmd(["visudo", "-c"])
            if rc != 0:
                return make(
                    status="error",
                    severity="high",
                    details="Cannot read sudoers configuration",
                    raw_data={"error": "cannot_read_sudoers"},
                )

        if sudoers:
            # Check for NOPASSWD
            nopasswd_pattern = re.compile(r"(\S+)\s+.*NOPASSWD", re.IGNORECASE)
            for match in nopasswd_pattern.finditer(sudoers):
                findings["nopasswd_users"].append(match.group(1))

            findings["requiretty"] = "requiretty" in sudoers.lower()
            findings["env_reset"] = "env_reset" in sudoers.lower()

        if findings["nopasswd_users"]:
            return make(
                status="warning",
                severity="high",
                details=f"NOPASSWD configured for: {', '.join(findings['nopasswd_users'])}",
                remediation="Remove NOPASSWD entries from sudoers unless absolutely necessary",
                raw_data=findings,
            )

        return make(
            status="pass",
            severity="high",
            details="Sudo configuration follows security best practices",
            raw_data=findings,
        )

    def _check_empty_passwords(self) -> ControlResult:
        """A.9.4.3 - Check for accounts with empty passwords."""
        make = self._factory(
            "A.9.4.3-2",
            "No Empty Passwords",
            "A.9.4.3 Password management system",
        )
        shadow = _read_file_safe("/etc/shadow")
        empty_password_users: list[str] = []

        if shadow is None:
            return make(
                status="error",
                severity="critical",
                details="Cannot read /etc/shadow (requires root)",
                raw_data={"error": "permission_denied"},
            )

        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                username, password_hash = parts[0], parts[1]
                # Empty or no password
                if password_hash == "":
                    empty_password_users.append(username)
                    continue
                if password_hash in ("!", "!!", "*"):
                    continue  # Locked or system account

        if empty_password_users:
            return make(
                status="fail",
                severity="critical",
                details=f"Accounts with empty passwords: {', '.join(empty_password_users)}",
                remediation="Set passwords for all accounts: passwd <username>",
                raw_data={"empty_password_users": empty_password_users},
            )

        return make(
            status="pass",
            severity="critical",
            details="No accounts with empty passwords found",
            raw_data={"empty_password_users": []},
        )

    def _check_password_aging(self) -> ControlResult:
        """A.9.4.3 - Check password aging configuration."""
        make = self._factory(
            "A.9.4.3-3",
            "Password Aging Policy",
            "A.9.4.3 Password management system",
        )
        login_defs = _read_file_safe("/etc/login.defs")
        findings = {"pass_max_days": 99999, "pass_min_days": 0, "pass_warn_age": 7}

        if login_defs:
            for line in login_defs.splitlines():
                line = line.strip()
                if line.startswith("PASS_MAX_DAYS"):
                    match = re.search(r"PASS_MAX_DAYS\s+(\d+)", line)
                    if match:
                        findings["pass_max_days"] = int(match.group(1))
                elif line.startswith("PASS_MIN_DAYS"):
                    match = re.search(r"PASS_MIN_DAYS\s+(\d+)", line)
                    if match:
                        findings["pass_min_days"] = int(match.group(1))
                elif line.startswith("PASS_WARN_AGE"):
                    match = re.search(r"PASS_WARN_AGE\s+(\d+)", line)
                    if match:
                        findings["pass_warn_age"] = int(match.group(1))

        max_days = findings["pass_max_days"]
        if max_days <= 90:
            return make(
                status="pass",
                severity="medium",
                details=f"Password expiry set to {max_days} days",
                raw_data=findings,
            )

        if max_days <= 365:
            return make(
                status="warning",
                severity="medium",
                details=f"Password expiry is {max_days} days, recommend <= 90",
                remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="medium",
            details=f"Password expiry too long: {max_days} days",
            remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs",
            raw_data=findings,
        )

    # =========================================================================
    # A.12.4 Logging and Monitoring
    # =========================================================================

    def _check_auditd_status(self) -> ControlResult:
        """A.12.4.1 - Check if auditd is running and enabled."""
        make = self._factory(
            "A.12.4.1-1",
            "Audit Daemon Running",
            "A.12.4.1 Event logging",
        )
        # Check if auditd is active
        stdout, _, rc = _run_cmd(["systemctl", "is-active", "auditd"])
        is_active = rc == 0 and stdout.strip() == "active"

        # Check if auditd is enabled
        stdout, _, rc = _run_cmd(["systemctl", "is-enabled", "auditd"])
        is_enabled = rc == 0 and stdout.strip() == "enabled"

        findings = {"is_active": is_active, "is_enabled": is_enabled}

        if is_active and is_enabled:
            return make(
                status="pass",
                severity="high",
                details="auditd is active and enabled",
                raw_data=findings,
            )

        if is_active:
            return make(
                status="warning",
                severity="high",
                details="auditd is active but not enabled at boot",
                remediation="Run: systemctl enable auditd",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="high",
            details="auditd is not running",
            remediation="Run: systemctl enable --now auditd",
            raw_data=findings,
        )

    def _check_syslog_config(self) -> ControlResult:
        """A.12.4.1 - Check syslog/rsyslog configuration."""
        make = self._factory(
            "A.12.4.1-2",
            "System Logging Configured",
            "A.12.4.1 Event logging",
        )
        rsyslog_conf = _read_file_safe("/etc/rsyslog.conf")
        journald_conf = _read_file_safe("/etc/systemd/journald.conf")

        findings = {
            "rsyslog_configured": rsyslog_conf is not None,
            "journald_persistent": False,
            "remote_logging": False,
        }

        # Check journald persistence
        if journald_conf:
            findings["journald_persistent"] = "Storage=persistent" in journald_conf

        # Check for remote logging
        if rsyslog_conf:
            findings["remote_logging"] = bool(
                re.search(r"@{1,2}[^\s]+", rsyslog_conf)  # @host or @@host
            )

        if findings["rsyslog_configured"] and (
            findings["journald_persistent"] or findings["remote_logging"]
        ):
            return make(
                status="pass",
                severity="high",
                details="Syslog is properly configured with persistence/remote logging",
                raw_data=findings,
            )

        if findings["rsyslog_configured"]:
            return make(
                status="warning",
                severity="high",
                details="Syslog configured but consider enabling persistent storage or remote logging",
                remediation="Set Storage=persistent in /etc/systemd/journald.conf",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="high",
            details="System logging not properly configured",
            remediation="Install and configure rsyslog or systemd-journald",
            raw_data=findings,
        )

    def _check_log_permissions(self) -> ControlResult:
        """A.12.4.3 - Check log file permissions."""
        make = self._factory(
            "A.12.4.3-1",
            "Log File Permissions",
            "A.12.4.3 Administrator and operator logs",
        )
        log_dirs = ["/var/log", "/var/log/audit"]
        insecure_logs: list[dict[str, Any]] = []

        for log_dir in log_dirs:
            if not os.path.exists(log_dir):
                continue

            try:
                for entry in os.scandir(log_dir):
                    if not entry.is_file():
                        continue
                    stat_info = entry.stat()
                    mode = stat_info.st_mode & 0o777

                    # Check if world-readable or world-writable
                    if mode & 0o007:  # Any world permissions
                        insecure_logs.append(
                            {
                                "path": entry.path,
                                "mode": oct(mode),
                                "issue": "world_accessible",
                            }
                        )
                    # Check if group-writable
                    elif mode & 0o020:
                        insecure_logs.append(
                            {
                                "path": entry.path,
                                "mode": oct(mode),
                                "issue": "group_writable",
                            }
                        )
            except PermissionError:
                continue

        if not insecure_logs:
            return make(
                status="pass",
                severity="medium",
                details="Log file permissions are properly restricted",
                raw_data={"checked_dirs": log_dirs},
            )

        return make(
            status="warning",
            severity="medium",
            details=f"Found {len(insecure_logs)} log files with insecure permissions",
            remediation="Run: chmod 640 <log_file> for affected files",
            raw_data={"insecure_logs": insecure_logs[:10]},  # Limit output
        )

    def _check_audit_rules(self) -> ControlResult:
        """A.12.4.1 - Check if critical audit rules are configured."""
        make = self._factory(
            "A.12.4.1-3",
            "Audit Rules Configured",
            "A.12.4.1 Event logging",
        )
        stdout, _, rc = _run_cmd(["auditctl", "-l"])
        if rc != 0:
            return make(
                status="error",
                severity="high",
                details="Cannot retrieve audit rules (auditctl not available or no permission)",
                raw_data={"error": "auditctl_failed"},
            )

        rules = stdout.strip()
        findings = {
            "total_rules": len(rules.splitlines()) if rules else 0,
            "monitors_passwd": "/etc/passwd" in rules,
            "monitors_shadow": "/etc/shadow" in rules,
            "monitors_sudoers": "/etc/sudoers" in rules,
            "monitors_logins": any(
                x in rules for x in ["/var/log/lastlog", "pam_unix"]
            ),
        }

        critical_monitors = sum(
            [
                findings["monitors_passwd"],
                findings["monitors_shadow"],
                findings["monitors_sudoers"],
                findings["monitors_logins"],
            ]
        )

        if critical_monitors >= 3:
            return make(
                status="pass",
                severity="high",
                details=f"Critical audit rules configured: {findings['total_rules']} total rules",
                raw_data=findings,
            )

        if findings["total_rules"] > 0:
            return make(
                status="warning",
                severity="high",
                details="Some audit rules configured but missing critical monitors",
                remediation="Add rules for /etc/passwd, /etc/shadow, /etc/sudoers, login events",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="high",
            details="No audit rules configured",
            remediation="Configure audit rules in /etc/audit/rules.d/",
            raw_data=findings,
        )

    # =========================================================================
    # A.13.1 Network Security
    # =========================================================================

    def _check_firewall_status(self) -> ControlResult:
        """A.13.1.1 - Check if firewall is active."""
        make = self._factory(
            "A.13.1.1-1",
            "Firewall Active",
            "A.13.1.1 Network controls",
        )
        findings = {
            "iptables_rules": 0,
            "nftables_active": False,
            "firewalld_active": False,
        }

        # Check firewalld
        stdout, _, rc = _run_cmd(["systemctl", "is-active", "firewalld"])
        findings["firewalld_active"] = rc == 0 and stdout.strip() == "active"

        # Check nftables
        stdout, _, rc = _run_cmd(["nft", "list", "ruleset"])
        if rc == 0 and stdout.strip():
            findings["nftables_active"] = True

        # Check iptables
        stdout, _, rc = _run_cmd(["iptables", "-L", "-n"])
        if rc == 0:
            # Count non-default rules
            findings["iptables_rules"] = len(
                [
                    l
                    for l in stdout.splitlines()
                    if l and not l.startswith(("Chain", "target"))
                ]
            )

        has_firewall = (
            findings["firewalld_active"]
            or findings["nftables_active"]
            or findings["iptables_rules"] > 0
        )

        if has_firewall:
            return make(
                status="pass",
                severity="critical",
                details="Firewall is active and configured",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="critical",
            details="No active firewall detected",
            remediation="Enable firewalld: systemctl enable --now firewalld",
            raw_data=findings,
        )

    def _check_open_ports(self) -> ControlResult:
        """A.13.1.1 - Check for unnecessary open ports."""
        make = self._factory(
            "A.13.1.1-2",
            "Open Port Analysis",
            "A.13.1.1 Network controls",
        )
        stdout, _, rc = _run_cmd(["ss", "-tuln"])
        if rc != 0:
            return make(
                status="error",
                severity="high",
                details="Cannot check open ports (ss command failed)",
                raw_data={"error": "ss_failed"},
            )

        listening_ports: list[dict[str, str]] = []
        dangerous_ports = {
            21,
            23,
            513,
            514,
            1099,
            3389,
            5900,
        }  # FTP, Telnet, rlogin, etc.
        found_dangerous: list[int] = []

        for line in stdout.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5 and "LISTEN" in line:
                local_addr = parts[4]
                # Extract port
                if ":" in local_addr:
                    port_str = local_addr.rsplit(":", 1)[-1]
                    try:
                        port = int(port_str)
                        listening_ports.append({"address": local_addr, "port": port})
                        if port in dangerous_ports:
                            found_dangerous.append(port)
                    except ValueError:
                        continue

        findings = {
            "total_listening": len(listening_ports),
            "dangerous_ports": found_dangerous,
            "sample_ports": listening_ports[:10],
        }

        if found_dangerous:
            return make(
                status="fail",
                severity="high",
                details=f"Dangerous ports open: {found_dangerous}",
                remediation="Disable insecure services (telnet, ftp, rsh) and close unnecessary ports",
                raw_data=findings,
            )

        if len(listening_ports) > 20:
            return make(
                status="warning",
                severity="high",
                details=f"High number of open ports: {len(listening_ports)}",
                remediation="Review and disable unnecessary services",
                raw_data=findings,
            )

        return make(
            status="pass",
            severity="high",
            details=f"Port configuration acceptable: {len(listening_ports)} listening ports",
            raw_data=findings,
        )

    def _check_ssh_protocol(self) -> ControlResult:
        """A.13.1.1 - Check SSH protocol and cipher configuration."""
        make = self._factory(
            "A.13.1.1-3",
            "SSH Protocol Security",
            "A.13.1.1 Network controls",
        )
        sshd_config = _read_file_safe("/etc/ssh/sshd_config")
        if sshd_config is None:
            return make(
                status="error",
                severity="high",
                details="Cannot read SSH configuration",
                raw_data={"error": "file_not_readable"},
            )

        config = _parse_sshd_config(sshd_config)
        findings = {
            "protocol": config.get("protocol", "2"),
            "ciphers": config.get("ciphers", "default"),
            "macs": config.get("macs", "default"),
            "password_auth": config.get("passwordauthentication", "yes"),
        }

        weak_ciphers = ["3des", "arcfour", "blowfish", "cast128"]
        has_weak = any(c in findings["ciphers"].lower() for c in weak_ciphers)

        if has_weak:
            return make(
                status="fail",
                severity="high",
                details="Weak SSH ciphers configured",
                remediation="Remove weak ciphers (3des, arcfour, blowfish) from sshd_config",
                raw_data=findings,
            )

        if findings["password_auth"].lower() == "yes":
            return make(
                status="warning",
                severity="medium",
                details="SSH password authentication enabled, consider key-only auth",
                remediation="Set PasswordAuthentication no and use SSH keys",
                raw_data=findings,
            )

        return make(
            status="pass",
            severity="high",
            details="SSH protocol configuration is secure",
            raw_data=findings,
        )

    # =========================================================================
    # A.14.2 Security in Development / System Hardening
    # =========================================================================

    def _check_kernel_parameters(self) -> ControlResult:
        """A.14.2.5 - Check kernel security parameters."""
        make = self._factory(
            "A.14.2.5-1",
            "Kernel Security Parameters",
            "A.14.2.5 Secure system engineering principles",
        )
        params_to_check = {
            "net.ipv4.ip_forward": "0",
            "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0",
            "net.ipv4.conf.all.accept_source_route": "0",
            "net.ipv4.conf.all.log_martians": "1",
            "kernel.randomize_va_space": "2",
        }

        findings: dict[str, Any] = {"params": {}, "insecure": []}

        for param, expected in params_to_check.items():
            stdout, _, rc = _run_cmd(["sysctl", "-n", param])
            actual = stdout.strip() if rc == 0 else "unknown"
            findings["params"][param] = actual
            if actual != expected and actual != "unknown":
                findings["insecure"].append(
                    {"param": param, "expected": expected, "actual": actual}
                )

        if not findings["insecure"]:
            return make(
                status="pass",
                severity="high",
                details="All checked kernel parameters are secure",
                raw_data=findings,
            )

        if len(findings["insecure"]) <= 2:
            return make(
                status="warning",
                severity="high",
                details=f"{len(findings['insecure'])} kernel parameters need adjustment",
                remediation="Update /etc/sysctl.conf with secure values",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="high",
            details="Multiple kernel parameters are insecure",
            remediation="Review and update /etc/sysctl.conf",
            raw_data=findings,
        )

    def _check_file_permissions(self) -> ControlResult:
        """A.14.2.5 - Check critical file permissions."""
        make = self._factory(
            "A.14.2.5-2",
            "Critical File Permissions",
            "A.14.2.5 Secure system engineering principles",
        )
        critical_files = {
            "/etc/passwd": 0o644,
            "/etc/shadow": 0o640,
            "/etc/group": 0o644,
            "/etc/gshadow": 0o640,
            "/etc/ssh/sshd_config": 0o600,
        }

        findings: dict[str, Any] = {"files": {}, "issues": []}

        for filepath, expected_mode in critical_files.items():
            if not os.path.exists(filepath):
                findings["files"][filepath] = "not_found"
                continue

            try:
                stat_info = os.stat(filepath)
                actual_mode = stat_info.st_mode & 0o777
                findings["files"][filepath] = oct(actual_mode)

                if actual_mode > expected_mode:
                    findings["issues"].append(
                        {
                            "file": filepath,
                            "expected": oct(expected_mode),
                            "actual": oct(actual_mode),
                        }
                    )
            except OSError:
                findings["files"][filepath] = "error"

        if not findings["issues"]:
            return make(
                status="pass",
                severity="high",
                details="Critical file permissions are correct",
                raw_data=findings,
            )

        return make(
            status="fail",
            severity="high",
            details=f"{len(findings['issues'])} files have incorrect permissions",
            remediation="Fix permissions: chmod <mode> <file>",
            raw_data=findings,
        )

    def _check_selinux_apparmor(self) -> ControlResult:
        """A.14.2.5 - Check if SELinux or AppArmor is enabled."""
        make = self._factory(
            "A.14.2.5-3",
            "Mandatory Access Control",
            "A.14.2.5 Secure system engineering principles",
        )
        findings = {"selinux": None, "apparmor": None}

        # Check SELinux
        if os.path.exists("/etc/selinux/config"):
            selinux_config = _read_file_safe("/etc/selinux/config")
            if selinux_config:
                match = re.search(r"SELINUX=(\w+)", selinux_config)
                if match:
                    findings["selinux"] = match.group(1)

        # Check AppArmor
        stdout, _, rc = _run_cmd(["aa-status", "--enabled"])
        if rc == 0:
            findings["apparmor"] = "enabled"
        elif os.path.exists("/sys/kernel/security/apparmor"):
            findings["apparmor"] = "available"

        selinux_enforcing = findings["selinux"] in ("enforcing", "permissive")
        apparmor_enabled = findings["apparmor"] == "enabled"

        if selinux_enforcing or apparmor_enabled:
            return make(
                status="pass",
                severity="medium",
                details="SELinux or AppArmor is active",
                raw_data=findings,
            )

        if findings["selinux"] == "permissive":
            return make(
                status="warning",
                severity="medium",
                details="SELinux is in permissive mode",
                remediation="Set SELINUX=enforcing in /etc/selinux/config",
                raw_data=findings,
            )

        return make(
            status="warning",
            severity="medium",
            details="Neither SELinux nor AppArmor is actively enforcing",
            remediation="Enable SELinux or AppArmor for mandatory access control",
            raw_data=findings,
        )

    def _check_unattended_upgrades(self) -> ControlResult:
        """A.12.6.1 - Check if automatic security updates are enabled."""
        make = self._factory(
            "A.12.6.1-1",
            "Automatic Security Updates",
            "A.12.6.1 Management of technical vulnerabilities",
        )
        findings = {"apt_auto": False, "yum_auto": False, "dnf_auto": False}

        # Check apt unattended-upgrades (Debian/Ubuntu)
        apt_auto = _read_file_safe("/etc/apt/apt.conf.d/20auto-upgrades")
        if apt_auto and 'Unattended-Upgrade "1"' in apt_auto:
            findings["apt_auto"] = True

        # Check yum-cron (RHEL/CentOS 7)
        stdout, _, rc = _run_cmd(["systemctl", "is-enabled", "yum-cron"])
        if rc == 0 and "enabled" in stdout:
            findings["yum_auto"] = True

        # Check dnf-automatic (RHEL/CentOS 8+)
        stdout, _, rc = _run_cmd(["systemctl", "is-enabled", "dnf-automatic.timer"])
        if rc == 0 and "enabled" in stdout:
            findings["dnf_auto"] = True

        if any([findings["apt_auto"], findings["yum_auto"], findings["dnf_auto"]]):
            return make(
                status="pass",
                severity="medium",
                details="Automatic security updates are enabled",
                raw_data=findings,
            )

        return make(
            status="warning",
            severity="medium",
            details="Automatic security updates are not enabled",
            remediation="Enable unattended-upgrades (Debian) or dnf-automatic (RHEL)",
            raw_data=findings,
        )


def main():
    """Run compliance scan and output JSON."""
    import json

    scanner = ComplianceScanner()
    results = scanner.scan_all()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
