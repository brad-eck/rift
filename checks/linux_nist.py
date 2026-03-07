"""
Linux NIST 800-53 Compliance Checks
Based on NIST Special Publication 800-53 Rev. 5 Security Controls
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import sys
sys.path.append(str(Path(__file__).parent.parent))
from scanner import ComplianceCheck
from checks.linux_cis import (
    FilePermissionCheck,
    PasswordPolicyCheck,
    SSHConfigCheck,
    ServiceCheck,
    FirewallCheck,
    AuditdCheck,
)


def _remap(check: ComplianceCheck, control_id: str) -> ComplianceCheck:
    """Re-map a CIS check to a NIST control."""
    check.framework = "NIST"
    check.control_id = control_id
    return check


class RootAccountCheck(ComplianceCheck):
    """AC-2: Verify no unauthorized UID 0 accounts exist"""

    def __init__(self):
        super().__init__(
            check_id="NIST_ROOT_ACCOUNTS",
            title="Ensure root is the only UID 0 account",
            description="Verify that no unauthorized accounts have UID 0 (root-level) access",
            severity="CRITICAL",
            framework="NIST",
            control_id="AC-2",
        )

    def run(self):
        passwd_file = "/etc/passwd"
        if not os.path.exists(passwd_file):
            self.status = "ERROR"
            self.findings.append(f"{passwd_file} not found")
            return

        try:
            with open(passwd_file, "r") as f:
                uid0_accounts = []
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                        uid0_accounts.append(parts[0])

            if uid0_accounts:
                self.status = "FAIL"
                self.findings.append(
                    f"Non-root accounts with UID 0: {', '.join(uid0_accounts)}"
                )
                self.remediation = (
                    "Remove or reassign UID for unauthorized UID 0 accounts: "
                    + ", ".join(uid0_accounts)
                )
            else:
                self.status = "PASS"
        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error reading passwd file: {str(e)}")


class EmptyPasswordAccountCheck(ComplianceCheck):
    """AC-2: Verify no accounts have empty password fields"""

    def __init__(self):
        super().__init__(
            check_id="NIST_EMPTY_PASSWORDS",
            title="Ensure no accounts have empty passwords",
            description="Verify that all accounts in /etc/shadow have a password set or are locked",
            severity="CRITICAL",
            framework="NIST",
            control_id="AC-2",
        )

    def run(self):
        shadow_file = "/etc/shadow"
        if not os.path.exists(shadow_file):
            self.status = "ERROR"
            self.findings.append(f"{shadow_file} not found")
            return

        try:
            with open(shadow_file, "r") as f:
                empty_pw_accounts = []
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] == "":
                        empty_pw_accounts.append(parts[0])

            if empty_pw_accounts:
                self.status = "FAIL"
                self.findings.append(
                    f"Accounts with empty passwords: {', '.join(empty_pw_accounts)}"
                )
                self.remediation = (
                    "Lock or set passwords for: "
                    + ", ".join(empty_pw_accounts)
                    + "\nRun: passwd -l <account> to lock or passwd <account> to set a password"
                )
            else:
                self.status = "PASS"
        except PermissionError:
            self.status = "ERROR"
            self.findings.append("Permission denied reading /etc/shadow (run as root)")
        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error reading shadow file: {str(e)}")


class LoginLockoutCheck(ComplianceCheck):
    """AC-7: Verify unsuccessful login attempt lockout is configured"""

    def __init__(self):
        super().__init__(
            check_id="NIST_LOGIN_LOCKOUT",
            title="Ensure account lockout is configured for failed login attempts",
            description="Verify PAM is configured to lock accounts after repeated failed login attempts",
            severity="HIGH",
            framework="NIST",
            control_id="AC-7",
        )

    def run(self):
        pam_files = [
            "/etc/pam.d/common-auth",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
        ]

        content = ""
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                try:
                    with open(pam_file, "r") as f:
                        content += f.read()
                except Exception:
                    pass

        if not content:
            self.status = "ERROR"
            self.findings.append("Could not find PAM authentication configuration files")
            return

        has_faillock = "pam_faillock" in content
        has_tally = "pam_tally2" in content or "pam_tally" in content
        has_faildelay = "pam_faildelay" in content

        if has_faillock or has_tally:
            self.status = "PASS"
            if has_faillock:
                self.findings.append("pam_faillock is configured")
            if has_tally:
                self.findings.append("pam_tally is configured")
        else:
            self.status = "FAIL"
            self.findings.append("No account lockout mechanism configured")
            self.remediation = (
                "Configure pam_faillock in PAM:\n"
                "Add to /etc/pam.d/common-auth or /etc/pam.d/system-auth:\n"
                "auth required pam_faillock.so preauth silent deny=5 unlock_time=900\n"
                "auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900"
            )


class LoginBannerCheck(ComplianceCheck):
    """AC-8: Verify system use notification banner is configured"""

    def __init__(self):
        super().__init__(
            check_id="NIST_LOGIN_BANNER",
            title="Ensure login warning banner is configured",
            description="Verify that a warning banner is displayed prior to system access",
            severity="MEDIUM",
            framework="NIST",
            control_id="AC-8",
        )

    def run(self):
        banner_files = ["/etc/issue", "/etc/issue.net"]
        issues = []

        for banner_file in banner_files:
            if not os.path.exists(banner_file):
                issues.append(f"{banner_file} does not exist")
                continue

            try:
                with open(banner_file, "r") as f:
                    content = f.read().strip()

                if not content:
                    issues.append(f"{banner_file} is empty")
                elif len(content) < 20:
                    issues.append(f"{banner_file} contains minimal content ({len(content)} chars)")
            except Exception as e:
                issues.append(f"Error reading {banner_file}: {str(e)}")

        if issues:
            self.status = "FAIL"
            self.findings = issues
            self.remediation = (
                "Configure login banners with an authorized use warning:\n"
                "Edit /etc/issue and /etc/issue.net with an appropriate warning message.\n"
                "Example: 'Authorized uses only. All activity may be monitored and reported.'"
            )
        else:
            self.status = "PASS"


class SysctlCheck(ComplianceCheck):
    """Check kernel parameters via sysctl"""

    def __init__(self, parameter: str, expected_value: str, control_id: str,
                 severity: str = "MEDIUM"):
        param_id = parameter.replace(".", "_").upper()
        super().__init__(
            check_id=f"NIST_SYSCTL_{param_id}",
            title=f"Ensure {parameter} is set to {expected_value}",
            description=f"Verify kernel parameter {parameter} is properly configured",
            severity=severity,
            framework="NIST",
            control_id=control_id,
        )
        self.parameter = parameter
        self.expected_value = expected_value

    def run(self):
        proc_path = Path("/proc/sys") / self.parameter.replace(".", "/")

        try:
            if proc_path.exists():
                actual_value = proc_path.read_text().strip()
            else:
                result = subprocess.run(
                    ["sysctl", "-n", self.parameter],
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    self.status = "ERROR"
                    self.findings.append(f"Could not read {self.parameter}")
                    return
                actual_value = result.stdout.strip()

            if actual_value == self.expected_value:
                self.status = "PASS"
            else:
                self.status = "FAIL"
                self.findings.append(
                    f"{self.parameter} is '{actual_value}', expected '{self.expected_value}'"
                )
                self.remediation = (
                    f"Run: sysctl -w {self.parameter}={self.expected_value}\n"
                    f"Persist by adding '{self.parameter} = {self.expected_value}' to /etc/sysctl.conf"
                )
        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error checking {self.parameter}: {str(e)}")


class TimeSyncCheck(ComplianceCheck):
    """AU-8: Verify time synchronization is configured"""

    def __init__(self):
        super().__init__(
            check_id="NIST_TIME_SYNC",
            title="Ensure time synchronization is configured",
            description="Verify that NTP or chrony is installed and active for accurate timestamps",
            severity="MEDIUM",
            framework="NIST",
            control_id="AU-8",
        )

    def run(self):
        services = [
            ("chronyd", "chrony"),
            ("systemd-timesyncd", "systemd-timesyncd"),
            ("ntpd", "ntp"),
        ]

        for service_name, _ in services:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    self.status = "PASS"
                    self.findings.append(f"{service_name} is active")
                    return
            except FileNotFoundError:
                break

        self.status = "FAIL"
        self.findings.append("No time synchronization service is active")
        self.remediation = (
            "Install and enable a time synchronization service:\n"
            "Run: apt install chrony && systemctl enable --now chronyd\n"
            "Or: apt install ntp && systemctl enable --now ntpd"
        )


class WorldWritableCheck(ComplianceCheck):
    """AC-6: Check for world-writable files in sensitive directories"""

    def __init__(self):
        super().__init__(
            check_id="NIST_WORLD_WRITABLE_ETC",
            title="Ensure no world-writable files exist in /etc",
            description="Verify that no configuration files in /etc are world-writable",
            severity="HIGH",
            framework="NIST",
            control_id="AC-6",
        )

    def run(self):
        etc_path = Path("/etc")
        if not etc_path.exists():
            self.status = "ERROR"
            self.findings.append("/etc directory not found")
            return

        try:
            world_writable = []
            for root, dirs, files in os.walk("/etc"):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        if os.path.islink(fpath):
                            continue
                        mode = os.stat(fpath).st_mode
                        if mode & 0o002:
                            world_writable.append(fpath)
                    except (OSError, PermissionError):
                        continue

            if world_writable:
                self.status = "FAIL"
                if len(world_writable) <= 10:
                    self.findings.append(
                        f"World-writable files found: {', '.join(world_writable)}"
                    )
                else:
                    self.findings.append(
                        f"{len(world_writable)} world-writable files found in /etc "
                        f"(first 10: {', '.join(world_writable[:10])})"
                    )
                self.remediation = (
                    "Remove world-writable permissions from files in /etc:\n"
                    "Run: chmod o-w <file> for each affected file"
                )
            else:
                self.status = "PASS"
        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error scanning /etc: {str(e)}")


def get_nist_checks(categories: list[str] = None) -> list[ComplianceCheck]:
    """
    Get list of NIST 800-53 compliance checks

    Categories:
    - all: All checks
    - filesystem: File system permissions (AC-3, AC-6)
    - services: Service configuration (CM-7)
    - network: Network and firewall (SC-5, SC-7, CM-6)
    - access: Access control and authentication (AC-2, AC-7, AC-8, AC-17, IA-5)
    - logging: Logging and auditing (AU-8, AU-12)
    """
    checks = []

    if not categories or "all" in categories or "filesystem" in categories:
        checks.extend([
            _remap(FilePermissionCheck("/etc/passwd", "644", "root", "root"), "AC-3"),
            _remap(FilePermissionCheck("/etc/shadow", "000", "root", "root"), "AC-3"),
            _remap(FilePermissionCheck("/etc/group", "644", "root", "root"), "AC-3"),
            WorldWritableCheck(),
        ])

    if not categories or "all" in categories or "access" in categories:
        checks.extend([
            RootAccountCheck(),
            EmptyPasswordAccountCheck(),
            LoginLockoutCheck(),
            LoginBannerCheck(),
            _remap(PasswordPolicyCheck("complexity"), "IA-5"),
            _remap(PasswordPolicyCheck("age"), "IA-5"),
            _remap(SSHConfigCheck("PermitRootLogin", "no"), "AC-17"),
            _remap(SSHConfigCheck("PermitEmptyPasswords", "no"), "AC-17"),
        ])

    if not categories or "all" in categories or "services" in categories:
        checks.extend([
            _remap(ServiceCheck("avahi-daemon", should_be_enabled=False), "CM-7"),
            _remap(ServiceCheck("cups", should_be_enabled=False), "CM-7"),
        ])

    if not categories or "all" in categories or "network" in categories:
        checks.extend([
            _remap(FirewallCheck(), "SC-7"),
            SysctlCheck("net.ipv4.tcp_syncookies", "1", "SC-5"),
            SysctlCheck("net.ipv4.conf.all.accept_redirects", "0", "SC-5"),
            SysctlCheck("net.ipv4.ip_forward", "0", "CM-6"),
        ])

    if not categories or "all" in categories or "logging" in categories:
        checks.extend([
            _remap(AuditdCheck(), "AU-12"),
            TimeSyncCheck(),
        ])

    return checks
