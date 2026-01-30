"""
Linux CIS Benchmark Compliance Checks
Based on CIS Distribution Independent Linux Benchmark
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Any
import pwd
import grp

import sys
sys.path.append(str(Path(__file__).parent.parent))
from scanner import ComplianceCheck

class FilePermissionCheck(ComplianceCheck):
    """Check file permissions against expected values"""

    def __init__(self, file_path: str, expected_perms: str,
                 expected_owner: str = None, expected_group: str = None):
        super().__init__(
            check_id=f"FILE_PERM_{Path(file_path).name.upper()}",
            title=f"Verify permissions on {file_path}",
            description=f"Ensure {file_path} has appropriate permissions and ownership",
            severity="HIGH",
            framework="CIS",
            control_id="6.1"
        )
        self.file_path = file_path
        self.expected_perms = expected_perms
        self.expected_owner = expected_owner
        self.expected_group = expected_group

    def run(self):
        """Execute permission check"""
        if not os.path.exists(self.file_path):
            self.status = "PASS"
            self.findings.append(f"File {self.file_path} does not exist (may be expected)")
            return
        
        try:
            stat_info = os.stat(self.file_path)
            actual_perms = oct(stat_info.st_mode)[-3:]

            if actual_perms != self.expected_perms:
                self.status = "FAIL"
                self.findings.append(
                    f"Permissions are {actual_perms}, expected {self.expected_perms}"
                )
                self.remediation = f"Run: chmod {self.expected_perms} {self.file_path}"
            else:
                self.status = "PASS"

            if self.expected_owner:
                actual_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if actual_owner != self.expected_owner:
                    self.status = "FAIL"
                    self.findings.append(
                        f"Owner is {actual_owner}, expected {self.expected_owner}"
                    )
                    self.remediation += f"\nRun: chown {self.expected_owner} {self.file_path}"

            if self.expected_group:
                actual_group = grp.getgrgid(stat_info.st_gid).gr_name
                if actual_group != self.expected_group:
                    self.status = "FAIL"
                    self.findings.append(
                        f"Group is {actual_group}, expected {self.expected_group}"
                    )
                    self.remediation += f"\nRun: chgrp {self.expected_group} {self.file_path}"

        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error checking file: {str(e)}")

class PasswordPolicyCheck(ComplianceCheck):
    """Check password policy settings"""
    
    def __init__(self, policy_type: str):
        super().__init__(
            check_id=f"PWD_POLICY_{policy_type.upper()}",
            title=f"Verify password {policy_type} policy",
            description=f"Ensure strong password {policy_type} requirements are configured",
            severity="HIGH",
            framework="CIS",
            control_id="5.2"
        )
        self.policy_type = policy_type

    def run(self):
        """Check password policy configuration"""
        try:
            if self.policy_type == "complexity":
                self._check_complexity()
            elif self.policy_type == "age":
                self._check_age()
            elif self.policy_type == "history":
                self._check_history()
        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error checking policy: {str(e)}")

    def _check_complexity(self):
        """Check password complexity requirements"""
        pam_file = "/etc/pam.d/common-password"

        if not os.path.exists(pam_file):
            pam_file = "/etc/pam.d/system-auth"

        if not os.path.exists(pam_file):
            self.status = "ERROR"
            self.findings.append("Could not find PAM password configuration file")
            return

        with open(pam_file, 'r') as f:
            content = f.read()

        if 'pam_pwquality' not in content and 'pam_cracklib' not in content:
            self.status = "FAIL"
            self.findings.append("Password complexity module not configured")
            self.remediation = "Install and configure libpam-pwquality"
        else:
            has_minlen = bool(re.search(r'minlen\s*=\s*\d+', content))

            if not has_minlen:
                self.status = "FAIL"
                self.findings.append("Minimum password length not configured")
                self.remediation = "Add minlen=14 to pam_pwquality configuration"
            else:
                self.status = "PASS"

    def _check_age(self):
        """Check password age requiremnets"""
        login_defs = "/etc/login.defs"

        if not os.path.exists(login_defs):
            self.status = "ERROR"
            self.findings.append(f"{login_defs} not found")
            return
        
        with open(login_defs, 'r') as f:
            content = f.read()

        issues = []

        max_days_match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
        if not max_days_match or int(max_days_match.group(1)) > 365:
            issues.append("PASS_MAX_DAYS not set or too high (should be <=365)")

        min_days_match = re.search(r'^PASS_MIN_DAYS\s+(\d+)', content, re.MULTILINE)
        if not min_days_match or int(min_days_match.group(1)) < 1:
            issues.append("PASS_MIN_DAYS not set or too low (should be >=1)")

        warn_age_match = re.search(r'^PASS_WARN_AGE\s+(\d+)', content, re.MULTILINE)
        if not warn_age_match or int(warn_age_match.group(1)) < 7:
            issues.append("PASS_WARN_AGE not set or too low (should be >=7)")

        if issues:
            self.status = "FAIL"
            self.findings = issues
            self.remediation = f"Edit {login_defs} and set appropriate values"
        else:
            self.status = "PASS"

    def _check_history(self):
        """Check password history requirements"""
        pam_file = "/etc/pam.d/common-password"

        if not os.path.exists(pam_file):
            pam_file = "/etc/pam.d/system-auth"

        if not os.path.exists(pam_file):
            self.status = "ERROR"
            self.findings.append("Could not find PAM password configuration file")
            return
        
        with open(pam_file, 'r') as f:
            content = f.read()

        remember_match = re.search(r'remember\s*=\s*(\d+)', content)

        if not remember_match:
            self.status = "FAIL"
            self.findings.append("Password history not configured")
            self.remediation = "Add 'remember=5' to pam_unix.so line in PAM configuration"
        elif int(remember_match.group(1)) < 5:
            self.status = "FAIL"
            self.findings.append(f"Password history set to {remember_match.group(1)}, should be >=5")
            self.remediation = "Increase remember value to at least 5"
        else:
            self.status = "PASS"

class ServiceCheck(ComplianceCheck):
    """Check if unnecessary services are disabled"""

    def __init__(self, service_name: str, should_be_enabled: bool = False):
        status_text = "enabled" if should_be_enabled else "disabled"
        super().__init__(
            check_id=f"SERVICE_{service_name.upper()}",
            title=f"Ensure {service_name} is {status_text}",
            description=f"Verify that {service_name} service is {status_text}",
            severity="MEDIUM",
            framework="CIS",
            control_id="CHANGE ME WHEN YOU FIND OUT ID"
        )
        self.service_name = service_name
        self.should_be_enabled = should_be_enabled

    def run(self):
        """Check service status"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-enabled', self.service_name],
                capture_output=True,
                text=True
            )

            is_enabled = result.returncode == 0

            if is_enabled == self.should_be_enabled:
                self.status = "PASS"
            else:
                self.status = "FAIL"
                expected = "enabled" if self.should_be_enabled else "disabled"
                actual = "enabled" if is_enabled else "disabled"
                self.findings.append(f"Service is {actual}, expected {expected}")

                if self.should_be_enabled:
                    self.remediation = f"systemctl enable {self.service_name}"
                else:
                    self.remediation = f"systemctl disable {self.service_name}"

        except FileNotFoundError:

            try:
                result = subprocess.run(
                    ['service', self.service_name, 'status'],
                    capture_output=True,
                    text=True
                )

                self.status = "PASS"
                self.findings.append("Manual verification recommended")
            except Exception as e:
                self.status = "ERROR"
                self.findings.append(f"Could not check service: {str(e)}")

class FirewallCheck(ComplianceCheck):
    """Check firewall configuration"""

    def __init__(self):
        super().__init__(
            check_id="FIREWALL_ENABLED",
            title="Ensure firewall is active",
            description="Verify that a firewall (iptables, ufw, or firewalld) is enabled",
            severity="CRITICAL",
            framework="CIS",
            control_id="FIX ME"
        )

    def run(self):
        """Check if any fireall is active"""
        firewall_found = False

        try:
            result = subprocess.run(
                ['ufw', 'status'],
                capture_output=True,
                text=True
            )
            if 'Status: active' in result.stdout:
                firewall_found = True
                self.status = "PASS"
                self.findings.append("UFW is active")
                return
        except FileNotFoundError:
            pass

        try:
            result = subprocess.run(
                ['firewall-cmd', '--state'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                firewall_found = True
                self.status = "PASS"
                self.findings.append("firewalld is active")
                return
        except FileNotFoundError:
            pass

        try:
            result = subprocess.run(
                ['iptables', '-L'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                firewall_found = True
                self.status = "PASS"
                self.findings.append("iptables rules are configured")
                return
        except FileNotFoundError:
            pass

        if not firewall_found:
            self.status = "FAIL"
            self.findings.append("No active firewall detected")
            self.remediation = "Install and enable ufw, firewalld, or configure iptables"

class SSHConfigCheck(ComplianceCheck):
    """Check SSH configuration settings"""

    def __init__(self, setting: str, expected_value: str):
        super().__init__(
            check_id=f"SSH_{setting.upper()}",
            title=f"Ensure SSh {setting} is properly configured",
            description=f"Verify SSH {setting} setting",
            severity="HIGH",
            framework="CIS",
            control_id="FIX ME"
        )
        self.setting = setting
        self.expected_value = expected_value

    def run(self):
        """Check SSH configuration"""
        ssh_config = "/etc/ssh/sshd_config"
        
        if not os.path.exists(ssh_config):
            self.status = "ERROR"
            self.findings.append(f"{ssh_config} not found")
            return
        
        try:
            with open(ssh_config, 'r') as f:
                content = f.read()
            
            pattern = rf'^{self.setting}\s+(.+)$'
            match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
            
            if not match:
                self.status = "FAIL"
                self.findings.append(f"{self.setting} not explicitly set")
                self.remediation = f"Add '{self.setting} {self.expected_value}' to {ssh_config}"
            else:
                actual_value = match.group(1).strip()
                if actual_value.lower() == self.expected_value.lower():
                    self.status = "PASS"
                else:
                    self.status = "FAIL"
                    self.findings.append(
                        f"{self.setting} is set to '{actual_value}', expected '{self.expected_value}'"
                    )
                    self.remediation = f"Set '{self.setting} {self.expected_value}' in {ssh_config}"
                    
        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error reading SSH config: {str(e)}")

class AuditdCheck(ComplianceCheck):
    """Check if auditd is installed and enabled"""

    def __init__(self):
        super().__init__(
            check_id="AUDITD_ENABLED",
            title="Ensure auditd service is enabled and running",
            description="Verify system auditing is configured and active",
            severity="HIGH",
            framework="CIS",
            control_id="FIX ME"
        )

    def run(self):
        """Check auditd status"""
        try:
            result = subprocess.run(
                ['which', 'auditd'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.status = "FAIL"
                self.findings.append("auditd is not installed")
                self.remediation = "Install auditd package"
                return
            
            result = subprocess.run(
                ['systemctl', 'is-enabled', 'auditd'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.status = "FAIL"
                self.findings.append("auditd is not enabled")
                self.remediation = "Run: systemctl enable auditd"
                return
            
            result = subprocess.run(
                ['systemctl', 'is-active', 'auditd'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                self.status = "FAIL"
                self.findings.append("auditd is not running")
                self.remediation = "Run: systemctl start auditd"
            else:
                self.status = "PASS"
                
        except Exception as e:
            self.status = "ERROR"
            self.findings.append(f"Error checking auditd: {str(e)}")

def get_cis_checks(categories: list[str] = None) -> list[ComplianceCheck]:
    """
    Get list of CIS compliance checks
    
    Categories:
    - all: All checks
    - filesystem: File system permissions
    - services: Service configuration
    - network: Network and firewall
    - access: Access control and authentication
    - logging: Logging and auditing
    """
    checks = []
    
    if not categories or 'all' in categories or 'filesystem' in categories:
        # File permission checks
        checks.extend([
            FilePermissionCheck("/etc/passwd", "644", "root", "root"),
            FilePermissionCheck("/etc/shadow", "000", "root", "root"),
            FilePermissionCheck("/etc/group", "644", "root", "root"),
            FilePermissionCheck("/etc/gshadow", "000", "root", "root"),
            FilePermissionCheck("/etc/ssh/sshd_config", "600", "root", "root"),
        ])
    
    if not categories or 'all' in categories or 'access' in categories:
        # Password policy checks
        checks.extend([
            PasswordPolicyCheck("complexity"),
            PasswordPolicyCheck("age"),
            PasswordPolicyCheck("history"),
        ])
        
        # SSH configuration checks
        checks.extend([
            SSHConfigCheck("PermitRootLogin", "no"),
            SSHConfigCheck("PasswordAuthentication", "no"),
            SSHConfigCheck("PermitEmptyPasswords", "no"),
            SSHConfigCheck("Protocol", "2"),
        ])
    
    if not categories or 'all' in categories or 'services' in categories:
        # Service checks - these services should generally be disabled
        checks.extend([
            ServiceCheck("avahi-daemon", should_be_enabled=False),
            ServiceCheck("cups", should_be_enabled=False),
            ServiceCheck("isc-dhcp-server", should_be_enabled=False),
            ServiceCheck("isc-dhcp-server6", should_be_enabled=False),
        ])
    
    if not categories or 'all' in categories or 'network' in categories:
        # Network and firewall checks
        checks.append(FirewallCheck())
    
    if not categories or 'all' in categories or 'logging' in categories:
        # Logging and auditing
        checks.append(AuditdCheck())
    
    return checks