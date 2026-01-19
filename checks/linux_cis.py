"""
Linux CIS Benchmark Compliance Checks
Based on CIS Distribution Independent Linux Benchmark
"""

import os
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any
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
                self.check_age()
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

class FirewallCheck(ComplianceCheck):
    """Check firewall configuration"""

class SSHConfigCheck(ComplianceCheck):
    """Check SSH configuration settings"""

class AuditdCheck(ComplianceCheck):
    """Check if auditd is installed and enabled"""