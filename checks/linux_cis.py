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

class ServiceCheck(ComplianceCheck):
    """Check if unnecessary services are disabled"""

class FirewallCheck(ComplianceCheck):
    """Check firewall configuration"""

class SSHConfigCheck(ComplianceCheck):
    """Check SSH configuration settings"""

class AuditdCheck(ComplianceCheck):
    """Check if auditd is installed and enabled"""