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