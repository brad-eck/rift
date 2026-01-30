# Rift - Security Compliance Scanner

A modular, extensible security compliance auditing tool that scans system configurations against industry-standard security frameworks. Built to demonstrate proficiency in both infrastructure security and software development.

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Project Overview

This tool performs automated security compliance auditing of Linux systems against established security benchmarks. It evaluates system configurations, identifies security gaps, and provides actionable remediation guidance through comprehensive reports.

**Current Focus:** CIS (Center for Internet Security) Distribution Independent Linux Benchmark

## Key Features

### Current Implementation (v0.1)

- ✅ **Modular Architecture** - Extensible check system with base classes for easy expansion
- ✅ **CIS Benchmark Support** - 18+ implemented checks covering critical security controls
- ✅ **Multiple Report Formats** - JSON, HTML, and console output
- ✅ **Category-Based Scanning** - Target specific security domains or run comprehensive audits
- ✅ **Compliance Scoring** - Automatic calculation of compliance percentages
- ✅ **Detailed Remediation** - Specific, actionable fix instructions for each failed check
- ✅ **Professional HTML Reports** - Color-coded, printable compliance reports with visual scoring
- ✅ **Severity Classification** - CRITICAL, HIGH, MEDIUM, LOW risk categorization
- ✅ **Error Handling** - Graceful degradation when checks can't be performed

### Security Checks Implemented

#### Filesystem & Permissions (Category: `filesystem`)
- `/etc/passwd` permissions and ownership
- `/etc/shadow` permissions and ownership
- `/etc/group` permissions and ownership
- `/etc/gshadow` permissions and ownership
- `/etc/ssh/sshd_config` permissions and ownership

#### Access Control & Authentication (Category: `access`)
- Password complexity requirements (PAM configuration)
- Password aging policies (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE)
- Password history enforcement
- SSH configuration hardening:
  - Root login prevention
  - Password authentication settings
  - Empty password prevention
  - Protocol version enforcement

#### Service Configuration (Category: `services`)
- Unnecessary service detection and status verification
- Avahi daemon status
- CUPS printing service status
- DHCP server service status

#### Network Security (Category: `network`)
- Firewall detection and status (UFW, firewalld, iptables)

#### Logging & Auditing (Category: `logging`)
- Auditd installation and operational status

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Linux operating system (Ubuntu, Debian, CentOS, RHEL, etc.)
- Root/sudo privileges (required for accessing security-sensitive files)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/brad-eck/rift.git
cd rift
```

2. **Create the project structure** (if not present)
```bash
mkdir -p reports checks tests
touch checks/__init__.py tests/__init__.py
```

3. **Verify installation**
```bash
python3 --version  # Should be 3.9+
python3 scanner.py --help
```

### Quick Start

Run a complete compliance scan:
```bash
sudo python3 scanner.py
```

View the generated HTML report:
```bash
firefox reports/compliance_report_*.html
# or
xdg-open reports/compliance_report_*.html
```

## Usage

### Basic Commands

```bash
# Full CIS benchmark scan with HTML and JSON reports
sudo python3 scanner.py

# Scan specific security categories
sudo python3 scanner.py --category filesystem --category access

# Generate only JSON output
sudo python3 scanner.py --format json

# Verbose logging for debugging
sudo python3 scanner.py --verbose

# Custom output filename
sudo python3 scanner.py --output prod_server_audit
```

### Available Categories

| Category | Description | Check Count |
|----------|-------------|-------------|
| `filesystem` | File and directory permissions | 5 |
| `access` | Authentication and access control | 7 |
| `services` | Service configurations | 4 |
| `network` | Firewall and network settings | 1 |
| `logging` | Audit and logging configuration | 1 |

### Understanding Results

#### Compliance Score
The overall compliance percentage is calculated as:
```
(Passed Checks / Total Applicable Checks) × 100
```

#### Check Statuses
- **PASS** ✅ - Configuration meets security requirements
- **FAIL** ❌ - Security issue detected, remediation needed
- **ERROR** ⚠️ - Check could not be completed (missing files, permissions, etc.)
- **NOT_RUN** - Check was skipped

#### Severity Levels
- **CRITICAL** 🔴 - Immediate security risk, requires urgent remediation
- **HIGH** 🟠 - Significant security concern, should be addressed promptly
- **MEDIUM** 🟡 - Moderate security issue, address during maintenance windows
- **LOW** 🟢 - Minor security enhancement, address as resources permit

## 📊 Sample Output

### Console Summary
```
======================================================================
SECURITY COMPLIANCE REPORT
======================================================================
Target: production-web-01
Framework: CIS
Scan Time: 2024-01-15T14:23:45
Compliance Score: 78.9%

Summary:
  Total Checks: 18
  Passed: 15
  Failed: 3
  Errors: 0

======================================================================

FAILED CHECKS (3):
----------------------------------------------------------------------

[HIGH] SSH_PERMITROOTLOGIN: Ensure SSH PermitRootLogin is properly configured
  Control: CIS 5.2
  Findings: PermitRootLogin is set to 'yes', expected 'no'
```

### HTML Report Features
- Visual compliance score gauge
- Color-coded summary cards (pass/fail/error counts)
- Expandable detailed results per check
- Embedded remediation instructions
- Framework control mapping
- Timestamp and target system identification
- Print-friendly styling

## Architecture

### Project Structure
```
security-compliance-scanner/
├── scanner.py              # Core scanner engine and orchestration
├── checks/
│   ├── __init__.py
│   └── linux_cis.py        # CIS benchmark implementations
├── reports/                # Generated scan reports
├── tests/                  # Unit and integration tests
│   ├── __init__.py
│   └── test_checks.py      # Test check
├── README.md              # This file
```

### Running Tests

```bash
# Run all tests
python3 -m unittest discover tests

# Run specific test file
python3 -m unittest tests.test_checks
```

## Roadmap

### Version 0.2 - Enhanced Reporting
- [ ] PDF report generation
- [ ] Compliance trend tracking (scan-over-scan comparison)
- [ ] Executive summary dashboard
- [ ] Custom branding options for reports

### Version 0.3 - Extended Coverage
- [ ] Additional CIS checks (target: 50+ total checks)
- [ ] Kernel parameter verification
- [ ] Network configuration auditing
- [ ] User account security analysis
- [ ] Filesystem mount option checks
- [ ] SELinux/AppArmor status verification

### Version 0.4 - Multi-Framework Support
- [ ] NIST 800-53 framework implementation
- [ ] STIG (Security Technical Implementation Guide) support
- [ ] PCI-DSS relevant controls
- [ ] HIPAA security rule mappings
- [ ] Custom framework definition via YAML

## 🤝 Contributing

This is currently a portfolio project, but contributions, suggestions, and feedback are welcome!

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Implement your changes with tests
4. Ensure all tests pass
5. Submit a pull request with detailed description

### Contribution Ideas
- New security check implementations
- Additional framework support
- Documentation improvements
- Bug fixes and optimizations
- Test coverage expansion

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CIS (Center for Internet Security)** - For comprehensive security benchmarks
- **NIST** - For cybersecurity framework guidance
- **Linux security community** - For hardening best practices

## 📬 Contact

**Project Maintainer:** [Brady Eckman]
- LinkedIn: [Brady Eckman](https://linkedin.com/in/brady-eckman)

## 🔒 Security Considerations

### Important Notes
- This tool requires root/sudo privileges to access security-sensitive files
- All operations are read-only; no system modifications are made
- Reports may contain sensitive security information - store securely
- Implement appropriate access controls for scan reports
- Review remediation steps before applying to production systems
- Test remediation actions in non-production environments first

---

**Built with ❤️ by an Infrastructure Security Engineer learning software development**

*Last Updated: January 2026*