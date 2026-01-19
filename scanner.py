#!/usr/bin/python3
"""
Security Compliance Scanner
A modular tool for auditing system configuratiosn against security frameworks
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import platform
from checks.linux_cis import get_cis_checks

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ComplianceCheck:
    """Base class for all compliance checks"""

    def __init__(self, check_id: str, title: str, description: str,
                 severity: str, framework: str, control_id: str):
        self.check_id = check_id
        self.title = title
        self.description = description
        self.severity = severity # CRITICAL, HIGH, MEDIUM, LOW
        self.framework = framework
        self.control_id = control_id
        self.status = "NOT RUN" # PASS, FAIL, ERROR
        self.findings = []
        self.remediation = ""

    def run(self) -> Dict[str, Any]:
        """Execute the check - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement run()")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert check results to dictionary"""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "framework": self.framework,
            "control_id": self.control_id,
            "status": self.status,
            "findings": self.findings,
            "remediation": self.remediation
        }

class ScanResult:
    """Container for scan results"""

    def __init__(self, target: str, framework: str):
        self.target = target
        self.framework = framework
        self.scan_time = datetime.now().isoformat()
        self.checks: List[ComplianceCheck] = []
        self.summary = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "not_run": 0
        }

    def add_check(self, check: ComplianceCheck):
        """Add a check result"""
        self.checks.append(check)
        self.summary["total"] += 1

        if check.status == "PASS":
            self.summary["passed"] += 1
        elif check.status == "FAIL":
            self.summary["failed"] += 1
        elif check.status == "ERROR":
            self.summary["errors"] += 1
        else:
            self.summary["not_run"] += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to dictionary"""
        return {
            "target": self.target,
            "framework": self.framework,
            "scan_time": self.scan_time,
            "checks": [check.to_dict() for check in self.checks],
            "summary": self.summary
        }
    
    def get_compliance_score(self) -> float:
        """Calculate compliance percentage"""
        total_applicable = self.summary["passed"] + self.summary["failed"]
        if total_applicable == 0:
            return 0.0
        return (self.summary["passed"] / total_applicable) * 100

class ComplianceScanner:
    """Main scanner orchestrator"""

    def __init__(self, framework: str = "CIS", check_categories: List[str] = None):
        self.framework = framework
        self.check_categories = check_categories or ["all"]
        self.checks = List[ComplianceCheck] = []

    def register_check(self, check: ComplianceCheck):
        """Register a compliance check"""
        self.checks.append(check)

    def load_checks(self):
        """Load checks based on framework and categories"""
        if platform.system() == "Linux":
            self.checks = get_cis_checks(self.check_categories)
        else:
            logger.warning(f"Unsupported platform: {platform.system()}")

    def run_scan(self) -> ScanResult:
        """Execute all registered checks"""
        result = ScanResult(
            target=platform.node(),
            framework=self.framework
        )

        logger.info(f"Starting scan with {len(self.checks)} checks...")

        for check in self.checks:
            try:
                logger.info(f"Running check: {check.check_id} - {check.title}")
                check.run()
                result.add_check(check)
            except Exception as e:
                logger.error(f"Error running check {check.check_id}: {str(e)}")
                check.status = "ERROR"
                check.findings.append(f"Error: {str(e)}")
                result.add_check(check)

        logger.info("Scan completed")
        return result

class ReportGenerator:
    """Generate reports in various formats"""

    @staticmethod
    def generate_json(result: ScanResult, output_path: Path):
        """Generate JSON report"""
        with open(output_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        logger.info(f"JSON report saved to {output_path}")

    @staticmethod
    def generate_html(result: ScanResult, output_path: Path):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .summary-card {{ background: #f9f9f9; padding: 20px; border-radius: 8px; border-left: 4px solid #4CAF50; }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; color: #333; }}
        .compliance-score {{ font-size: 48px; font-weight: bold; color: #4CAF50; text-align: center; margin: 20px 0; }}
        .check {{ background: #fff; border: 1px solid #ddd; margin: 15px 0; padding: 20px; border-radius: 5px; }}
        .check.FAIL {{ border-left: 4px solid #f44336; }}
        .check.PASS {{ border-left: 4px solid #4CAF50; }}
        .check.ERROR {{ border-left: 4px solid #ff9800; }}
        .severity {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .severity.CRITICAL {{ background: #f44336; color: white; }}
        .severity.HIGH {{ background: #ff9800; color: white; }}
        .severity.MEDIUM {{ background: #ffc107; color: black; }}
        .severity.LOW {{ background: #8bc34a; color: white; }}
        .status {{ display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-left: 10px; }}
        .status.PASS {{ background: #4CAF50; color: white; }}
        .status.FAIL {{ background: #f44336; color: white; }}
        .status.ERROR {{ background: #ff9800; color: white; }}
        .findings {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .remediation {{ background: #e3f2fd; padding: 10px; margin: 10px 0; border-radius: 3px; border-left: 3px solid #2196F3; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Compliance Report</h1>
        <p><strong>Target:</strong> {result.target}</p>
        <p><strong>Framework:</strong> {result.framework}</p>
        <p><strong>Scan Time:</strong> {result.scan_time}</p>
        
        <div class="compliance-score">
            {result.get_compliance_score():.1f}% Compliant
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Checks</h3>
                <div class="value">{result.summary['total']}</div>
            </div>
            <div class="summary-card" style="border-left-color: #4CAF50;">
                <h3>Passed</h3>
                <div class="value" style="color: #4CAF50;">{result.summary['passed']}</div>
            </div>
            <div class="summary-card" style="border-left-color: #f44336;">
                <h3>Failed</h3>
                <div class="value" style="color: #f44336;">{result.summary['failed']}</div>
            </div>
            <div class="summary-card" style="border-left-color: #ff9800;">
                <h3>Errors</h3>
                <div class="value" style="color: #ff9800;">{result.summary['errors']}</div>
            </div>
        </div>
        
        <h2>Detailed Results</h2>
"""
        
        for check in result.checks:
            findings_html = ""
            if check.findings:
                findings_html = f"""
                <div class="findings">
                    <strong>Findings:</strong><br>
                    {'<br>'.join(check.findings)}
                </div>
                """
            
            remediation_html = ""
            if check.remediation:
                remediation_html = f"""
                <div class="remediation">
                    <strong>Remediation:</strong><br>
                    {check.remediation}
                </div>
                """
            
            html_content += f"""
        <div class="check {check.status}">
            <h3>
                {check.check_id}: {check.title}
                <span class="severity {check.severity}">{check.severity}</span>
                <span class="status {check.status}">{check.status}</span>
            </h3>
            <p><strong>Control:</strong> {check.framework} {check.control_id}</p>
            <p>{check.description}</p>
            {findings_html}
            {remediation_html}
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {output_path}")

    @staticmethod
    def generate_console(result: ScanResult):
        """Generate console output"""
        print("\n" + "="*70)
        print("SECURITY COMPLIANCE REPORT")
        print("="*70)
        print(f"Target: {result.target}")
        print(f"Framework: {result.framework}")
        print(f"Scan Time: {result.scan_time}")
        print(f"Compliance Score: {result.get_compliance_score():.1f}%")
        print("\nSummary:")
        print(f"  Total Checks: {result.summary['total']}")
        print(f"  Passed: {result.summary['passed']}")
        print(f"  Failed: {result.summary['failed']}")
        print(f"  Errors: {result.summary['errors']}")
        print("\n" + "="*70)

        # Display failed checks
        failed_checks = [c for c in result.checks if c.status == "FAIL"]
        if failed_checks:
            print(f"\nFAILED CHECKS ({len(failed_checks)}):")
            print("-"*70)
            for check in failed_checks:
                print(f"\n[{check.severity}] {check.check_id}: {check.title}")
                print(f"  Control: {check.framework} {check.control_id}")
                if check.findings:
                    print(f"  Findings: {check.findings[0]}")

def main():
    parser = argparse.ArgumentParser(
        description="Security Compliance Scanner - Audit system configurations"
    )
    parser.add_argument(
        '--framework',
        choices=['CIS', 'NIST', 'STIG'],
        default='CIS',
        help='Security framework to scan against'
    )
    parser.add_argument(
        '--category',
        action='append',
        help='Specific check categories to run (can be specified multiple times)'
    )
    parser.add_argument(
        '--output',
        default='compliance_report',
        help='Output file prefix (without extension)'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'html', 'both'],
        default='both',
        help='Report format'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize scanner
    scanner = ComplianceScanner(
        framework=args.framework,
        check_categories=args.category
    )

    try:
        scanner.load_checks()
    except Exception as e:
        logger.error(f"Failed to load checks: {str(e)}")
        sys.exit(1)

    if not scanner.checks:
        logger.error("No checks loaded. Exiting.")
        sys.exit(1)

    result = scanner.run_scan()

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.format in ['json', 'both']:
        json_path = output_dir / f"{args.output}_{timestamp}.json"
        ReportGenerator.generate_json(result, json_path)

    if args.format in ['html', 'both']:
        html_path = output_dir / f"{args.output}_{timestamp}.html"
        ReportGenerator.generate_html(result, html_path)

    ReportGenerator.generate_console(result)

    if result.summary['failed'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()