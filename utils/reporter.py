# utils/reporter.py
import json
import os
import time
from datetime import datetime
from colorama import Fore, Style, init
from typing import Dict, List, Union

init(autoreset=True)


class VulnerabilityReporter:
    SEVERITY_COLORS = {
        "critical": Fore.RED,
        "high": Fore.LIGHTRED_EX,
        "medium": Fore.YELLOW,
        "low": Fore.CYAN
    }

    def __init__(self, scan_results: Dict):
        self.results = scan_results
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_report(self, format: str = "console") -> str:
        """Main report generation dispatcher"""
        try:
            if format.lower() == "html":
                return self._generate_html()
            elif format.lower() == "json":
                return self._generate_json()
            return self._generate_console()
        except Exception as e:
            return f"Report generation failed: {str(e)}"

    def _generate_console(self) -> str:
        """Color-coded console output with parameter validation"""
        report = []

        # XSS Findings
        for vuln in self.results.get('results', {}).get('xss', []):
            safe_vuln = self._safe_get_vuln(vuln, 'XSS')
            report.append(
                f"{self.SEVERITY_COLORS['high']}[XSS] Parameter: {safe_vuln['parameter']}\n"
                f"  Location: {safe_vuln['endpoint']}\n"
                f"  Payload: {Fore.CYAN}{safe_vuln['payload']}{Style.RESET_ALL}\n"
                f"  Context: {safe_vuln['context']}"
            )

        # SQLi Findings
        sqli = self.results.get('results', {}).get('sqli', {})
        if sqli.get('vulnerable', False):
            for vuln in sqli.get('vulnerabilities', []):
                safe_vuln = self._safe_get_vuln(vuln, 'SQLi')
                report.append(
                    f"{self.SEVERITY_COLORS['critical']}[SQLi] Parameter: {safe_vuln['parameter']}\n"
                    f"  Location: {safe_vuln['endpoint']}\n"
                    f"  Payload: {Fore.LIGHTRED_EX}{safe_vuln['payload']}{Style.RESET_ALL}\n"
                    f"  Evidence: {safe_vuln['evidence'][:100]}..."
                )

        # CSRF Findings
        csrf = self.results.get('results', {}).get('csrf', {})
        if csrf.get('vulnerable', False):
            for form in csrf.get('forms', []):
                safe_form = self._safe_get_vuln(form, 'CSRF')
                report.append(
                    f"{self.SEVERITY_COLORS['medium']}[CSRF] Parameter: {safe_form['parameter']}\n"
                    f"  Endpoint: {safe_form['endpoint']}\n"
                    f"  Form Action: {safe_form['form_action']}"
                )

        return "\n\n".join(report) if report else f"{Fore.GREEN}No vulnerabilities found"

    def _safe_get_vuln(self, vuln: Dict, vuln_type: str) -> Dict:
        """Ensure consistent vulnerability data structure"""
        defaults = {
            "parameter": "unknown-parameter",
            "payload": "none",
            "endpoint": "unknown-endpoint",
            "context": "",
            "evidence": "",
            "form_action": "#"
        }
        return {**defaults, **vuln, "type": vuln_type}

    def _generate_html(self) -> str:
        """Interactive HTML report with vulnerability details"""
        filename = f"report_{self._sanitize_filename(self.results.get('target', 'unknown'))}_{int(time.time())}.html"
        path = os.path.join(self.report_dir, filename)

        with open(path, 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        .vulnerability {{ margin-bottom: 20px; padding: 10px; border-left: 4px solid; }}
        .xss {{ border-color: #ff9800; }}
        .sqli {{ border-color: #f44336; }}
        .csrf {{ border-color: #4caf50; }}
        pre {{ white-space: pre-wrap; background: #f5f5f5; padding: 10px; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Target: {self.results.get('target', 'Unknown')}</p>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    {self._html_vulnerability_section('xss', 'XSS Vulnerabilities', 'orange')}
    {self._html_vulnerability_section('sqli', 'SQL Injection Findings', 'red')}
    {self._html_vulnerability_section('csrf', 'CSRF Vulnerabilities', 'green')}

    <h2>Summary</h2>
    <p>Total vulnerabilities found: {self._count_vulns()}</p>
</body>
</html>""")
        return f"HTML report generated: {path}"

    def _html_vulnerability_section(self, vuln_type: str, title: str, color: str) -> str:
        """Generate HTML section for specific vulnerability type"""
        vulns = self.results.get('results', {}).get(vuln_type, [])
        if not vulns: return ""

        section = [f'<div class="vulnerability {vuln_type}"><h3 style="color: {color};">{title}</h3>']

        for vuln in vulns if isinstance(vulns, list) else vulns.get('vulnerabilities', []):
            safe_vuln = self._safe_get_vuln(vuln, vuln_type.upper())
            section.append(f"""
                <div class="vuln-details">
                    <h4>Parameter: {safe_vuln['parameter']}</h4>
                    <p><strong>Location:</strong> {safe_vuln.get('endpoint', 'Unknown')}</p>
                    {self._html_if_present('Payload', safe_vuln.get('payload'))}
                    {self._html_if_present('Context', safe_vuln.get('context'))}
                    {self._html_if_present('Evidence', safe_vuln.get('evidence'), True)}
                </div>
            """)

        section.append("</div>")
        return "\n".join(section)

    def _html_if_present(self, label: str, value: str, is_code: bool = False) -> str:
        """Helper for conditional HTML content"""
        if not value: return ""
        content = f"<pre>{value}</pre>" if is_code else value
        return f"<p><strong>{label}:</strong> {content}</p>"

    def _generate_json(self) -> str:
        """Structured JSON report with validation"""
        filename = f"report_{self._sanitize_filename(self.results.get('target', 'unknown'))}_{int(time.time())}.json"
        path = os.path.join(self.report_dir, filename)

        report_data = {
            "metadata": {
                "target": self.results.get('target'),
                "timestamp": datetime.now().isoformat(),
                "duration": self.results.get('duration', 0)
            },
            "results": {
                "xss": [self._safe_get_vuln(v, 'XSS') for v in self.results.get('results', {}).get('xss', [])],
                "sqli": {
                    "vulnerable": self.results.get('results', {}).get('sqli', {}).get('vulnerable', False),
                    "findings": [self._safe_get_vuln(v, 'SQLi') for v in
                                 self.results.get('results', {}).get('sqli', {}).get('vulnerabilities', [])]
                },
                "csrf": {
                    "vulnerable": self.results.get('results', {}).get('csrf', {}).get('vulnerable', False),
                    "forms": [self._safe_get_vuln(f, 'CSRF') for f in
                              self.results.get('results', {}).get('csrf', {}).get('forms', [])]
                }
            },
            "summary": {
                "total_vulnerabilities": self._count_vulns(),
                "xss_count": len(self.results.get('results', {}).get('xss', [])),
                "sqli_count": len(self.results.get('results', {}).get('sqli', {}).get('vulnerabilities', [])),
                "csrf_count": len(self.results.get('results', {}).get('csrf', {}).get('forms', []))
            }
        }

        with open(path, 'w') as f:
            json.dump(report_data, f, indent=2)
        return f"JSON report generated: {path}"

    def _count_vulns(self) -> int:
        """Count all vulnerability instances"""
        return (
                len(self.results.get('results', {}).get('xss', [])) +
                len(self.results.get('results', {}).get('sqli', {}).get('vulnerabilities', [])) +
                len(self.results.get('results', {}).get('csrf', {}).get('forms', []))
        )

    def _sanitize_filename(self, name: str) -> str:
        """Sanitize filename"""
        return "".join(c if c.isalnum() else "_" for c in name)