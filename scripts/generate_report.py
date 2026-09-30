#!/usr/bin/env python3
"""
DevSecOps Pipeline - Report Generator
Generates consolidated human-readable and machine-readable security reports.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import Counter


def load_gate_result(result_path: str) -> Dict[str, Any]:
    """Load security gate result."""
    if not os.path.exists(result_path):
        return {}
    
    with open(result_path, 'r') as f:
        return json.load(f)


def load_normalized_findings(findings_path: str) -> Dict[str, Any]:
    """Load normalized findings."""
    if not os.path.exists(findings_path):
        return {"findings": []}
    
    with open(findings_path, 'r') as f:
        return json.load(f)


def normalize_cwe_ids(cwe_ids: List[Any]) -> List[str]:
    """Normalize CWE IDs to strings, handling various formats.
    
    Handles:
    - Integers: 79
    - Strings: "79", "CWE-79", "CWE79"
    - None/empty: returns empty list
    """
    if not cwe_ids:
        return []
    normalized = []
    for cwe in cwe_ids:
        if cwe is None:
            continue
        cwe_str = str(cwe).strip()
        # Normalize format: ensure "CWE-" prefix
        if cwe_str.isdigit():
            cwe_str = f"CWE-{cwe_str}"
        elif cwe_str.upper().startswith("CWE") and not cwe_str.upper().startswith("CWE-"):
            # Handle "CWE79" -> "CWE-79"
            num_part = cwe_str[3:]
            if num_part.isdigit():
                cwe_str = f"CWE-{num_part}"
        normalized.append(cwe_str)
    return normalized


def generate_markdown_report(gate_result: Dict, normalized_data: Dict, metadata: Dict) -> str:
    """Generate Markdown security report."""
    lines = []
    
    # Header
    lines.append("# DevSecOps Security Pipeline Report")
    lines.append("")
    lines.append(f"**Generated:** {metadata.get('generated_at', datetime.utcnow().isoformat())}Z")
    lines.append(f"**Pipeline Run:** {metadata.get('run_id', 'N/A')}")
    lines.append(f"**Commit:** {metadata.get('commit_sha', 'N/A')}")
    lines.append(f"**Branch:** {metadata.get('branch', 'N/A')}")
    lines.append("")
    
    # Overall Result
    passed = gate_result.get("passed", False)
    status_text = "PASSED" if passed else "FAILED"
    lines.append(f"## Overall Security Gate: {status_text}")
    lines.append("")
    
    # Summary
    summary = gate_result.get("summary", {})
    lines.append("## Findings Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    
    severity_order = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
    for sev in severity_order:
        count = summary.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev} | {count} |")
    
    lines.append(f"| **Total** | **{summary.get('Total', 0)}** |")
    lines.append("")
    
    # By Scanner
    by_scanner = summary.get("by_scanner", {})
    if by_scanner:
        lines.append("## Findings by Scanner")
        lines.append("")
        lines.append("| Scanner | Count |")
        lines.append("|---------|-------|")
        for scanner, count in sorted(by_scanner.items(), key=lambda x: -x[1]):
            lines.append(f"| {scanner} | {count} |")
        lines.append("")
    
    # Policy Violations
    violations = gate_result.get("policy_violations", [])
    if violations:
        lines.append("## Policy Violations (Security Gate Failures)")
        lines.append("")
        lines.append("These findings violate the configured security policy and caused the gate to fail.")
        lines.append("")
        lines.append("| Severity | Scanner | Rule ID | Message | Location |")
        lines.append("|----------|---------|---------|---------|----------|")
        
        for v in violations:
            severity = v.get("severity", "Unknown")
            scanner = v.get("scanner", "Unknown")
            rule_id = v.get("rule_id", "Unknown")
            message = v.get("message", "No message")[:100]
            file_path = v.get("file_path", "N/A")
            line = v.get("line_number", "")
            location = f"{file_path}:{line}" if line else file_path
            
            lines.append(f"| {severity} | {scanner} | {rule_id} | {message} | {location} |")
        
        lines.append("")
    
    # Top Findings by Severity
    findings = normalized_data.get("findings", [])
    if findings:
        lines.append("## Detailed Findings")
        lines.append("")
        
        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "Unknown")
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)
        
        for sev in severity_order:
            sev_findings = by_severity.get(sev, [])
            if not sev_findings:
                continue
            
            lines.append(f"### {sev} ({len(sev_findings)})")
            lines.append("")
            
            for f in sev_findings[:20]:  # Limit to 20 per severity
                scanner = f.get("scanner", "Unknown")
                rule_id = f.get("rule_id", "Unknown")
                message = f.get("message", "No message")
                file_path = f.get("file_path", "N/A")
                line = f.get("line_number", "")
                cve_ids = f.get("cve_ids", [])
                cwe_ids = normalize_cwe_ids(f.get("cwe_ids", []))
                fix_versions = f.get("fix_versions", [])
                references = f.get("references", [])
                
                lines.append(f"#### {scanner}: {rule_id}")
                lines.append(f"**Message:** {message}")
                lines.append(f"**Location:** {file_path}:{line}" if line else f"**Location:** {file_path}")
                
                if cve_ids:
                    lines.append(f"**CVEs:** {', '.join(cve_ids)}")
                if cwe_ids:
                    lines.append(f"**CWEs:** {', '.join(cwe_ids)}")
                if fix_versions:
                    lines.append(f"**Fixed Versions:** {', '.join(fix_versions)}")
                if references:
                    lines.append(f"**References:** {', '.join(references[:3])}")
                
                lines.append("")
            
            if len(sev_findings) > 20:
                lines.append(f"*... and {len(sev_findings) - 20} more {sev.lower()} findings*")
                lines.append("")
    
    # Remediation Guidance
    lines.append("## Remediation Guidance")
    lines.append("")
    
    # Group by scanner for remediation advice
    scanner_findings = {}
    for f in findings:
        scanner = f.get("scanner", "Unknown")
        if scanner not in scanner_findings:
            scanner_findings[scanner] = []
        scanner_findings[scanner].append(f)
    
    for scanner, scanner_f in scanner_findings.items():
        lines.append(f"### {scanner.upper()} Remediation")
        lines.append("")
        
        if scanner == "gitleaks":
            lines.append("- Remove hardcoded secrets from source code")
            lines.append("- Use environment variables or secret management systems")
            lines.append("- Rotate any exposed credentials immediately")
            lines.append("- Add secret scanning to pre-commit hooks")
        elif scanner in ("semgrep", "bandit"):
            lines.append("- Review and fix insecure code patterns identified")
            lines.append("- Use safe APIs (e.g., `subprocess.run` without `shell=True`)")
            lines.append("- Implement input validation and sanitization")
            lines.append("- Use parameterized queries for database operations")
        elif scanner in ("osv-scanner", "pip-audit"):
            lines.append("- Update vulnerable dependencies to fixed versions")
            lines.append("- Check for breaking changes before upgrading")
            lines.append("- Pin dependencies to specific secure versions")
            lines.append("- Enable Dependabot or similar automated updates")
        elif scanner == "trivy":
            lines.append("- Update base image to latest secure version")
            lines.append("- Remove unnecessary packages from container")
            lines.append("- Use distroless or minimal base images")
            lines.append("- Scan images regularly in CI/CD")
        elif scanner == "zap":
            lines.append("- Implement missing security headers (CSP, HSTS, X-Frame-Options, etc.)")
            lines.append("- Add input validation and output encoding")
            lines.append("- Implement CSRF protection for state-changing operations")
            lines.append("- Secure cookies with HttpOnly, Secure, SameSite flags")
        
        lines.append("")
    
    # Execution Metadata
    exec_meta = gate_result.get("execution_metadata", {})
    if exec_meta:
        lines.append("## Execution Metadata")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        for key, value in exec_meta.items():
            if isinstance(value, dict):
                value = json.dumps(value)
            lines.append(f"| {key} | {value} |")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("*Report generated by DevSecOps Security Pipeline*")
    
    return "\n".join(lines)


def generate_html_report(gate_result: Dict, normalized_data: Dict, metadata: Dict) -> str:
    """Generate HTML security report."""
    markdown = generate_markdown_report(gate_result, normalized_data, metadata)
    
    # Simple markdown to HTML conversion for basic elements
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Security Pipeline Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; color: #333; }}
        h1 {{ color: #1a1a1a; border-bottom: 2px solid #e1e4e8; padding-bottom: 10px; }}
        h2 {{ color: #24292e; margin-top: 30px; border-bottom: 1px solid #e1e4e8; padding-bottom: 5px; }}
        h3 {{ color: #24292e; margin-top: 24px; }}
        h4 {{ color: #24292e; }}
        table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
        th, td {{ border: 1px solid #e1e4e8; padding: 8px 12px; text-align: left; }}
        th {{ background-color: #f6f8fa; font-weight: 600; }}
        tr:nth-child(2n) {{ background-color: #f6f8fa; }}
        .passed {{ color: #28a745; font-weight: bold; }}
        .failed {{ color: #cb2431; font-weight: bold; }}
        .critical {{ color: #cb2431; font-weight: bold; }}
        .high {{ color: #cb2431; }}
        .medium {{ color: #f97583; }}
        .low {{ color: #6a737d; }}
        code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 3px; font-family: 'SF Mono', Monaco, monospace; }}
        pre {{ background: #f6f8fa; padding: 16px; border-radius: 6px; overflow: auto; }}
        .metadata {{ font-size: 0.9em; color: #586069; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e1e4e8; color: #586069; font-size: 0.9em; }}
    </style>
</head>
<body>
"""
    
    # Convert markdown to HTML (simplified)
    html += markdown_to_html(markdown)
    
    html += """
</body>
</html>"""
    
    return html


def markdown_to_html(md: str) -> str:
    """Simple markdown to HTML conversion for our report format."""
    lines = md.split('\n')
    html_lines = []
    in_table = False
    table_rows = []
    
    for line in lines:
        # Headers
        if line.startswith('### '):
            html_lines.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith('## '):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith('# '):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        # Bold
        elif line.startswith('**') and line.endswith('**'):
            html_lines.append(f"<p><strong>{line[2:-2]}</strong></p>")
        # Horizontal rule
        elif line == '---':
            html_lines.append("<hr>")
        # Table handling
        elif line.startswith('|') and line.endswith('|'):
            if not in_table:
                in_table = True
                table_rows = []
            table_rows.append(line)
        else:
            if in_table:
                html_lines.append(table_to_html(table_rows))
                table_rows = []
                in_table = False
            
            # Regular paragraph
            if line.strip():
                # Handle bold/italic
                line = line.replace('**', '<strong>').replace('**', '</strong>', 1)
                line = line.replace('*', '<em>').replace('*', '</em>', 1)
                html_lines.append(f"<p>{line}</p>")
            else:
                html_lines.append("")
    
    if in_table:
        html_lines.append(table_to_html(table_rows))
    
    return "\n".join(html_lines)


def table_to_html(rows: List[str]) -> str:
    """Convert markdown table rows to HTML table."""
    if not rows:
        return ""
    
    html = ["<table>"]
    
    for i, row in enumerate(rows):
        cells = [cell.strip() for cell in row.split('|')[1:-1]]
        if not cells:
            continue
        
        if i == 0:
            html.append("<thead><tr>")
            for cell in cells:
                html.append(f"<th>{cell}</th>")
            html.append("</tr></thead><tbody>")
        elif i == 1 and all(c.startswith('-') for c in cells):
            # Skip separator row
            continue
        else:
            html.append("<tr>")
            for cell in cells:
                html.append(f"<td>{cell}</td>")
            html.append("</tr>")
    
    html.append("</tbody></table>")
    return "\n".join(html)


def save_reports(gate_result: Dict, normalized_data: Dict, metadata: Dict, output_dir: str = "reports"):
    """Save all report formats."""
    os.makedirs(output_dir, exist_ok=True)
    
    # JSON consolidated report
    consolidated = {
        "metadata": metadata,
        "gate_result": gate_result,
        "normalized_findings": normalized_data
    }
    
    json_path = os.path.join(output_dir, "consolidated-report.json")
    with open(json_path, 'w') as f:
        json.dump(consolidated, f, indent=2)
    print(f"Consolidated JSON report saved to {json_path}")
    
    # Markdown report
    md_path = os.path.join(output_dir, "security-report.md")
    md_content = generate_markdown_report(gate_result, normalized_data, metadata)
    with open(md_path, 'w') as f:
        f.write(md_content)
    print(f"Markdown report saved to {md_path}")
    
    # HTML report
    html_path = os.path.join(output_dir, "security-report.html")
    html_content = generate_html_report(gate_result, normalized_data, metadata)
    with open(html_path, 'w') as f:
        f.write(html_content)
    print(f"HTML report saved to {html_path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate consolidated security reports")
    parser.add_argument("--gate-result", default="reports/security-gate-result.json", help="Gate result input")
    parser.add_argument("--normalized", default="reports/normalized-findings.json", help="Normalized findings input")
    parser.add_argument("--output-dir", default="reports", help="Output directory")
    parser.add_argument("--run-id", default="local", help="Pipeline run ID")
    parser.add_argument("--commit-sha", default="unknown", help="Git commit SHA")
    parser.add_argument("--branch", default="unknown", help="Git branch")
    
    args = parser.parse_args()
    
    # Load data
    gate_result = load_gate_result(args.gate_result)
    normalized_data = load_normalized_findings(args.normalized)
    
    # Build metadata
    metadata = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "run_id": args.run_id,
        "commit_sha": args.commit_sha,
        "branch": args.branch,
        "pipeline": "devsecops-pipeline"
    }
    
    # Generate reports
    save_reports(gate_result, normalized_data, metadata, args.output_dir)


if __name__ == "__main__":
    main()