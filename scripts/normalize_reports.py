#!/usr/bin/env python3
"""
DevSecOps Pipeline - Report Normalization Module
Normalizes findings from various security scanners into a common schema.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    """Normalized severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"
    UNKNOWN = "Unknown"


class ScannerType(Enum):
    """Supported scanner types."""
    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    OSV_SCANNER = "osv-scanner"
    PIP_AUDIT = "pip-audit"
    TRIVY = "trivy"
    ZAP = "zap"


@dataclass
class Finding:
    """Normalized finding schema."""
    scanner: str
    rule_id: str
    severity: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None
    code_snippet: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    references: Optional[List[str]] = None
    fix_versions: Optional[List[str]] = None
    confidence: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


def parse_severity(severity: str) -> Severity:
    """Parse various severity formats to normalized Severity enum."""
    if not severity:
        return Severity.UNKNOWN
    
    severity_lower = severity.lower().strip()
    
    # Direct mappings
    if severity_lower in ("critical", "crit"):
        return Severity.CRITICAL
    elif severity_lower in ("high", "error"):
        return Severity.HIGH
    elif severity_lower in ("medium", "warn", "warning", "moderate"):
        return Severity.MEDIUM
    elif severity_lower in ("low", "info", "information", "note"):
        return Severity.LOW
    elif severity_lower in ("informational",):
        return Severity.INFO
    
    # Numeric mappings (CVSS-like)
    try:
        score = float(severity_lower)
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score >= 0.1:
            return Severity.LOW
        else:
            return Severity.INFO
    except ValueError:
        pass
    
    return Severity.UNKNOWN


def normalize_gitleaks(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Gitleaks JSON report."""
    findings = []
    
    # Gitleaks outputs a list of findings directly
    if isinstance(data, list):
        leaks = data
    else:
        leaks = data.get("leaks", [])
    
    for leak in leaks:
        finding = Finding(
            scanner=ScannerType.GITLEAKS.value,
            rule_id=leak.get("RuleID", "unknown"),
            severity=parse_severity(leak.get("Severity", "HIGH")).value,
            message=leak.get("Description", "Secret detected"),
            file_path=leak.get("File"),
            line_number=leak.get("StartLine"),
            column=leak.get("StartColumn"),
            code_snippet=leak.get("Match"),
            references=[leak.get("URL")] if leak.get("URL") else None,
            raw_data=leak
        )
        findings.append(finding)
    
    return findings


def normalize_semgrep(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Semgrep JSON report."""
    findings = []
    
    results = data.get("results", [])
    
    for result in results:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        
        # Parse severity from metadata or use default
        severity_str = metadata.get("impact", extra.get("severity", "MEDIUM"))
        
        finding = Finding(
            scanner=ScannerType.SEMGREP.value,
            rule_id=result.get("check_id", "unknown"),
            severity=parse_severity(severity_str).value,
            message=extra.get("message", "Semgrep finding"),
            file_path=result.get("path"),
            line_number=result.get("start", {}).get("line"),
            column=result.get("start", {}).get("col"),
            code_snippet=extra.get("lines"),
            cwe_ids=metadata.get("cwe", []) if isinstance(metadata.get("cwe"), list) else (
                [metadata["cwe"]] if metadata.get("cwe") else None
            ),
            references=metadata.get("references", []) if isinstance(metadata.get("references"), list) else (
                [metadata["references"]] if metadata.get("references") else None
            ),
            confidence=metadata.get("confidence"),
            raw_data=result
        )
        findings.append(finding)
    
    return findings


def normalize_bandit(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Bandit JSON report."""
    findings = []
    
    results = data.get("results", [])
    
    for result in results:
        finding = Finding(
            scanner=ScannerType.BANDIT.value,
            rule_id=result.get("test_id", "unknown"),
            severity=parse_severity(result.get("issue_severity", "MEDIUM")).value,
            message=result.get("issue_text", "Bandit finding"),
            file_path=result.get("filename"),
            line_number=result.get("line_number"),
            column=result.get("col_offset"),
            code_snippet=result.get("code"),
            cwe_ids=[result.get("issue_cwe", {}).get("id")] if result.get("issue_cwe") else None,
            confidence=result.get("issue_confidence"),
            raw_data=result
        )
        findings.append(finding)
    
    return findings


def normalize_osv_scanner(data: Dict[str, Any]) -> List[Finding]:
    """Normalize OSV-Scanner JSON report."""
    findings = []
    
    results = data.get("results", [])
    
    for result in results:
        packages = result.get("packages", [])
        for pkg in packages:
            vulns = pkg.get("vulnerabilities", [])
            for vuln in vulns:
                # Parse affected versions
                affected = vuln.get("affected", [])
                fix_versions = []
                for aff in affected:
                    ranges = aff.get("ranges", [])
                    for r in ranges:
                        events = r.get("events", [])
                        for event in events:
                            if "fixed" in event:
                                fix_versions.append(event["fixed"])
                
                finding = Finding(
                    scanner=ScannerType.OSV_SCANNER.value,
                    rule_id=vuln.get("id", "unknown"),
                    severity=parse_severity(
                        vuln.get("database_specific", {}).get("severity", "MEDIUM")
                    ).value,
                    message=f"Vulnerable dependency: {pkg.get('package', {}).get('name')}@{pkg.get('package', {}).get('version')}",
                    file_path=pkg.get("package", {}).get("path"),
                    cve_ids=[vuln.get("id")] if vuln.get("id", "").startswith("CVE-") else None,
                    references=[ref.get("url") for ref in vuln.get("references", [])],
                    fix_versions=fix_versions if fix_versions else None,
                    raw_data=vuln
                )
                findings.append(finding)
    
    return findings


def normalize_pip_audit(data: Dict[str, Any]) -> List[Finding]:
    """Normalize pip-audit JSON report."""
    findings = []
    
    # pip-audit outputs a list of vulnerabilities
    vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
    
    for vuln in vulns:
        finding = Finding(
            scanner=ScannerType.PIP_AUDIT.value,
            rule_id=vuln.get("id", "unknown"),
            severity=parse_severity(
                vuln.get("severity", "MEDIUM") if "severity" in vuln else "MEDIUM"
            ).value,
            message=f"Vulnerable dependency: {vuln.get('package', 'unknown')}",
            file_path="requirements.txt",
            cve_ids=[vuln.get("id")] if vuln.get("id", "").startswith("CVE-") else None,
            references=[ref.get("url") for ref in vuln.get("references", [])],
            fix_versions=vuln.get("fix_versions", []),
            raw_data=vuln
        )
        findings.append(finding)
    
    return findings


def normalize_trivy(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Trivy JSON report."""
    findings = []
    
    results = data.get("Results", [])
    
    for result in results:
        target = result.get("Target", "unknown")
        vulns = result.get("Vulnerabilities", [])
        misconfigs = result.get("Misconfigurations", [])
        
        # Process vulnerabilities
        for vuln in vulns:
            finding = Finding(
                scanner=ScannerType.TRIVY.value,
                rule_id=vuln.get("VulnerabilityID", "unknown"),
                severity=parse_severity(vuln.get("Severity", "MEDIUM")).value,
                message=f"{vuln.get('Title', 'Vulnerability')} in {vuln.get('PkgName', 'unknown')}",
                file_path=target,
                cve_ids=[vuln.get("VulnerabilityID")] if vuln.get("VulnerabilityID", "").startswith("CVE-") else None,
                references=vuln.get("References", []),
                fix_versions=[vuln.get("FixedVersion")] if vuln.get("FixedVersion") else None,
                raw_data=vuln
            )
            findings.append(finding)
        
        # Process misconfigurations
        for misconfig in misconfigs:
            finding = Finding(
                scanner=ScannerType.TRIVY.value,
                rule_id=misconfig.get("ID", "unknown"),
                severity=parse_severity(misconfig.get("Severity", "MEDIUM")).value,
                message=misconfig.get("Title", "Misconfiguration"),
                file_path=target,
                references=misconfig.get("References", []),
                raw_data=misconfig
            )
            findings.append(finding)
    
    return findings


def parse_zap_rules_tsv(tsv_path: str) -> Dict[str, Dict[str, str]]:
    """Parse ZAP rules TSV configuration file."""
    rules = {}
    
    if not os.path.exists(tsv_path):
        return rules
    
    with open(tsv_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split('\t')
            if len(parts) >= 4:
                alert_id = parts[0].strip()
                action = parts[1].strip().upper()
                severity = parts[2].strip()
                justification = parts[3].strip()
                
                rules[alert_id] = {
                    "action": action,
                    "severity": severity,
                    "justification": justification
                }
    
    return rules


def normalize_zap(data: Dict[str, Any], rules_tsv_path: str = ".zap/rules.tsv") -> List[Finding]:
    """Normalize ZAP JSON report with rules.tsv policy."""
    findings = []
    
    # Parse rules configuration
    zap_rules = parse_zap_rules_tsv(rules_tsv_path)
    
    site = data.get("site", [])
    if isinstance(site, list):
        sites = site
    else:
        sites = [site]
    
    for s in sites:
        alerts = s.get("alerts", [])
        
        for alert in alerts:
            alert_id = str(alert.get("pluginid", "unknown"))
            rule_config = zap_rules.get(alert_id, {})
            
            # Determine action from rules or default
            action = rule_config.get("action", "WARN")
            configured_severity = rule_config.get("severity", alert.get("risk", "Medium"))
            justification = rule_config.get("justification", "")
            
            # Skip suppressed findings
            if action == "SUPPRESS":
                continue
            
            finding = Finding(
                scanner=ScannerType.ZAP.value,
                rule_id=alert_id,
                severity=parse_severity(configured_severity).value,
                message=alert.get("alert", "ZAP finding"),
                file_path=alert.get("url"),
                cwe_ids=[alert.get("cweid")] if alert.get("cweid") and alert.get("cweid") != "-1" else None,
                references=[alert.get("reference")] if alert.get("reference") else None,
                raw_data={
                    **alert,
                    "zap_action": action,
                    "zap_justification": justification
                }
            )
            findings.append(finding)
    
    return findings


def normalize_report(scanner: str, report_path: str, rules_tsv_path: str = ".zap/rules.tsv") -> List[Finding]:
    """
    Normalize a scanner report based on scanner type.
    
    Args:
        scanner: Scanner type (gitleaks, semgrep, bandit, osv-scanner, pip-audit, trivy, zap)
        report_path: Path to the JSON report file
        rules_tsv_path: Path to ZAP rules TSV (for ZAP scanner)
        
    Returns:
        List of normalized Finding objects
    """
    if not os.path.exists(report_path):
        print(f"Warning: Report not found: {report_path}")
        return []
    
    with open(report_path, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error parsing {report_path}: {e}")
            return []
    
    scanner_lower = scanner.lower()
    
    if scanner_lower == "gitleaks":
        return normalize_gitleaks(data)
    elif scanner_lower == "semgrep":
        return normalize_semgrep(data)
    elif scanner_lower == "bandit":
        return normalize_bandit(data)
    elif scanner_lower in ("osv-scanner", "osv_scanner"):
        return normalize_osv_scanner(data)
    elif scanner_lower in ("pip-audit", "pip_audit"):
        return normalize_pip_audit(data)
    elif scanner_lower == "trivy":
        return normalize_trivy(data)
    elif scanner_lower == "zap":
        return normalize_zap(data, rules_tsv_path)
    else:
        print(f"Unknown scanner type: {scanner}")
        return []


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate findings based on scanner, rule_id, file_path, and line_number."""
    seen = set()
    deduplicated = []
    
    for finding in findings:
        # Create deduplication key
        key = (
            finding.scanner,
            finding.rule_id,
            finding.file_path or "",
            finding.line_number or 0
        )
        
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
    
    return deduplicated


def load_all_reports(reports_dir: str = "reports") -> List[Finding]:
    """Load and normalize all reports in the reports directory."""
    all_findings = []
    
    scanner_files = {
        "gitleaks": "gitleaks-report.json",
        "semgrep": "semgrep-report.json",
        "bandit": "bandit-report.json",
        "osv-scanner": "osv-scanner-report.json",
        "pip-audit": "pip-audit-report.json",
        "trivy": "trivy-report.json",
        "zap": "zap-report.json"
    }
    
    for scanner, filename in scanner_files.items():
        report_path = os.path.join(reports_dir, filename)
        if os.path.exists(report_path):
            print(f"Normalizing {scanner} report...")
            findings = normalize_report(scanner, report_path)
            all_findings.extend(findings)
            print(f"  Found {len(findings)} findings")
        else:
            print(f"Warning: {scanner} report not found at {report_path}")
    
    # Deduplicate
    all_findings = deduplicate_findings(all_findings)
    print(f"Total findings after deduplication: {len(all_findings)}")
    
    return all_findings


def save_normalized_findings(findings: List[Finding], output_path: str):
    """Save normalized findings to JSON file."""
    output_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings]
    }
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"Normalized findings saved to {output_path}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Normalize security scanner reports")
    parser.add_argument("--reports-dir", default="reports", help="Reports directory")
    parser.add_argument("--output", default="reports/normalized-findings.json", help="Output file")
    parser.add_argument("--rules-tsv", default=".zap/rules.tsv", help="ZAP rules TSV")
    
    args = parser.parse_args()
    
    findings = load_all_reports(args.reports_dir)
    save_normalized_findings(findings, args.output)