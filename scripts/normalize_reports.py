#!/usr/bin/env python3
"""
DevSecOps Pipeline - Report Normalization Module
Normalizes findings from various security scanners into a common schema.
"""

import json
import os
import sys
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict, field
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
    scanner_version: Optional[str] = None
    execution_status: str = "success"

    def deduplication_key(self) -> tuple:
        """Generate a key for deduplication that preserves distinct findings."""
        return (
            self.scanner,
            self.rule_id,
            self.file_path or "",
            self.line_number or 0,
            self.column or 0,
            hashlib.md5(self.message.encode()).hexdigest()[:8]
        )


@dataclass
class ScannerMetadata:
    """Metadata about a scanner execution."""
    scanner: str
    version: Optional[str] = None
    execution_status: str = "success"
    error_message: Optional[str] = None
    findings_count: int = 0
    execution_time_seconds: Optional[float] = None
    command: Optional[str] = None


def parse_severity(severity: Union[str, float, int, None], default: Union[Severity, str] = Severity.UNKNOWN) -> Severity:
    """Parse various severity formats to normalized Severity enum."""
    if severity is None:
        if isinstance(default, Severity):
            return default
        return parse_severity(default)

    # Handle numeric CVSS scores
    if isinstance(severity, (int, float)):
        score = float(severity)
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

    severity_str = str(severity).lower().strip()

    # Direct string mappings
    if severity_str in ("critical", "crit"):
        return Severity.CRITICAL
    elif severity_str in ("high", "error"):
        return Severity.HIGH
    elif severity_str in ("medium", "warn", "warning", "moderate"):
        return Severity.MEDIUM
    elif severity_str in ("low", "info", "information", "note"):
        return Severity.LOW
    elif severity_str in ("informational",):
        return Severity.INFO

    # Try numeric parsing for string numbers
    try:
        score = float(severity_str)
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


def validate_json_structure(data: Any, expected_type: type, path: str = "") -> bool:
    """Validate JSON structure matches expected type."""
    if not isinstance(data, expected_type):
        print(f"Validation error at {path}: expected {expected_type.__name__}, got {type(data).__name__}")
        return False
    return True


def safe_get(data: Dict, *keys, default=None) -> Any:
    """Safely get nested dictionary value."""
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def normalize_gitleaks(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Gitleaks JSON report."""
    findings = []

    # Gitleaks outputs a list of findings directly
    if isinstance(data, list):
        leaks = data
    else:
        leaks = data.get("leaks", [])

    if not validate_json_structure(leaks, list, "gitleaks.leaks"):
        return []

    scanner_version = safe_get(data, "version") if isinstance(data, dict) else None

    for leak in leaks:
        if not validate_json_structure(leak, dict, "gitleaks.leak"):
            continue

        finding = Finding(
            scanner=ScannerType.GITLEAKS.value,
            rule_id=str(leak.get("RuleID", "unknown")),
            severity=parse_severity(leak.get("Severity", "HIGH")).value,
            message=str(leak.get("Description", "Secret detected")),
            file_path=leak.get("File"),
            line_number=leak.get("StartLine"),
            column=leak.get("StartColumn"),
            code_snippet=leak.get("Match"),
            references=[leak.get("URL")] if leak.get("URL") else None,
            raw_data=leak,
            scanner_version=scanner_version
        )
        findings.append(finding)

    return findings


def normalize_semgrep(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Semgrep JSON report."""
    findings = []

    results = data.get("results", [])
    if not validate_json_structure(results, list, "semgrep.results"):
        return []

    scanner_version = safe_get(data, "version")

    for result in results:
        if not validate_json_structure(result, dict, "semgrep.result"):
            continue

        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Parse severity from metadata or use default
        severity_str = metadata.get("impact", extra.get("severity", "MEDIUM"))

        finding = Finding(
            scanner=ScannerType.SEMGREP.value,
            rule_id=str(result.get("check_id", "unknown")),
            severity=parse_severity(severity_str).value,
            message=str(extra.get("message", "Semgrep finding")),
            file_path=result.get("path"),
            line_number=safe_get(result, "start", "line"),
            column=safe_get(result, "start", "col"),
            code_snippet=extra.get("lines"),
            cwe_ids=metadata.get("cwe", []) if isinstance(metadata.get("cwe"), list) else (
                [metadata["cwe"]] if metadata.get("cwe") else None
            ),
            references=metadata.get("references", []) if isinstance(metadata.get("references"), list) else (
                [metadata["references"]] if metadata.get("references") else None
            ),
            confidence=metadata.get("confidence"),
            raw_data=result,
            scanner_version=scanner_version
        )
        findings.append(finding)

    return findings


def normalize_bandit(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Bandit JSON report."""
    findings = []

    results = data.get("results", [])
    if not validate_json_structure(results, list, "bandit.results"):
        return []

    scanner_version = safe_get(data, "version") or safe_get(data, "generator", "version")

    for result in results:
        if not validate_json_structure(result, dict, "bandit.result"):
            continue

        cwe_id = None
        issue_cwe = result.get("issue_cwe")
        if issue_cwe:
            if isinstance(issue_cwe, dict):
                cwe_id = issue_cwe.get("id")
            else:
                cwe_id = str(issue_cwe)

        finding = Finding(
            scanner=ScannerType.BANDIT.value,
            rule_id=str(result.get("test_id", "unknown")),
            severity=parse_severity(result.get("issue_severity", "MEDIUM")).value,
            message=str(result.get("issue_text", "Bandit finding")),
            file_path=result.get("filename"),
            line_number=result.get("line_number"),
            column=result.get("col_offset"),
            code_snippet=result.get("code"),
            cwe_ids=[cwe_id] if cwe_id else None,
            confidence=str(result.get("issue_confidence", "")).capitalize() if result.get("issue_confidence") else None,
            raw_data=result,
            scanner_version=scanner_version
        )
        findings.append(finding)

    return findings


def normalize_osv_scanner(data: Dict[str, Any]) -> List[Finding]:
    """Normalize OSV-Scanner JSON report (supports 1.x and 2.x formats)."""
    findings = []

    results = data.get("results", [])
    if not validate_json_structure(results, list, "osv-scanner.results"):
        return []

    scanner_version = safe_get(data, "version")

    for result in results:
        if not validate_json_structure(result, dict, "osv-scanner.result"):
            continue

        packages = result.get("packages", [])
        for pkg in packages:
            vulns = pkg.get("vulnerabilities", [])
            for vuln in vulns:
                # Parse affected versions from multiple possible locations
                fix_versions = []
                
                # Try affected.ranges.events (OSV schema)
                affected = vuln.get("affected", [])
                for aff in affected:
                    ranges = aff.get("ranges", [])
                    for r in ranges:
                        events = r.get("events", [])
                        for event in events:
                            if "fixed" in event:
                                fix_versions.append(event["fixed"])
                
                # Also check for direct fixed_versions field (some formats)
                if "fixed_versions" in vuln:
                    fix_versions.extend(vuln.get("fixed_versions", []))

                vuln_id = vuln.get("id", "unknown")
                cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else None
                if not cve_ids and "aliases" in vuln:
                    cve_ids = [a for a in vuln["aliases"] if a.startswith("CVE-")] or None

                # Severity: try multiple locations (OSV-Scanner 2.x uses different schema)
                # Prefer database_specific.severity (string) over severity array (CVSS objects)
                severity = None
                if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                    severity = vuln["database_specific"]["severity"]
                elif "database" in vuln and "severity" in vuln["database"]:
                    severity = vuln["database"]["severity"]
                elif "severity" in vuln:
                    sev = vuln["severity"]
                    # If severity is an array (CVSS objects), skip it and use default
                    if not isinstance(sev, list):
                        severity = sev
                elif "summary" in vuln:
                    # Some formats embed severity in summary
                    pass
                
                # References: handle different formats
                references = []
                for ref in vuln.get("references", []):
                    if isinstance(ref, dict):
                        url = ref.get("url")
                        if url:
                            references.append(url)
                    elif isinstance(ref, str):
                        references.append(ref)

                # Package info - handle different schemas
                pkg_name = safe_get(pkg, "package", "name", default="unknown")
                pkg_version = safe_get(pkg, "package", "version", default="unknown")
                pkg_path = safe_get(pkg, "package", "path")  # May be None in 2.x

                finding = Finding(
                    scanner=ScannerType.OSV_SCANNER.value,
                    rule_id=vuln_id,
                    severity=parse_severity(severity, default="MEDIUM").value,
                    message=f"Vulnerable dependency: {pkg_name}@{pkg_version}",
                    file_path=pkg_path,
                    cve_ids=cve_ids,
                    references=references if references else None,
                    fix_versions=fix_versions if fix_versions else None,
                    raw_data=vuln,
                    scanner_version=scanner_version
                )
                findings.append(finding)

    return findings


def normalize_pip_audit(data: Union[Dict[str, Any], List[Any]]) -> List[Finding]:
    """Normalize pip-audit JSON report."""
    findings = []

    # pip-audit outputs a list of vulnerabilities or a dict with vulnerabilities key
    vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])

    if not validate_json_structure(vulns, list, "pip-audit.vulnerabilities"):
        return []

    scanner_version = None
    if isinstance(data, dict):
        scanner_version = safe_get(data, "version")

    for vuln in vulns:
        if not validate_json_structure(vuln, dict, "pip-audit.vuln"):
            continue

        vuln_id = vuln.get("id", "unknown")
        cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else None
        if not cve_ids and "aliases" in vuln:
            cve_ids = [a for a in vuln["aliases"] if a.startswith("CVE-")] or None

        finding = Finding(
            scanner=ScannerType.PIP_AUDIT.value,
            rule_id=vuln_id,
            severity=parse_severity(vuln.get("severity", "MEDIUM")).value,
            message=f"Vulnerable dependency: {vuln.get('package', 'unknown')}",
            file_path="requirements.txt",
            cve_ids=cve_ids,
            references=[ref.get("url") for ref in vuln.get("references", []) if ref.get("url")],
            fix_versions=vuln.get("fix_versions", []),
            raw_data=vuln,
            scanner_version=scanner_version
        )
        findings.append(finding)

    return findings


def normalize_trivy(data: Dict[str, Any]) -> List[Finding]:
    """Normalize Trivy JSON report."""
    findings = []

    results = data.get("Results", [])
    if not validate_json_structure(results, list, "trivy.Results"):
        return []

    scanner_version = safe_get(data, "Metadata", "Scanner", "Version") or safe_get(data, "Version")

    for result in results:
        if not validate_json_structure(result, dict, "trivy.result"):
            continue

        target = result.get("Target", "unknown")
        vulns = result.get("Vulnerabilities", [])
        misconfigs = result.get("Misconfigurations", [])

        # Process vulnerabilities
        for vuln in vulns:
            if not validate_json_structure(vuln, dict, "trivy.vuln"):
                continue

            vuln_id = vuln.get("VulnerabilityID", "unknown")
            cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else None

            finding = Finding(
                scanner=ScannerType.TRIVY.value,
                rule_id=vuln_id,
                severity=parse_severity(vuln.get("Severity", "MEDIUM")).value,
                message=f"{vuln.get('Title', 'Vulnerability')} in {vuln.get('PkgName', 'unknown')}",
                file_path=target,
                cve_ids=cve_ids,
                references=vuln.get("References", []),
                fix_versions=[vuln.get("FixedVersion")] if vuln.get("FixedVersion") else None,
                raw_data=vuln,
                scanner_version=scanner_version
            )
            findings.append(finding)

        # Process misconfigurations
        for misconfig in misconfigs:
            if not validate_json_structure(misconfig, dict, "trivy.misconfig"):
                continue

            finding = Finding(
                scanner=ScannerType.TRIVY.value,
                rule_id=str(misconfig.get("ID", "unknown")),
                severity=parse_severity(misconfig.get("Severity", "MEDIUM")).value,
                message=str(misconfig.get("Title", "Misconfiguration")),
                file_path=target,
                references=misconfig.get("References", []),
                raw_data=misconfig,
                scanner_version=scanner_version
            )
            findings.append(finding)

    return findings


def parse_zap_rules_tsv(tsv_path: str) -> Dict[str, Dict[str, str]]:
    """Parse ZAP rules TSV configuration file."""
    rules = {}

    if not os.path.exists(tsv_path):
        print(f"Warning: ZAP rules file not found at {tsv_path}")
        return rules

    with open(tsv_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split('\t')
            if len(parts) < 4:
                print(f"Warning: Invalid TSV format at line {line_num}: {line}")
                continue

            alert_id = parts[0].strip()
            action = parts[1].strip().upper()
            severity = parts[2].strip()
            justification = parts[3].strip()

            # Validate action
            valid_actions = {"FAIL", "WARN", "INFO", "SUPPRESS"}
            if action not in valid_actions:
                print(f"Warning: Invalid action '{action}' at line {line_num}, defaulting to WARN")
                action = "WARN"

            # Validate severity
            valid_severities = {"Critical", "High", "Medium", "Low", "Informational", "Info"}
            if severity not in valid_severities:
                print(f"Warning: Invalid severity '{severity}' at line {line_num}, defaulting to Medium")
                severity = "Medium"

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
        sites = [site] if site else []

    if not sites:
        print("Warning: No site data found in ZAP report")
        return []

    scanner_version = safe_get(data, "@version") or safe_get(data, "version")

    for s in sites:
        alerts = s.get("alerts", [])
        for alert in alerts:
            if not validate_json_structure(alert, dict, "zap.alert"):
                continue

            alert_id = str(alert.get("pluginid", "unknown"))
            rule_config = zap_rules.get(alert_id, {})

            # Determine action from rules or default
            action = rule_config.get("action", "WARN")
            configured_severity = rule_config.get("severity", alert.get("risk", "Medium"))
            justification = rule_config.get("justification", "")

            # Skip suppressed findings but track them
            if action == "SUPPRESS":
                # Still create finding but mark as suppressed for audit trail
                finding = Finding(
                    scanner=ScannerType.ZAP.value,
                    rule_id=alert_id,
                    severity=parse_severity(configured_severity).value,
                    message=f"[SUPPRESSED] {alert.get('alert', 'ZAP finding')}",
                    file_path=alert.get("url"),
                    cwe_ids=[alert.get("cweid")] if alert.get("cweid") and alert.get("cweid") != "-1" else None,
                    references=[alert.get("reference")] if alert.get("reference") else None,
                    raw_data={
                        **alert,
                        "zap_action": action,
                        "zap_justification": justification,
                        "zap_suppressed": True
                    },
                    scanner_version=scanner_version,
                    execution_status="suppressed"
                )
                findings.append(finding)
                continue

            finding = Finding(
                scanner=ScannerType.ZAP.value,
                rule_id=alert_id,
                severity=parse_severity(configured_severity).value,
                message=str(alert.get("alert", "ZAP finding")),
                file_path=alert.get("url"),
                cwe_ids=[alert.get("cweid")] if alert.get("cweid") and alert.get("cweid") != "-1" else None,
                references=[alert.get("reference")] if alert.get("reference") else None,
                raw_data={
                    **alert,
                    "zap_action": action,
                    "zap_justification": justification,
                    "zap_suppressed": False
                },
                scanner_version=scanner_version
            )
            findings.append(finding)

    return findings


def normalize_report(
    scanner: str,
    report_path: str,
    rules_tsv_path: str = ".zap/rules.tsv",
    scanner_metadata: Optional[ScannerMetadata] = None
) -> List[Finding]:
    """
    Normalize a scanner report based on scanner type.

    Args:
        scanner: Scanner type (gitleaks, semgrep, bandit, osv-scanner, pip-audit, trivy, zap)
        report_path: Path to the JSON report file
        rules_tsv_path: Path to ZAP rules TSV (for ZAP scanner)
        scanner_metadata: Optional metadata about scanner execution

    Returns:
        List of normalized Finding objects
    """
    if not os.path.exists(report_path):
        print(f"Warning: Report not found: {report_path}")
        if scanner_metadata:
            scanner_metadata.execution_status = "missing"
            scanner_metadata.error_message = f"Report file not found: {report_path}"
        return []

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except UnicodeDecodeError:
        # Handle non-UTF8 encoded JSON (e.g., Windows-1252 output from some tools)
        try:
            with open(report_path, 'r', encoding='utf-8', errors='replace') as f:
                data = json.load(f)
            print(f"Warning: {report_path} contained invalid UTF-8, replaced invalid characters")
        except json.JSONDecodeError as e:
            print(f"Error parsing {report_path} (after UTF-8 replacement): {e}")
            if scanner_metadata:
                scanner_metadata.execution_status = "parse_error"
                scanner_metadata.error_message = str(e)
            return []
        except Exception as e:
            print(f"Error reading {report_path} (after UTF-8 replacement): {e}")
            if scanner_metadata:
                scanner_metadata.execution_status = "read_error"
                scanner_metadata.error_message = str(e)
            return []
    except json.JSONDecodeError as e:
        print(f"Error parsing {report_path}: {e}")
        if scanner_metadata:
            scanner_metadata.execution_status = "parse_error"
            scanner_metadata.error_message = str(e)
        return []
    except Exception as e:
        print(f"Error reading {report_path}: {e}")
        if scanner_metadata:
            scanner_metadata.execution_status = "read_error"
            scanner_metadata.error_message = str(e)
        return []

    scanner_lower = scanner.lower()

    try:
        if scanner_lower == "gitleaks":
            findings = normalize_gitleaks(data)
        elif scanner_lower == "semgrep":
            findings = normalize_semgrep(data)
        elif scanner_lower == "bandit":
            findings = normalize_bandit(data)
        elif scanner_lower in ("osv-scanner", "osv_scanner"):
            findings = normalize_osv_scanner(data)
        elif scanner_lower in ("pip-audit", "pip_audit"):
            findings = normalize_pip_audit(data)
        elif scanner_lower in ("trivy", "trivy-image"):
            findings = normalize_trivy(data)
        elif scanner_lower == "zap":
            findings = normalize_zap(data, rules_tsv_path)
        else:
            print(f"Unknown scanner type: {scanner}")
            if scanner_metadata:
                scanner_metadata.execution_status = "unknown_scanner"
                scanner_metadata.error_message = f"Unknown scanner type: {scanner}"
            return []

        # Update metadata with findings count
        if scanner_metadata:
            scanner_metadata.findings_count = len(findings)
            if not scanner_metadata.version:
                scanner_metadata.version = findings[0].scanner_version if findings else None

        return findings

    except Exception as e:
        print(f"Error normalizing {scanner} report: {e}")
        if scanner_metadata:
            scanner_metadata.execution_status = "normalization_error"
            scanner_metadata.error_message = str(e)
        return []


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate findings based on scanner, rule_id, file_path, line_number, column, and message hash."""
    seen = set()
    deduplicated = []

    for finding in findings:
        key = finding.deduplication_key()

        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)

    return deduplicated


def load_all_reports(
    reports_dir: str = "reports",
    rules_tsv_path: str = ".zap/rules.tsv"
) -> tuple[List[Finding], List[ScannerMetadata]]:
    """Load and normalize all reports in the reports directory."""
    all_findings = []
    scanner_metadata_list = []

    scanner_files = {
        "gitleaks": "gitleaks-report.json",
        "semgrep": "semgrep-report.json",
        "bandit": "bandit-report.json",
        "osv-scanner": "osv-scanner-report.json",
        "pip-audit": "pip-audit-report.json",
        "trivy": "trivy-report.json",
        "trivy-image": "trivy-image-report.json",
        "zap": "zap-report.json"
    }

    for scanner, filename in scanner_files.items():
        report_path = os.path.join(reports_dir, filename)
        metadata = ScannerMetadata(scanner=scanner, command=f"{scanner} scan")
        scanner_metadata_list.append(metadata)

        if os.path.exists(report_path):
            print(f"Normalizing {scanner} report...")
            findings = normalize_report(scanner, report_path, rules_tsv_path, metadata)
            all_findings.extend(findings)
            print(f"  Found {len(findings)} findings")
        else:
            print(f"Warning: {scanner} report not found at {report_path}")
            metadata.execution_status = "missing"
            metadata.error_message = f"Report file not found: {report_path}"

    # Deduplicate
    all_findings = deduplicate_findings(all_findings)
    print(f"Total findings after deduplication: {len(all_findings)}")

    return all_findings, scanner_metadata_list


def save_normalized_findings(
    findings: List[Finding],
    scanner_metadata: List[ScannerMetadata],
    output_path: str,
    pipeline_metadata: Optional[Dict[str, Any]] = None
):
    """Save normalized findings to JSON file with metadata."""
    output_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "pipeline_metadata": pipeline_metadata or {},
        "scanner_metadata": [asdict(m) for m in scanner_metadata],
        "findings": [asdict(f) for f in findings]
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"Normalized findings saved to {output_path}")


def load_normalized_findings(report_path: str) -> List[Finding]:
    """Load normalized findings from JSON report."""
    if not os.path.exists(report_path):
        raise FileNotFoundError(f"Normalized report not found: {report_path}")

    with open(report_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings = []
    for item in data.get("findings", []):
        # Filter out fields not in Finding dataclass
        finding_fields = {
            k: v for k, v in item.items()
            if k in Finding.__dataclass_fields__
        }
        findings.append(Finding(**finding_fields))

    return findings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Normalize security scanner reports")
    parser.add_argument("--reports-dir", default="reports", help="Reports directory")
    parser.add_argument("--output", default="reports/normalized-findings.json", help="Output file")
    parser.add_argument("--rules-tsv", default=".zap/rules.tsv", help="ZAP rules TSV")

    args = parser.parse_args()

    findings, metadata = load_all_reports(args.reports_dir, args.rules_tsv)
    save_normalized_findings(findings, metadata, args.output)