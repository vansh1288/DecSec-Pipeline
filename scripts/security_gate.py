#!/usr/bin/env python3
"""
DevSecOps Pipeline - Security Gate
Evaluates normalized security findings against policy and determines pass/fail.
"""

import json
import os
import sys
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import Counter


class Severity(Enum):
    """Severity levels for policy evaluation."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0
    UNKNOWN = -1


class PolicyAction(Enum):
    """Policy actions for severity levels."""
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"


@dataclass
class PolicyConfig:
    """Security policy configuration loaded from YAML."""
    mode: str = "strict"
    severity_actions: Dict[str, PolicyAction] = field(default_factory=dict)
    scanner_failures: PolicyAction = PolicyAction.FAIL
    missing_reports: PolicyAction = PolicyAction.FAIL
    required_scanners: List[str] = field(default_factory=list)
    suppressions_enabled: bool = True
    suppressions_require_justification: bool = True
    suppressions_require_expiry: bool = True
    suppressions_max_duration_days: int = 90
    scanner_overrides: Dict[str, Any] = field(default_factory=dict)
    rule_exceptions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Set defaults if not provided
        defaults = {
            "critical": PolicyAction.FAIL,
            "high": PolicyAction.FAIL,
            "medium": PolicyAction.WARN,
            "low": PolicyAction.INFO,
            "informational": PolicyAction.INFO,
            "unknown": PolicyAction.FAIL,
        }
        for sev, action in defaults.items():
            if sev not in self.severity_actions:
                self.severity_actions[sev] = action


@dataclass
class Finding:
    """Normalized finding from report."""
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
    zap_action: Optional[str] = None
    zap_justification: Optional[str] = None
    zap_suppressed: bool = False
    execution_status: str = "success"
    scanner_version: Optional[str] = None


@dataclass
class GateResult:
    """Security gate evaluation result."""
    passed: bool
    summary: Dict[str, int]
    findings_by_severity: Dict[str, List[Finding]]
    policy_violations: List[Finding]
    suppressed_findings: List[Finding]
    scanner_failures: List[Dict[str, Any]]
    missing_reports: List[str]
    execution_metadata: Dict[str, Any]


def parse_severity(severity: str) -> Severity:
    """Parse severity string to Severity enum."""
    if not severity:
        return Severity.UNKNOWN

    severity_lower = severity.lower().strip()

    mapping = {
        "critical": Severity.CRITICAL,
        "crit": Severity.CRITICAL,
        "high": Severity.HIGH,
        "error": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "warn": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "information": Severity.INFO,
        "note": Severity.INFO,
        "informational": Severity.INFO,
    }

    return mapping.get(severity_lower, Severity.UNKNOWN)


def load_policy(policy_path: str) -> PolicyConfig:
    """Load policy configuration from YAML file."""
    if not os.path.exists(policy_path):
        print(f"Warning: Policy file not found: {policy_path}, using defaults")
        return create_default_policy()

    try:
        with open(policy_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error parsing policy YAML: {e}")
        return create_default_policy()

    if not data:
        print("Warning: Empty policy file, using defaults")
        return create_default_policy()

    # Parse severity actions
    severity_actions = {}
    for sev, action_str in data.get("severity", {}).items():
        try:
            severity_actions[sev.lower()] = PolicyAction(action_str.lower())
        except ValueError:
            print(f"Warning: Invalid policy action '{action_str}' for severity '{sev}', using FAIL")
            severity_actions[sev.lower()] = PolicyAction.FAIL

    policy = PolicyConfig(
        mode=data.get("mode", "strict"),
        severity_actions=severity_actions,
        scanner_failures=PolicyAction(data.get("scanner_failures", "FAIL").lower()),
        missing_reports=PolicyAction(data.get("missing_reports", "FAIL").lower()),
        required_scanners=data.get("required_scanners", []),
        suppressions_enabled=data.get("suppressions", {}).get("enabled", True),
        suppressions_require_justification=data.get("suppressions", {}).get("require_justification", True),
        suppressions_require_expiry=data.get("suppressions", {}).get("require_expiry", True),
        suppressions_max_duration_days=data.get("suppressions", {}).get("max_duration_days", 90),
        scanner_overrides=data.get("scanner_overrides", {}),
        rule_exceptions=data.get("rule_exceptions", {}),
    )

    return policy


def create_default_policy() -> PolicyConfig:
    """Create default strict policy configuration."""
    return PolicyConfig(
        mode="strict",
        severity_actions={
            "critical": PolicyAction.FAIL,
            "high": PolicyAction.FAIL,
            "medium": PolicyAction.WARN,
            "low": PolicyAction.INFO,
            "informational": PolicyAction.INFO,
            "unknown": PolicyAction.FAIL,
        },
        scanner_failures=PolicyAction.FAIL,
        missing_reports=PolicyAction.FAIL,
        required_scanners=[
            "gitleaks", "semgrep", "bandit", "osv-scanner",
            "pip-audit", "trivy", "zap"
        ],
        suppressions_enabled=True,
        suppressions_require_justification=True,
        suppressions_require_expiry=True,
        suppressions_max_duration_days=90,
    )


def create_educational_policy() -> PolicyConfig:
    """Create educational baseline policy configuration (more lenient)."""
    return PolicyConfig(
        mode="educational",
        severity_actions={
            "critical": PolicyAction.FAIL,
            "high": PolicyAction.FAIL,
            "medium": PolicyAction.WARN,
            "low": PolicyAction.INFO,
            "informational": PolicyAction.INFO,
            "unknown": PolicyAction.WARN,
        },
        scanner_failures=PolicyAction.WARN,
        missing_reports=PolicyAction.WARN,
        required_scanners=[
            "gitleaks", "semgrep", "bandit", "osv-scanner",
            "pip-audit", "trivy", "zap"
        ],
        suppressions_enabled=True,
        suppressions_require_justification=True,
        suppressions_require_expiry=True,
        suppressions_max_duration_days=90,
    )


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


def load_scanner_metadata(report_path: str) -> List[Dict[str, Any]]:
    """Load scanner metadata from normalized findings report."""
    if not os.path.exists(report_path):
        return []

    with open(report_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    return data.get("scanner_metadata", [])


def check_suppression_valid(finding: Finding, policy: PolicyConfig) -> bool:
    """Check if a suppression is valid according to policy."""
    if not policy.suppressions_enabled:
        return False

    # Check if finding has suppression metadata
    if not finding.zap_suppressed and finding.zap_action != "SUPPRESS":
        return False

    # Check justification requirement
    if policy.suppressions_require_justification:
        justification = finding.zap_justification or ""
        if not justification or len(justification.strip()) < 10:
            return False

    # Check expiry requirement
    if policy.suppressions_require_expiry:
        # In a real implementation, this would check an expiry date field
        # For now, we'll check if justification contains a date-like pattern
        import re
        justification = finding.zap_justification or ""
        # Look for ISO date pattern (YYYY-MM-DD)
        if not re.search(r'\d{4}-\d{2}-\d{2}', justification):
            return False

    # Check max duration (would need expiry date parsing in real implementation)
    # For now, just return True if other checks pass
    return True


def evaluate_policy(
    findings: List[Finding],
    scanner_metadata: List[Dict[str, Any]],
    policy: PolicyConfig,
    missing_reports: List[str]
) -> GateResult:
    """
    Evaluate findings against security policy.

    Args:
        findings: List of normalized findings
        scanner_metadata: List of scanner execution metadata
        policy: Policy configuration
        missing_reports: List of missing required scanner reports

    Returns:
        GateResult with pass/fail decision and details
    """
    # Group findings by severity
    findings_by_severity = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Informational": [],
        "Unknown": []
    }

    policy_violations = []
    suppressed_findings = []
    scanner_failures = []

    # Check scanner failures
    for meta in scanner_metadata:
        if meta.get("execution_status") != "success":
            scanner_failures.append({
                "scanner": meta.get("scanner"),
                "status": meta.get("execution_status"),
                "error": meta.get("error_message"),
                "command": meta.get("command")
            })

    # Check rule exceptions
    rule_exceptions = policy.rule_exceptions

    for finding in findings:
        severity_enum = parse_severity(finding.severity)
        severity_key = severity_enum.name.capitalize()
        if severity_key == "Info":
            severity_key = "Informational"
        elif severity_key == "Unknown":
            severity_key = "Unknown"

        findings_by_severity[severity_key].append(finding)

        # Check for rule exception
        exception_key = f"{finding.scanner}:{finding.rule_id}"
        if exception_key in rule_exceptions:
            exception = rule_exceptions[exception_key]
            # Check if exception has expired
            if "expires" in exception:
                from datetime import date
                try:
                    expiry = date.fromisoformat(exception["expires"])
                    if date.today() > expiry:
                        # Exception expired, treat normally
                        pass
                    else:
                        # Exception still valid, apply override
                        action = PolicyAction(exception.get("action", "INFO").lower())
                        if action == PolicyAction.FAIL:
                            policy_violations.append(finding)
                        continue
                except ValueError:
                    pass

        # Check ZAP suppressions
        if finding.zap_suppressed or finding.zap_action == "SUPPRESS":
            if check_suppression_valid(finding, policy):
                suppressed_findings.append(finding)
                continue
            else:
                # Invalid suppression, treat as violation if severity warrants
                pass

        # Check policy action for this severity
        action = policy.severity_actions.get(severity_enum.name.lower(), PolicyAction.FAIL)

        # Check scanner-specific override
        scanner_override = policy.scanner_overrides.get(finding.scanner, {})
        if "severity" in scanner_override:
            scanner_sev_action = scanner_override["severity"].get(severity_enum.name.lower())
            if scanner_sev_action:
                try:
                    action = PolicyAction(scanner_sev_action.lower())
                except ValueError:
                    pass

        if action == PolicyAction.FAIL:
            policy_violations.append(finding)

    # Determine overall result
    passed = True

    # Check policy violations
    if policy_violations:
        passed = False

    # Check scanner failures
    if scanner_failures and policy.scanner_failures == PolicyAction.FAIL:
        passed = False

    # Check missing reports
    if missing_reports and policy.missing_reports == PolicyAction.FAIL:
        passed = False

    # Build summary
    summary = {
        "Critical": len(findings_by_severity["Critical"]),
        "High": len(findings_by_severity["High"]),
        "Medium": len(findings_by_severity["Medium"]),
        "Low": len(findings_by_severity["Low"]),
        "Informational": len(findings_by_severity["Informational"]),
        "Unknown": len(findings_by_severity["Unknown"]),
        "Total": len(findings),
        "Suppressed": len(suppressed_findings),
        "PolicyViolations": len(policy_violations),
        "ScannerFailures": len(scanner_failures),
        "MissingReports": len(missing_reports),
    }

    # Count by scanner
    scanner_counts = Counter(f.scanner for f in findings)
    summary["by_scanner"] = dict(scanner_counts)

    execution_metadata = {
        "evaluated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "policy_violations": len(policy_violations),
        "suppressed_findings": len(suppressed_findings),
        "scanner_failures": len(scanner_failures),
        "missing_reports": len(missing_reports),
        "policy": {
            "mode": policy.mode,
            "severity": {k: v.value for k, v in policy.severity_actions.items()},
            "scanner_failures": policy.scanner_failures.value,
            "missing_reports": policy.missing_reports.value,
        }
    }

    return GateResult(
        passed=passed,
        summary=summary,
        findings_by_severity=findings_by_severity,
        policy_violations=policy_violations,
        suppressed_findings=suppressed_findings,
        scanner_failures=scanner_failures,
        missing_reports=missing_reports,
        execution_metadata=execution_metadata
    )


def print_summary(result: GateResult, verbose: bool = False):
    """Print human-readable summary to console."""
    print("\n" + "=" * 60)
    print("SECURITY GATE EVALUATION")
    print("=" * 60)

    status = "PASSED" if result.passed else "FAILED"
    print(f"Overall Result: {status}")
    print()

    print("Findings Summary:")
    print(f"  Critical:         {result.summary['Critical']}")
    print(f"  High:             {result.summary['High']}")
    print(f"  Medium:           {result.summary['Medium']}")
    print(f"  Low:              {result.summary['Low']}")
    print(f"  Informational:    {result.summary['Informational']}")
    print(f"  Unknown:          {result.summary['Unknown']}")
    print(f"  Suppressed:       {result.summary['Suppressed']}")
    print(f"  Policy Violations:{result.summary['PolicyViolations']}")
    print(f"  Scanner Failures: {result.summary['ScannerFailures']}")
    print(f"  Missing Reports:  {result.summary['MissingReports']}")
    print(f"  Total:            {result.summary['Total']}")
    print()

    print("Findings by Scanner:")
    for scanner, count in result.summary.get("by_scanner", {}).items():
        print(f"  {scanner}: {count}")
    print()

    if result.scanner_failures:
        print("Scanner Failures:")
        for sf in result.scanner_failures:
            print(f"  [{sf['scanner']}] {sf['status']}: {sf['error']}")
        print()

    if result.missing_reports:
        print("Missing Required Reports:")
        for mr in result.missing_reports:
            print(f"  {mr}")
        print()

    if result.policy_violations:
        print("Policy Violations (FAIL):")
        for v in result.policy_violations:
            print(f"  [{v.severity}] {v.scanner}/{v.rule_id}: {v.message[:80]}")
            if v.file_path:
                loc = f"  File: {v.file_path}"
                if v.line_number:
                    loc += f":{v.line_number}"
                print(loc)
        print()

    if result.suppressed_findings:
        print("Suppressed Findings:")
        for s in result.suppressed_findings:
            print(f"  [{s.severity}] {s.scanner}/{s.rule_id}: {s.message[:80]}")
            if s.zap_justification:
                print(f"    Justification: {s.zap_justification[:100]}")
        print()

    if verbose and result.findings_by_severity:
        print("All Findings (verbose):")
        for severity in ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]:
            findings = result.findings_by_severity.get(severity, [])
            if findings:
                print(f"\n  {severity} ({len(findings)}):")
                for f in findings[:10]:
                    print(f"    [{f.scanner}/{f.rule_id}] {f.message[:100]}")
                    if f.file_path:
                        loc = f"      File: {f.file_path}"
                        if f.line_number:
                            loc += f":{f.line_number}"
                        print(loc)
                if len(findings) > 10:
                    print(f"      ... and {len(findings) - 10} more")


def save_gate_result(result: GateResult, output_path: str):
    """Save gate evaluation result to JSON."""
    output_data = {
        "passed": result.passed,
        "summary": result.summary,
        "policy_violations": [asdict(f) for f in result.policy_violations],
        "suppressed_findings": [asdict(f) for f in result.suppressed_findings],
        "scanner_failures": result.scanner_failures,
        "missing_reports": result.missing_reports,
        "execution_metadata": result.execution_metadata
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    print(f"Gate result saved to {output_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Security Gate - Evaluate findings against policy")
    parser.add_argument("--input", default="reports/normalized-findings.json", help="Normalized findings input")
    parser.add_argument("--output", default="reports/security-gate-result.json", help="Gate result output")
    parser.add_argument("--policy", default="config/security-policy.yml", help="Policy configuration file")
    parser.add_argument("--policy-mode", choices=["strict", "educational"], help="Override policy mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--fail-on-missing", action="store_true", help="Fail if input report missing")

    args = parser.parse_args()

    # Load policy
    if args.policy_mode == "educational":
        policy = create_educational_policy()
        print("Using educational baseline policy mode")
    elif args.policy_mode == "strict":
        policy = create_default_policy()
        print("Using strict policy mode")
    else:
        policy = load_policy(args.policy)
        print(f"Using policy from {args.policy} (mode: {policy.mode})")

    # Check if input exists
    if not os.path.exists(args.input):
        if args.fail_on_missing:
            print(f"ERROR: Required report not found: {args.input}")
            sys.exit(1)
        else:
            print(f"WARNING: Report not found: {args.input}")
            print("Creating empty result...")
            result = GateResult(
                passed=True,
                summary={"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Unknown": 0, "Total": 0, "Suppressed": 0, "PolicyViolations": 0, "ScannerFailures": 0, "MissingReports": 0},
                findings_by_severity={},
                policy_violations=[],
                suppressed_findings=[],
                scanner_failures=[],
                missing_reports=[],
                execution_metadata={
                    "evaluated_at": datetime.utcnow().isoformat() + "Z",
                    "note": "No findings report available"
                }
            )
            save_gate_result(result, args.output)
            sys.exit(0)

    # Load findings and metadata
    try:
        findings = load_normalized_findings(args.input)
        scanner_metadata = load_scanner_metadata(args.input)
        print(f"Loaded {len(findings)} normalized findings from {len(scanner_metadata)} scanners")
    except Exception as e:
        print(f"ERROR loading findings: {e}")
        sys.exit(1)

    # Determine missing reports
    missing_reports = []
    required_scanners = policy.required_scanners
    available_scanners = {m.get("scanner") for m in scanner_metadata if m.get("execution_status") == "success"}
    for required in required_scanners:
        if required not in available_scanners:
            missing_reports.append(required)

    # Evaluate
    result = evaluate_policy(findings, scanner_metadata, policy, missing_reports)

    # Print summary
    print_summary(result, verbose=args.verbose)

    # Save result
    save_gate_result(result, args.output)

    # Exit with appropriate code
    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()