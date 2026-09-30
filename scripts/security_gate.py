#!/usr/bin/env python3
"""
DevSecOps Pipeline - Security Gate
Evaluates normalized security findings against policy and determines pass/fail.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
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
    """Security policy configuration."""
    critical: PolicyAction = PolicyAction.FAIL
    high: PolicyAction = PolicyAction.FAIL
    medium: PolicyAction = PolicyAction.WARN
    low: PolicyAction = PolicyAction.INFO
    info: PolicyAction = PolicyAction.INFO
    unknown: PolicyAction = PolicyAction.WARN


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


@dataclass
class GateResult:
    """Security gate evaluation result."""
    passed: bool
    summary: Dict[str, int]
    findings_by_severity: Dict[str, List[Finding]]
    policy_violations: List[Finding]
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


def load_normalized_findings(report_path: str) -> List[Finding]:
    """Load normalized findings from JSON report."""
    if not os.path.exists(report_path):
        raise FileNotFoundError(f"Normalized report not found: {report_path}")
    
    with open(report_path, 'r') as f:
        data = json.load(f)
    
    findings = []
    for item in data.get("findings", []):
        findings.append(Finding(**item))
    
    return findings


def evaluate_policy(findings: List[Finding], policy: PolicyConfig) -> GateResult:
    """
    Evaluate findings against security policy.
    
    Args:
        findings: List of normalized findings
        policy: Policy configuration
        
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
    
    for finding in findings:
        severity_enum = parse_severity(finding.severity)
        severity_key = severity_enum.name.capitalize()
        if severity_key == "Info":
            severity_key = "Informational"
        elif severity_key == "Unknown":
            severity_key = "Unknown"
        
        findings_by_severity[severity_key].append(finding)
        
        # Check policy action for this severity
        action = getattr(policy, severity_enum.name.lower())
        
        # Handle ZAP-specific suppressions
        if finding.zap_action == "SUPPRESS":
            continue
        
        if action == PolicyAction.FAIL:
            policy_violations.append(finding)
        elif action == PolicyAction.WARN and severity_enum in (Severity.CRITICAL, Severity.HIGH):
            # WARN for High/Critical is treated as violation in strict mode
            policy_violations.append(finding)
    
    # Determine overall result
    # Fail if any Critical or High findings with FAIL policy
    # Fail if any policy violations exist
    passed = len(policy_violations) == 0
    
    # Build summary
    summary = {
        "Critical": len(findings_by_severity["Critical"]),
        "High": len(findings_by_severity["High"]),
        "Medium": len(findings_by_severity["Medium"]),
        "Low": len(findings_by_severity["Low"]),
        "Informational": len(findings_by_severity["Informational"]),
        "Unknown": len(findings_by_severity["Unknown"]),
        "Total": len(findings)
    }
    
    # Count by scanner
    scanner_counts = Counter(f.scanner for f in findings)
    summary["by_scanner"] = dict(scanner_counts)
    
    execution_metadata = {
        "evaluated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "policy_violations": len(policy_violations),
        "policy": {
            "critical": policy.critical.value,
            "high": policy.high.value,
            "medium": policy.medium.value,
            "low": policy.low.value,
            "info": policy.info.value,
            "unknown": policy.unknown.value
        }
    }
    
    return GateResult(
        passed=passed,
        summary=summary,
        findings_by_severity=findings_by_severity,
        policy_violations=policy_violations,
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
    print(f"  Total:            {result.summary['Total']}")
    print()
    
    print("Findings by Scanner:")
    for scanner, count in result.summary.get("by_scanner", {}).items():
        print(f"  {scanner}: {count}")
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
    
    if verbose and result.findings_by_severity:
        print("All Findings (verbose):")
        for severity in ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]:
            findings = result.findings_by_severity.get(severity, [])
            if findings:
                print(f"\n  {severity} ({len(findings)}):")
                for f in findings[:10]:  # Limit to first 10 per severity
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
        "execution_metadata": result.execution_metadata
    }
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"Gate result saved to {output_path}")


def create_default_policy(educational_baseline: bool = False) -> PolicyConfig:
    """Create default policy configuration."""
    if educational_baseline:
        # In educational baseline mode, we're more lenient to show the difference
        return PolicyConfig(
            critical=PolicyAction.FAIL,
            high=PolicyAction.FAIL,
            medium=PolicyAction.WARN,
            low=PolicyAction.INFO,
            info=PolicyAction.INFO,
            unknown=PolicyAction.WARN
        )
    else:
        # Standard strict policy
        return PolicyConfig(
            critical=PolicyAction.FAIL,
            high=PolicyAction.FAIL,
            medium=PolicyAction.WARN,
            low=PolicyAction.INFO,
            info=PolicyAction.INFO,
            unknown=PolicyAction.WARN
        )


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Gate - Evaluate findings against policy")
    parser.add_argument("--input", default="reports/normalized-findings.json", help="Normalized findings input")
    parser.add_argument("--output", default="reports/security-gate-result.json", help="Gate result output")
    parser.add_argument("--policy", choices=["strict", "educational"], default="strict", help="Policy mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--fail-on-missing", action="store_true", help="Fail if input report missing")
    
    args = parser.parse_args()
    
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
                summary={"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Unknown": 0, "Total": 0},
                findings_by_severity={},
                policy_violations=[],
                execution_metadata={
                    "evaluated_at": datetime.utcnow().isoformat() + "Z",
                    "note": "No findings report available"
                }
            )
            save_gate_result(result, args.output)
            sys.exit(0)
    
    # Load findings
    try:
        findings = load_normalized_findings(args.input)
        print(f"Loaded {len(findings)} normalized findings")
    except Exception as e:
        print(f"ERROR loading findings: {e}")
        sys.exit(1)
    
    # Create policy
    educational = args.policy == "educational"
    policy = create_default_policy(educational_baseline=educational)
    print(f"Using policy mode: {'educational-baseline' if educational else 'strict'}")
    
    # Evaluate
    result = evaluate_policy(findings, policy)
    
    # Print summary
    print_summary(result, verbose=args.verbose)
    
    # Save result
    save_gate_result(result, args.output)
    
    # Exit with appropriate code
    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()