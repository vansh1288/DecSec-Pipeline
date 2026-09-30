#!/usr/bin/env python3
"""
DevSecOps Pipeline - Scanner Execution Script
Runs all configured security scanners and produces raw reports.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScannerResult:
    """Result of a scanner execution."""
    name: str
    success: bool
    exit_code: int
    report_path: str
    error_message: Optional[str] = None
    execution_time: float = 0.0
    findings_count: int = 0


def check_command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(cmd) is not None


def run_command(cmd: list[str], timeout: int = 300, cwd: Optional[str] = None) -> tuple[int, str, str]:
    """Run a command and return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            cwd=cwd
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout} seconds"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", f"Error running command: {e}"


def run_bandit(reports_dir: str) -> ScannerResult:
    """Run Bandit Python SAST scanner."""
    report_path = os.path.join(reports_dir, "bandit-report.json")
    cmd = ["bandit", "-r", "app/", "-f", "json", "-o", report_path]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd)
    execution_time = time.time() - start

    if exit_code in (0, 1):  # Bandit returns 1 when findings exist
        success = True
        # Count findings
        findings = 0
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                    findings = len(data.get("results", []))
            except Exception:
                pass
        return ScannerResult(
            name="bandit",
            success=success,
            exit_code=exit_code,
            report_path=report_path,
            execution_time=execution_time,
            findings_count=findings
        )
    else:
        return ScannerResult(
            name="bandit",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"Bandit failed: {stderr}",
            execution_time=execution_time
        )


def run_semgrep(reports_dir: str) -> ScannerResult:
    """Run Semgrep SAST scanner."""
    report_path = os.path.join(reports_dir, "semgrep-report.json")
    cmd = ["semgrep", "scan", "--config=auto", "--json", "-o", report_path, "."]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=600)
    execution_time = time.time() - start

    if exit_code in (0, 1):  # Semgrep returns 1 when findings exist
        success = True
        findings = 0
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                    findings = len(data.get("results", []))
            except Exception:
                pass
        return ScannerResult(
            name="semgrep",
            success=success,
            exit_code=exit_code,
            report_path=report_path,
            execution_time=execution_time,
            findings_count=findings
        )
    else:
        return ScannerResult(
            name="semgrep",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"Semgrep failed: {stderr}",
            execution_time=execution_time
        )


def run_pip_audit(reports_dir: str) -> ScannerResult:
    """Run pip-audit Python dependency scanner."""
    report_path = os.path.join(reports_dir, "pip-audit-report.json")
    # Use JSON output to stdout and redirect
    cmd = ["pip-audit", "-f", "json"]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=300)
    execution_time = time.time() - start

    # pip-audit 1.x outputs JSON list of packages to stdout
    # pip-audit 2.x outputs dict with dependencies/fixes keys
    # We need to transform to the format expected by normalize_pip_audit:
    # either a list of vulnerabilities OR a dict with "vulnerabilities" key

    if exit_code in (0, 1):  # pip-audit returns 1 when vulnerabilities found
        try:
            data = json.loads(stdout) if stdout.strip() else []

            # Transform to expected format
            if isinstance(data, list):
                # pip-audit 1.x format: list of packages with "vulns" arrays
                vulnerabilities = []
                for pkg in data:
                    pkg_name = pkg.get("name", "unknown")
                    pkg_version = pkg.get("version", "unknown")
                    for vuln in pkg.get("vulns", []):
                        # Transform to expected vulnerability format
                        # Preserve all available fields from the scanner output
                        transformed = {
                            "id": vuln.get("id", "unknown"),
                            "package": f"{pkg_name}=={pkg_version}",
                        }
                        # Only add fields that are actually present in the scanner output
                        if "severity" in vuln:
                            transformed["severity"] = vuln["severity"]
                        if "fix_versions" in vuln:
                            transformed["fix_versions"] = vuln["fix_versions"]
                        if "aliases" in vuln:
                            transformed["aliases"] = vuln["aliases"]
                        if "references" in vuln:
                            transformed["references"] = vuln["references"]
                        if "description" in vuln:
                            transformed["description"] = vuln["description"]
                        vulnerabilities.append(transformed)

                # Write transformed output
                with open(report_path, "w") as f:
                    json.dump({"vulnerabilities": vulnerabilities}, f, indent=2)

                findings = len(vulnerabilities)
                return ScannerResult(
                    name="pip-audit",
                    success=True,
                    exit_code=exit_code,
                    report_path=report_path,
                    execution_time=execution_time,
                    findings_count=findings
                )
            elif isinstance(data, dict) and "vulnerabilities" in data:
                # Already in expected format (cyclonedx-json or newer)
                with open(report_path, "w") as f:
                    json.dump(data, f, indent=2)
                findings = len(data.get("vulnerabilities", []))
                return ScannerResult(
                    name="pip-audit",
                    success=True,
                    exit_code=exit_code,
                    report_path=report_path,
                    execution_time=execution_time,
                    findings_count=findings
                )
            elif isinstance(data, dict) and "dependencies" in data:
                # pip-audit 2.x format - transform
                vulnerabilities = []
                for dep in data.get("dependencies", []):
                    pkg_name = dep.get("name", "unknown")
                    pkg_version = dep.get("version", "unknown")
                    for vuln in dep.get("vulnerabilities", []):
                        transformed = {
                            "id": vuln.get("id", "unknown"),
                            "package": f"{pkg_name}=={pkg_version}",
                        }
                        # Only add fields that are actually present
                        if "severity" in vuln:
                            transformed["severity"] = vuln["severity"]
                        if "fix_versions" in vuln:
                            transformed["fix_versions"] = vuln["fix_versions"]
                        if "aliases" in vuln:
                            transformed["aliases"] = vuln["aliases"]
                        if "references" in vuln:
                            transformed["references"] = vuln["references"]
                        if "description" in vuln:
                            transformed["description"] = vuln["description"]
                        vulnerabilities.append(transformed)

                with open(report_path, "w") as f:
                    json.dump({"vulnerabilities": vulnerabilities}, f, indent=2)

                findings = len(vulnerabilities)
                return ScannerResult(
                    name="pip-audit",
                    success=True,
                    exit_code=exit_code,
                    report_path=report_path,
                    execution_time=execution_time,
                    findings_count=findings
                )
            else:
                return ScannerResult(
                    name="pip-audit",
                    success=False,
                    exit_code=-1,
                    report_path=report_path,
                    error_message=f"Unexpected pip-audit output format",
                    execution_time=execution_time
                )
        except json.JSONDecodeError as e:
            return ScannerResult(
                name="pip-audit",
                success=False,
                exit_code=-1,
                report_path=report_path,
                error_message=f"Failed to parse pip-audit output: {e}",
                execution_time=execution_time
            )
    else:
        return ScannerResult(
            name="pip-audit",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"pip-audit failed (exit {exit_code}): {stderr}",
            execution_time=execution_time
        )


def run_gitleaks(reports_dir: str) -> ScannerResult:
    """Run Gitleaks secret scanner."""
    report_path = os.path.join(reports_dir, "gitleaks-report.json")
    cmd = ["gitleaks", "detect", "--source", ".", "--report-format", "json", "--report-path", report_path]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=300)
    execution_time = time.time() - start

    if exit_code in (0, 1):  # Gitleaks returns 1 when leaks found
        success = True
        findings = 0
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                    findings = len(data) if isinstance(data, list) else len(data.get("leaks", []))
            except Exception:
                pass
        return ScannerResult(
            name="gitleaks",
            success=success,
            exit_code=exit_code,
            report_path=report_path,
            execution_time=execution_time,
            findings_count=findings
        )
    else:
        return ScannerResult(
            name="gitleaks",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"Gitleaks failed (exit {exit_code}): {stderr}",
            execution_time=execution_time
        )


def run_osv_scanner(reports_dir: str) -> ScannerResult:
    """Run OSV-Scanner for dependency vulnerabilities."""
    report_path = os.path.join(reports_dir, "osv-scanner-report.json")
    # Use --output-file (--output is deprecated) and scan requirements.txt explicitly
    cmd = ["osv-scanner", "scan", "--format=json", "--output-file", report_path, "app/requirements.txt"]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=300)
    execution_time = time.time() - start

    if exit_code in (0, 1):  # OSV-Scanner returns 1 when vulnerabilities found
        success = True
        findings = 0
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                    # Count vulnerabilities
                    for result in data.get("results", []):
                        for pkg in result.get("packages", []):
                            findings += len(pkg.get("vulnerabilities", []))
            except Exception:
                pass
        return ScannerResult(
            name="osv-scanner",
            success=success,
            exit_code=exit_code,
            report_path=report_path,
            execution_time=execution_time,
            findings_count=findings
        )
    else:
        return ScannerResult(
            name="osv-scanner",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"OSV-Scanner failed (exit {exit_code}): {stderr}",
            execution_time=execution_time
        )


def run_trivy_image(reports_dir: str, image_name: str = "devsecops-pipeline:1.0.0-vulnerable") -> ScannerResult:
    """Run Trivy image vulnerability scanner.
    
    Note: This runs 'trivy image' on the built Docker image.
    Configuration scanning is handled separately by run_trivy().
    """
    report_path = os.path.join(reports_dir, "trivy-image-report.json")
    cmd = ["trivy", "image", "--format", "json", "--output-file", report_path, image_name]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=300)
    execution_time = time.time() - start

    if exit_code in (0, 1):  # Trivy returns 1 when vulnerabilities found
        success = True
        findings = 0
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                    for result in data.get("Results", []):
                        findings += len(result.get("Vulnerabilities", []))
            except Exception:
                pass
        return ScannerResult(
            name="trivy",
            success=success,
            exit_code=exit_code,
            report_path=report_path,
            execution_time=execution_time,
            findings_count=findings
        )
    else:
        return ScannerResult(
            name="trivy",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"Trivy image scan failed (exit {exit_code}): {stderr}",
            execution_time=execution_time
        )


def run_trivy(reports_dir: str) -> ScannerResult:
    """Run Trivy configuration scanner (Dockerfile misconfigurations).
    
    Note: This runs 'trivy config' on the app/ directory.
    Image vulnerability scanning requires a built Docker image and is handled separately in P0-4.
    """
    report_path = os.path.join(reports_dir, "trivy-report.json")
    # Use --output-file (--output is deprecated in Trivy 0.50+)
    cmd = ["trivy", "config", "--format", "json", "--output-file", report_path, "app/"]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=300)
    execution_time = time.time() - start

    if exit_code in (0, 1):  # Trivy returns 1 when findings exist
        success = True
        findings = 0
        scan_type = "config"
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                    for result in data.get("Results", []):
                        findings += len(result.get("Misconfigurations", []))
                        # Check if vulnerability scan also ran (trivy image)
                        if result.get("Vulnerabilities"):
                            scan_type = "config+vuln"
            except Exception:
                pass
        return ScannerResult(
            name="trivy",
            success=success,
            exit_code=exit_code,
            report_path=report_path,
            execution_time=execution_time,
            findings_count=findings,
            error_message=None if success else f"Trivy {scan_type} scan failed: {stderr}"
        )
    else:
        return ScannerResult(
            name="trivy",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"Trivy config scan failed (exit {exit_code}): {stderr}",
            execution_time=execution_time
        )


def run_trivy_image(reports_dir: str, image_name: str = "devsecops-pipeline:1.0.0-vulnerable") -> ScannerResult:
    """Run Trivy image vulnerability scanner.
    
    Note: This runs 'trivy image' on the built Docker image.
    Configuration scanning is handled separately by run_trivy().
    """
    report_path = os.path.join(reports_dir, "trivy-image-report.json")
    cmd = ["trivy", "image", "--format", "json", "--output-file", report_path, image_name]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=300)
    execution_time = time.time() - start

    if exit_code in (0, 1):  # Trivy returns 1 when vulnerabilities found
        success = True
        findings = 0
        if os.path.exists(report_path):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                    for result in data.get("Results", []):
                        findings += len(result.get("Vulnerabilities", []))
            except Exception:
                pass
        return ScannerResult(
            name="trivy",
            success=success,
            exit_code=exit_code,
            report_path=report_path,
            execution_time=execution_time,
            findings_count=findings
        )
    else:
        return ScannerResult(
            name="trivy",
            success=False,
            exit_code=exit_code,
            report_path=report_path,
            error_message=f"Trivy image scan failed (exit {exit_code}): {stderr}",
            execution_time=execution_time
        )


def build_docker_image(image_name: str = "devsecops-pipeline:1.0.0-vulnerable") -> tuple[bool, str, str]:
    """Build the Docker image from the app/Dockerfile.
    
    Returns: (success, stdout, stderr)
    """
    # Build context is the app/ directory (where Dockerfile is located)
    cmd = ["docker", "build", "-t", image_name, "-f", "app/Dockerfile", "app/"]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=600)
    execution_time = time.time() - start
    
    if exit_code == 0:
        return True, stdout, stderr
    else:
        return False, stdout, stderr


def run_zap(reports_dir: str, target_url: str = "http://localhost:5000") -> ScannerResult:
    """Run OWASP ZAP DAST scanner with application lifecycle management."""
    report_path = os.path.join(reports_dir, "zap-report.json")
    zap_rules_dir = os.path.abspath(".zap")

    # Import and run the ZAP scan with application lifecycle management
    # We delegate to the dedicated ZAP scan script which handles app lifecycle
    cmd = [
        sys.executable, "scripts/run_zap_scan.py",
        "--reports-dir", reports_dir,
        "--target-url", target_url,
        "--zap-rules-dir", zap_rules_dir,
        "--report-name", "zap-report.json",
    ]
    start = time.time()
    exit_code, stdout, stderr = run_command(cmd, timeout=720)  # 12 min timeout for app startup + scan
    execution_time = time.time() - start

    # Check if report was generated
    findings = 0
    report_generated = os.path.exists(os.path.join(reports_dir, "zap-report.json"))

    if exit_code == 0 and report_generated:
        # Success - scan completed (0 = no warnings, 1 = warnings/findings)
        success = True
        if report_generated:
            try:
                report_path = os.path.join(reports_dir, "zap-report.json")
                with open(report_path) as f:
                    data = json.load(f)
                    for site in data.get("site", []):
                        findings += len(site.get("alerts", []))
            except Exception:
                pass
        return ScannerResult(
            name="zap",
            success=success,
            exit_code=exit_code,
            report_path=os.path.join(reports_dir, "zap-report.json"),
            execution_time=execution_time,
            findings_count=findings
        )
    elif exit_code == 1 and report_generated:
        # ZAP returns 1 when there are findings/warnings but scan completed
        success = True
        if report_generated:
            try:
                report_path = os.path.join(reports_dir, "zap-report.json")
                with open(report_path) as f:
                    data = json.load(f)
                    for site in data.get("site", []):
                        findings += len(site.get("alerts", []))
            except Exception:
                pass
        return ScannerResult(
            name="zap",
            success=success,
            exit_code=exit_code,
            report_path=os.path.join(reports_dir, "zap-report.json"),
            execution_time=execution_time,
            findings_count=findings
        )
    else:
        # Failed - scan error or report not generated
        error_msg = f"ZAP failed (exit {exit_code})"
        if not report_generated:
            error_msg += ": report not generated"
        if stderr:
            error_msg += f": {stderr[:500]}"
        return ScannerResult(
            name="zap",
            success=False,
            exit_code=exit_code,
            report_path=os.path.join(reports_dir, "zap-report.json"),
            error_message=error_msg,
            execution_time=execution_time
        )


SCANNERS = {
    "gitleaks": run_gitleaks,
    "semgrep": run_semgrep,
    "bandit": run_bandit,
    "osv-scanner": run_osv_scanner,
    "pip-audit": run_pip_audit,
    "trivy": run_trivy,
    "trivy-image": run_trivy_image,
    "zap": run_zap,
}

REQUIRED_SCANNERS = [
    "gitleaks", "semgrep", "bandit", "osv-scanner",
    "pip-audit", "trivy", "trivy-image", "zap"
]


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run security scanners")
    parser.add_argument("--reports-dir", default="reports", help="Reports output directory")
    parser.add_argument("--zap-target", default="http://localhost:5000", help="Target URL for ZAP scan")
    parser.add_argument("--scanners", nargs="+", choices=list(SCANNERS.keys()), help="Specific scanners to run (default: all)")
    parser.add_argument("--skip-missing", action="store_true", help="Skip scanners that are not installed instead of failing")
    
    args = parser.parse_args()

    os.makedirs(args.reports_dir, exist_ok=True)

    scanners_to_run = args.scanners if args.scanners else REQUIRED_SCANNERS

    print(f"Running {len(scanners_to_run)} scanners...")
    print(f"Reports directory: {args.reports_dir}")
    print()

    results = []
    all_success = True

    for scanner_name in scanners_to_run:
        if scanner_name not in SCANNERS:
            print(f"  [SKIP] {scanner_name}: Unknown scanner")
            continue

        if scanner_name in ("zap", "trivy-image") and not check_command_exists("docker"):
            msg = f"Docker not available, required for {scanner_name}"
            if args.skip_missing:
                print(f"  [SKIP] {scanner_name}: {msg}")
                results.append(ScannerResult(
                    name=scanner_name,
                    success=False,
                    exit_code=-1,
                    report_path=os.path.join(args.reports_dir, f"{scanner_name}-report.json"),
                    error_message=msg,
                    execution_time=0
                ))
                continue
            else:
                print(f"  [FAIL] {scanner_name}: {msg}")
                results.append(ScannerResult(
                    name=scanner_name,
                    success=False,
                    exit_code=-1,
                    report_path=os.path.join(args.reports_dir, f"{scanner_name}-report.json"),
                    error_message=msg,
                    execution_time=0
                ))
                all_success = False
                continue

        if scanner_name not in ("trivy", "trivy-image", "zap") and not check_command_exists(scanner_name):
            msg = f"Scanner not installed: {scanner_name}"
            if args.skip_missing:
                print(f"  [SKIP] {scanner_name}: {msg}")
                results.append(ScannerResult(
                    name=scanner_name,
                    success=False,
                    exit_code=-1,
                    report_path=os.path.join(args.reports_dir, f"{scanner_name}-report.json"),
                    error_message=msg,
                    execution_time=0
                ))
                continue
            else:
                print(f"  [FAIL] {scanner_name}: {msg}")
                results.append(ScannerResult(
                    name=scanner_name,
                    success=False,
                    exit_code=-1,
                    report_path=os.path.join(args.reports_dir, f"{scanner_name}-report.json"),
                    error_message=msg,
                    execution_time=0
                ))
                all_success = False
                continue

        print(f"  [RUN] {scanner_name}...")
        scanner_func = SCANNERS[scanner_name]
        
        try:
            # Build Docker image before running trivy-image scan
            if scanner_name == "trivy-image":
                print("  [BUILD] Building Docker image...")
                build_success, build_stdout, build_stderr = build_docker_image("devsecops-pipeline:1.0.0-vulnerable")
                if not build_success:
                    result = ScannerResult(
                        name="trivy-image",
                        success=False,
                        exit_code=-1,
                        report_path=os.path.join(args.reports_dir, "trivy-image-report.json"),
                        error_message=f"Docker build failed: {build_stderr}",
                        execution_time=0
                    )
                    results.append(result)
                    all_success = False
                    print(f"  [FAIL] trivy-image: Docker build failed")
                    continue
            
            if scanner_name == "zap":
                result = scanner_func(args.reports_dir, args.zap_target)
            elif scanner_name == "trivy-image":
                result = scanner_func(args.reports_dir, "devsecops-pipeline:1.0.0-vulnerable")
            else:
                result = scanner_func(args.reports_dir)
        except Exception as e:
            result = ScannerResult(
                name=scanner_name,
                success=False,
                exit_code=-1,
                report_path=os.path.join(args.reports_dir, f"{scanner_name}-report.json"),
                error_message=f"Unexpected error: {e}",
                execution_time=0
            )

        results.append(result)

        if result.success:
            print(f"  [OK] {scanner_name}: {result.findings_count} findings in {result.execution_time:.1f}s")
        else:
            print(f"  [FAIL] {scanner_name}: {result.error_message}")
            all_success = False

    print()
    print("=" * 60)
    print("SCANNER EXECUTION SUMMARY")
    print("=" * 60)
    for r in results:
        status = "OK" if r.success else "FAIL"
        findings = f" ({r.findings_count} findings)" if r.success else ""
        print(f"  {status:4} {r.name:12} {r.execution_time:6.1f}s{findings}")
        if not r.success and r.error_message:
            print(f"       Error: {r.error_message}")

    # Summary
    ok_count = sum(1 for r in results if r.success)
    fail_count = sum(1 for r in results if not r.success)
    print()
    print(f"Total: {ok_count} passed, {fail_count} failed")

    if not all_success and not args.skip_missing:
        sys.exit(1)


if __name__ == "__main__":
    main()