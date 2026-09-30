#!/usr/bin/env python3
"""
DevSecOps Pipeline - ZAP Baseline Scan with Application Lifecycle Management
Starts the Flask application, waits for readiness, runs ZAP baseline scan, and cleans up.
"""

import os
import sys
import time
import signal
import subprocess
import argparse
import requests
from pathlib import Path
from typing import Optional, Tuple


class ApplicationManager:
    """Manages the Flask application lifecycle for DAST scanning."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        app_path: str = "app/app.py",
        secure_mode: bool = False,
        startup_timeout: int = 30,
        health_interval: int = 2,
    ):
        self.host = host
        self.port = port
        self.app_path = Path(app_path).resolve()
        self.secure_mode = secure_mode
        self.startup_timeout = startup_timeout
        self.health_interval = health_interval
        self.base_url = f"http://{host}:{port}"
        self.health_url = f"{self.base_url}/health"
        self.process: Optional[subprocess.Popen] = None
        self._start_time: float = 0

    def start(self) -> Tuple[bool, str]:
        """Start the Flask application and wait for readiness."""
        if self.process is not None:
            return False, "Application already running"

        # Check if app path exists
        if not self.app_path.exists():
            return False, f"Application not found at {self.app_path}"

        app_path_str = os.path.relpath(self.app_path, os.getcwd())
        print(f"Starting Flask application at {app_path_str}...")
        print(f"  Host: {self.host}")
        print(f"  Port: {self.port}")
        print(f"  Secure mode: {self.secure_mode}")
        print(f"  Health endpoint: {self.health_url}")

        # Prepare environment
        env = os.environ.copy()
        env["SECURE_MODE"] = "true" if self.secure_mode else "false"
        env["HOST"] = self.host
        env["PORT"] = str(self.port)
        env["PYTHONUNBUFFERED"] = "1"

        # Start the application
        try:
            self.process = subprocess.Popen(
                [sys.executable, str(self.app_path)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            return False, f"Failed to start application: {e}"

        self._start_time = time.time()

        # Wait for readiness
        success, message = self._wait_for_ready()
        if not success:
            self.stop()
            return False, message

        elapsed = time.time() - self._start_time
        print(f"Application ready in {elapsed:.1f}s at {self.base_url}")
        return True, "Application started successfully"

    def _wait_for_ready(self) -> Tuple[bool, str]:
        """Wait for the health endpoint to return 200 OK."""
        elapsed = 0
        start = time.time()

        print(f"Waiting for health endpoint at {self.health_url} (max {self.startup_timeout}s)...")

        while elapsed < self.startup_timeout:
            if self._check_health():
                return True, "Health check passed"

            time.sleep(self.health_interval)
            elapsed = time.time() - start

            if elapsed < self.startup_timeout:
                print(f"  Still waiting... ({elapsed:.1f}s elapsed)")

        # If we get here, startup timed out
        error_msg = f"Application failed to become ready within {self.startup_timeout}s"
        return False, error_msg

    def _check_health(self) -> bool:
        """Check if the health endpoint returns 200 OK."""
        try:
            response = requests.get(self.health_url, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def stop(self) -> Tuple[bool, str]:
        """Stop the Flask application gracefully."""
        if self.process is None:
            return True, "No application running"

        print("Stopping Flask application...")
        try:
            # Try graceful shutdown first
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
                print("Application stopped gracefully")
                return True, "Application stopped"
            except subprocess.TimeoutExpired:
                # Force kill if graceful shutdown fails
                print("Graceful shutdown timed out, forcing kill...")
                self.process.kill()
                self.process.wait(timeout=5)
                print("Application force killed")
                return True, "Application force killed"
        except Exception as e:
            return False, f"Error stopping application: {e}"
        finally:
            self.process = None

    def get_logs(self) -> str:
        """Get application output logs."""
        if self.process and self.process.stdout:
            try:
                return self.process.stdout.read()
            except Exception:
                pass
        return ""


def run_zap_scan(
    target_url: str,
    report_path: str,
    zap_rules_dir: str,
    timeout: int = 600,
) -> Tuple[bool, int, str, str]:
    """
    Run ZAP baseline scan against the target URL.
    
    Returns: (success, exit_code, stdout, stderr)
    """
    # Ensure report directory exists
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)

    # Build the ZAP command with rules if available
    cmd = [
        "docker", "run", "--rm", "--network", "host",
        "-v", f"{os.path.abspath(zap_rules_dir)}:/home/zap/.zap:rw",
        "owasp/zap2docker-stable",
        "zap-baseline.py", "-t", target_url, "-r", report_path
    ]

    print(f"Running ZAP baseline scan against {target_url}...")
    print(f"  Report will be saved to: {report_path}")
    print(f"  Timeout: {timeout}s")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
        )
        return result.returncode in (0, 1), result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, -1, "", f"ZAP scan timed out after {timeout}s"
    except FileNotFoundError:
        return False, -1, "", "Docker not found. Please install Docker to run ZAP scan."
    except Exception as e:
        return False, -1, "", f"Error running ZAP scan: {e}"


def main():
    parser = argparse.ArgumentParser(description="Run ZAP baseline scan with application lifecycle management")
    parser.add_argument("--reports-dir", default="reports", help="Reports output directory")
    parser.add_argument("--app-host", default="127.0.0.1", help="Flask application host (default: 127.0.0.1)")
    parser.add_argument("--app-port", type=int, default=5000, help="Flask application port (default: 5000)")
    parser.add_argument("--app-path", default="app/app.py", help="Path to Flask application (default: app/app.py)")
    parser.add_argument("--secure-mode", action="store_true", help="Run application in secure mode")
    parser.add_argument("--startup-timeout", type=int, default=30, help="Application startup timeout in seconds (default: 30)")
    parser.add_argument("--health-interval", type=int, default=2, help="Health check interval in seconds (default: 2)")
    parser.add_argument("--zap-timeout", type=int, default=600, help="ZAP scan timeout in seconds (default: 600)")
    parser.add_argument("--zap-rules-dir", default=".zap", help="ZAP rules directory (default: .zap)")
    parser.add_argument("--report-name", default="zap-report.json", help="ZAP report filename (default: zap-report.json)")
    parser.add_argument("--skip-app-start", action="store_true", help="Skip application startup (assume app is already running)")
    parser.add_argument("--target-url", help="Target URL for ZAP scan (default: http://<app-host>:<app-port>)")

    args = parser.parse_args()

    # Determine target URL
    target_url = args.target_url or f"http://{args.app_host}:{args.app_port}"
    report_path = os.path.join(args.reports_dir, args.report_name)
    zap_rules_dir = Path(args.zap_rules_dir).resolve()

    # Ensure reports directory exists
    os.makedirs(args.reports_dir, exist_ok=True)

    print("=" * 60)
    print("ZAP Baseline Scan with Application Lifecycle")
    print("=" * 60)
    print(f"Target URL: {target_url}")
    print(f"Report: {os.path.basename(report_path)}")
    print(f"ZAP Rules Dir: {args.zap_rules_dir}")
    print(f"Secure Mode: {args.secure_mode}")
    print()

    app_manager = ApplicationManager(
        host=args.app_host,
        port=args.app_port,
        app_path=args.app_path,
        secure_mode=args.secure_mode,
        startup_timeout=args.startup_timeout,
        health_interval=args.health_interval,
    )

    try:
        # Start application if not skipped
        if not args.skip_app_start:
            success, message = app_manager.start()
            if not success:
                print(f"ERROR: Failed to start application: {message}")
                # Print any captured logs
                logs = app_manager.get_logs()
                if logs:
                    print("Application logs:")
                    print(logs[-2000:] if len(logs) > 2000 else logs)
                sys.exit(1)

            # Verify health endpoint one more time
            if not app_manager._check_health():
                print("ERROR: Health check failed after startup")
                app_manager.stop()
                sys.exit(1)

        else:
            # Just verify the target is reachable
            print(f"Skipping application startup, assuming app is running at {target_url}")
            try:
                response = requests.get(f"{target_url}/health", timeout=5)
                if response.status_code != 200:
                    print(f"ERROR: Target application not healthy at {target_url}/health")
                    sys.exit(1)
            except requests.RequestException as e:
                print(f"ERROR: Cannot reach target application at {target_url}: {e}")
                sys.exit(1)

        # Run ZAP scan
        print()
        print("-" * 60)
        print("Starting ZAP Baseline Scan")
        print("-" * 60)

        scan_success, exit_code, stdout, stderr = run_zap_scan(
            target_url=target_url,
            report_path=report_path,
            zap_rules_dir=str(zap_rules_dir),
            timeout=args.zap_timeout,
        )

        print()
        print("ZAP Scan Output:")
        print(stdout)
        if stderr:
            print("ZAP Scan Errors:")
            print(stderr)

        # Check if report was generated
        report_exists = os.path.exists(report_path)
        if report_exists:
            try:
                with open(report_path, 'r') as f:
                    import json
                    data = json.load(f)
                    site_count = len(data.get("site", []))
                    alert_count = sum(len(s.get("alerts", [])) for s in data.get("site", []))
                    print(f"\nReport generated successfully: {report_path}")
                    print(f"  Sites scanned: {site_count}")
                    print(f"  Total alerts: {alert_count}")
            except Exception as e:
                print(f"Warning: Could not parse report: {e}")

        # Determine overall success
        # ZAP returns: 0 = success, 1 = warnings/findings, 2 = errors
        if exit_code in (0, 1):
            overall_success = True
        else:
            overall_success = False

        return overall_success, exit_code, report_exists

    finally:
        # Always stop the application if we started it
        if not args.skip_app_start:
            print()
            print("Stopping application...")
            app_manager.stop()


if __name__ == "__main__":
    import os
    main()