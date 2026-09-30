# DevSecOps Security Pipeline

A CI/CD security pipeline that integrates automated **SAST, SCA, secrets scanning, IaC scanning, container vulnerability scanning, DAST, security-policy enforcement, and centralized vulnerability reporting** into GitHub Actions.

The project uses an intentionally vulnerable Flask API as a controlled security-testing target. The pipeline identifies security weaknesses before code can be merged and applies a configurable severity-based security gate.

> **Project status:** Core pipeline logic implemented and locally validated. Full end-to-end execution of Docker-dependent scanners and GitHub Actions remains to be verified on an Ubuntu runner.

---

## Overview

Modern applications depend on source code, third-party libraries, containers, and infrastructure configurations. A vulnerability introduced at any of these layers can become a production security issue.

This project demonstrates a **shift-left security model** by integrating security testing directly into the CI/CD workflow.

```text
Developer
    │
    ▼
Git Commit / Pull Request
    │
    ▼
GitHub Actions
    │
    ├── Unit Tests
    │
    ├── Secrets Scanning
    │      └── Gitleaks
    │
    ├── SAST
    │      ├── Bandit
    │      └── Semgrep
    │
    ├── Dependency Scanning
    │      ├── pip-audit
    │      └── OSV-Scanner
    │
    ├── IaC / Configuration Scanning
    │      └── Trivy
    │
    ├── Docker Build
    │
    ├── Container Image Scanning
    │      └── Trivy
    │
    ├── Dynamic Application Security Testing
    │      └── OWASP ZAP
    │
    ▼
Report Normalization
    │
    ▼
Security Policy Engine
    │
    ├── Critical → FAIL
    ├── High     → FAIL
    ├── Medium   → WARN
    ├── Low      → INFO
    └── Unknown  → REVIEW
    │
    ▼
Security Report + CI Gate
```

---

# Key Features

* Automated security checks on pull requests and pushes to `main`
* Secrets detection using Gitleaks
* Python SAST using Bandit and Semgrep
* Dependency vulnerability detection using pip-audit and OSV-Scanner
* Dockerfile/IaC scanning using Trivy
* Docker image vulnerability scanning using Trivy
* Dynamic API security testing using OWASP ZAP
* Centralized finding normalization
* Severity-based security policy enforcement
* Configurable ZAP alert handling
* JSON, Markdown and HTML security reports
* GitHub Actions artifact retention
* Automated application health checks
* Controlled intentionally vulnerable application for security testing
* Unit and security-gate tests
* Missing-report detection to prevent false pipeline success

---

# Security Toolchain

| Tool                  | Security Function                    | Output             |
| --------------------- | ------------------------------------ | ------------------ |
| Gitleaks              | Secrets scanning                     | JSON               |
| Bandit                | Python SAST                          | JSON               |
| Semgrep               | SAST                                 | JSON               |
| pip-audit             | Python dependency scanning           | JSON               |
| OSV-Scanner           | Dependency vulnerability scanning    | JSON               |
| Trivy                 | IaC/configuration scanning           | JSON               |
| Trivy                 | Container image scanning             | JSON               |
| OWASP ZAP             | DAST                                 | JSON/HTML          |
| Custom Python scripts | Normalization and policy enforcement | JSON/Markdown/HTML |

---

# Pipeline Stages

## 1. Unit Testing

The pipeline first executes the application's automated tests.

The tests verify:

* API endpoints
* Health checks
* Authentication behavior
* Input handling
* Invalid requests
* Error handling
* Expected security-test behavior

If application tests fail, the security pipeline should not proceed.

---

## 2. Secrets Scanning

### Tool: Gitleaks

Gitleaks searches the repository for accidentally committed credentials and sensitive material.

Examples of detected secret categories include:

* API keys
* Authentication tokens
* Private keys
* Password-like values
* Cloud credentials
* Other credential patterns

The project uses only **dummy educational credentials**. No real secrets should ever be committed.

The pipeline is designed to fail if an actual secret is detected.

---

## 3. Static Application Security Testing

### Tools

* Bandit
* Semgrep

SAST analyzes the application source code without executing the application.

The pipeline can identify patterns such as:

* Unsafe subprocess usage
* Potential command injection
* Insecure Python APIs
* Unsafe input handling
* Hardcoded sensitive values
* Other security-oriented coding patterns

Example Bandit output from local validation:

```text
93 findings
```

These findings represent scanner output from the intentionally vulnerable application and should be reviewed rather than blindly suppressed.

---

# 4. Software Composition Analysis

### Tools

* pip-audit
* OSV-Scanner

SCA analyzes third-party dependencies rather than the application's own source code.

The pipeline checks:

```text
requirements.txt
       │
       ▼
Dependency Resolution
       │
       ▼
Vulnerability Database
       │
       ▼
Known Advisories / CVEs
       │
       ▼
Security Report
```

The project intentionally supports testing against vulnerable dependency versions so that the SCA stage can demonstrate vulnerability detection and remediation.

Dependency versions should be updated to fixed releases during the remediation phase.

---

# 5. Infrastructure / Configuration Scanning

### Tool: Trivy

Trivy is used to inspect project configuration for security issues.

The pipeline produces:

```text
reports/trivy-report.json
```

This stage helps identify insecure configuration before deployment.

---

# 6. Docker Image Build

The application is packaged as a Docker image.

Example image:

```text
devsecops-pipeline:1.0.0-vulnerable
```

The image is built before container scanning.

The Docker configuration follows basic container-security practices including:

* Minimal base image where practical
* Pinned application dependencies
* Non-root application execution
* `.dockerignore`
* No real credentials inside the image
* Predictable application startup

---

# 7. Container Vulnerability Scanning

### Tool: Trivy

After building the image, Trivy scans the image for vulnerabilities.

The scan covers applicable:

* Operating-system packages
* Application dependencies
* Known vulnerabilities
* Container configuration issues

Report:

```text
reports/trivy-image-report.json
```

The image scan is intentionally performed before the application is used for DAST.

---

# 8. Dynamic Application Security Testing

### Tool: OWASP ZAP

The pipeline starts the Dockerized Flask application locally on the GitHub Actions runner.

The workflow performs:

```text
Build Image
    │
    ▼
Start Container
    │
    ▼
Health Check
    │
    ▼
Application Available
    │
    ▼
OWASP ZAP Baseline Scan
    │
    ▼
ZAP Report
    │
    ▼
Container Cleanup
```

ZAP tests the running HTTP application for applicable security issues such as:

* Missing security headers
* Information disclosure
* HTTP configuration problems
* Potential injection entry points
* Other passive security findings

The application is scanned locally and is not intended to be exposed as a public vulnerable service.

---

# 9. ZAP Rule Management

Configuration:

```text
.zap/rules.tsv
```

The project uses a controlled TSV policy to manage ZAP findings.

Example structure:

```text
alert_id    action      severity    justification
10020       WARN        Medium      Review CSP configuration
10021       FAIL        High        Security-sensitive finding
```

The custom normalization layer applies these policies to ZAP findings.

Suppressions must be:

* Explicit
* Narrowly scoped
* Justified
* Reviewable

The project does not use blanket suppression to make the pipeline pass.

---

# 10. Finding Normalization

Different security tools produce different JSON formats.

For example:

```text
Bandit
Semgrep
pip-audit
OSV-Scanner
Gitleaks
Trivy
ZAP
   │
   ▼
Different Finding Formats
   │
   ▼
normalize_reports.py
   │
   ▼
Common Finding Schema
   │
   ▼
security_gate.py
```

The normalization layer allows findings from different scanners to be evaluated consistently.

Current normalization support includes:

* Bandit
* Semgrep
* pip-audit
* OSV-Scanner
* Gitleaks
* Trivy configuration findings
* Trivy image findings
* OWASP ZAP

Trivy configuration and image reports are handled separately according to their finding types while sharing the Trivy normalization implementation.

---

# 11. Security Policy Engine

The central policy engine is:

```text
scripts/security_gate.py
```

The default policy is:

| Severity | Policy        |
| -------- | ------------- |
| Critical | FAIL          |
| High     | FAIL          |
| Medium   | WARN          |
| Low      | INFO          |
| Unknown  | Manual Review |

The gate also verifies that mandatory reports exist.

This is important because a scanner failure should not silently become a successful security result.

For example:

```text
Required Scanner
      │
      ▼
Report Missing
      │
      ▼
Security Gate
      │
      ▼
FAIL
```

The gate supports the `--fail-on-missing` behavior for mandatory scanner reports.

---

# 12. Security Reports

The pipeline generates individual reports as well as consolidated reports.

## Scanner Reports

```text
reports/
├── bandit-report.json
├── semgrep-report.json
├── pip-audit-report.json
├── osv-scanner-report.json
├── gitleaks-report.json
├── trivy-report.json
├── trivy-image-report.json
└── zap-report.json
```

## Normalized Report

```text
reports/normalized-findings.json
```

## Security Gate

```text
reports/security-gate-result.json
```

## Final Reports

```text
reports/
├── security-report.json
├── security-report.md
└── security-report.html
```

These reports can be uploaded as GitHub Actions artifacts for later investigation.

---

# 13. Deliberately Vulnerable Application

The Flask application is intentionally designed as a security-testing target.

The vulnerable baseline demonstrates categories such as:

* Unsafe command construction
* Hardcoded dummy credentials
* Missing input validation
* Missing security headers
* Vulnerable dependency versions

These weaknesses exist **only for educational security testing**.

The application should be run locally or inside an isolated CI environment.

Do not deploy the vulnerable baseline to a public server.

---

# 14. Remediation Workflow

The project demonstrates the complete security lifecycle rather than stopping at vulnerability detection.

```text
Vulnerable Application
        │
        ▼
Security Scan
        │
        ▼
Findings
        │
        ▼
Security Gate FAIL
        │
        ▼
Developer Remediation
        │
        ├── Fix insecure code
        ├── Update dependencies
        ├── Remove hardcoded credentials
        ├── Improve input validation
        └── Harden configuration
        │
        ▼
Security Scan Again
        │
        ▼
Reduced / Resolved Findings
        │
        ▼
Security Gate Evaluation
```

This allows the project to demonstrate both:

**Detection**

and

**Remediation verification**

rather than simply running scanners.

---

# 15. Local Setup

## Requirements

Recommended environment:

* Python 3.11+
* Docker
* Git
* GitHub account
* Linux/WSL recommended for complete local scanner compatibility

Some binary scanners and Docker-dependent stages may not be available in every Windows environment.

---

## Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd devsecops-pipeline
```

---

## Create a virtual environment

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Install application dependencies

```bash
pip install -r app/requirements.txt
```

Install development/testing dependencies as required by the project.

---

# 16. Run the Application

From the project root:

```bash
python app/app.py
```

The API should be available at:

```text
http://127.0.0.1:5000
```

Health check:

```text
http://127.0.0.1:5000/health
```

Expected behavior is an HTTP 200 health response when the application is running correctly.

---

# 17. Run with Docker

Build:

```bash
docker build -t devsecops-pipeline:local ./app
```

Run:

```bash
docker run --rm -p 127.0.0.1:5000:5000 devsecops-pipeline:local
```

Check:

```text
http://127.0.0.1:5000/health
```

Stop the container when testing is complete.

---

# 18. Run Tests

Run the application tests using:

```bash
pytest
```

Run Python syntax validation:

```bash
python -m py_compile scripts/*.py
```

The CI workflow performs syntax validation as part of the security pipeline.

---

# 19. Run Security Scanners Locally

Individual scanners can be executed independently when installed.

### Bandit

```bash
bandit -r app -f json -o reports/bandit-report.json
```

### Semgrep

```bash
semgrep scan --config auto app --json --output reports/semgrep-report.json
```

### pip-audit

```bash
pip-audit -r app/requirements.txt -f json -o reports/pip-audit-report.json
```

### Gitleaks

```bash
gitleaks detect --source . --report-format json --report-path reports/gitleaks-report.json
```

### Trivy

Trivy commands depend on the installed Trivy version and should match the commands defined in the GitHub Actions workflow.

### OWASP ZAP

ZAP requires Docker for the configured baseline workflow.

---

# 20. GitHub Actions

The workflow is located at:

```text
.github/workflows/ci.yml
```

It is configured for:

* Pull requests targeting `main`
* Pushes to `main`
* Manual workflow dispatch

The workflow performs the complete security pipeline.

```text
Test
 ↓
SAST
 ↓
SCA
 ↓
Secrets
 ↓
IaC
 ↓
Docker Build
 ↓
Container Scan
 ↓
DAST
 ↓
Normalization
 ↓
Security Gate
 ↓
Reports
```

---

# 21. GitHub Security Configuration

For production-like repository protection, configure GitHub branch protection so that the required CI status checks must pass before merging.

Recommended controls include:

* Require pull request reviews
* Require successful GitHub Actions checks
* Restrict direct pushes to `main`
* Enable Dependabot updates where appropriate
* Review workflow permissions
* Avoid exposing repository secrets to untrusted pull-request code

The exact required-check names depend on the final GitHub Actions job configuration.

---

# 22. Current Validation Status

The core Python pipeline components have been locally validated.

| Component            | Status                         |
| -------------------- | ------------------------------ |
| Python syntax        | PASS                           |
| Bandit               | PASS — 93 findings detected    |
| Semgrep              | PASS — 0 findings in local run |
| pip-audit            | PASS — 0 findings in local run |
| OSV-Scanner          | Not locally verified           |
| Gitleaks             | Implemented                    |
| Trivy config         | Not locally verified           |
| Trivy image          | Not locally verified           |
| OWASP ZAP            | Not locally verified           |
| Report normalization | PASS                           |
| Security gate logic  | PASS                           |
| Report generation    | PASS                           |

The Docker-dependent and Linux-specific components require validation on an Ubuntu environment or GitHub Actions runner.

---

# 23. Example Security Gate Behavior

A failing security assessment can look conceptually like:

```text
Security Gate
────────────────────────────

Critical : 0
High     : 19
Medium   : 42
Low      : 111

Missing mandatory reports:
- ZAP

Policy:
Critical → FAIL
High     → FAIL
Medium   → WARN
Low      → INFO

RESULT: FAIL
```

The exact counts above should not be interpreted as permanent project metrics; scanner output can change with tool versions, dependency databases, and application changes.

---

# 24. Why Multiple Security Scanners?

No single security tool provides complete application coverage.

This project therefore uses multiple complementary security layers.

```text
Source Code
    │
    ├── Bandit
    └── Semgrep

Dependencies
    │
    ├── pip-audit
    └── OSV-Scanner

Repository Secrets
    │
    └── Gitleaks

Infrastructure
    │
    └── Trivy

Container
    │
    └── Trivy

Running Application
    │
    └─
```
