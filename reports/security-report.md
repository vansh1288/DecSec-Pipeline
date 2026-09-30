# DevSecOps Security Pipeline Report

**Generated:** 2026-09-30T23:28:51.677745ZZ
**Pipeline Run:** test-run
**Commit:** test-sha
**Branch:** test-branch

## Overall Security Gate: FAILED

## Findings Summary

| Severity | Count |
|----------|-------|
| High | 19 |
| Medium | 58 |
| Low | 95 |
| **Total** | **172** |

## Findings by Scanner

| Scanner | Count |
|---------|-------|
| bandit | 93 |
| osv-scanner | 74 |
| gitleaks | 3 |
| trivy | 2 |

## Policy Violations (Security Gate Failures)

These findings violate the configured security policy and caused the gate to fail.

| Severity | Scanner | Rule ID | Message | Location |
|----------|---------|---------|---------|----------|
| High | gitleaks | generic-secret | Generic secret pattern | app/app.py:30 |
| High | gitleaks | generic-secret | Generic secret pattern | app/tests/test_security.py:51 |
| High | gitleaks | generic-secret | Generic secret pattern | app/tests/test_security.py:126 |
| High | bandit | B602 | subprocess call with shell=True identified, security issue. | app/app.py:238 |
| High | osv-scanner | GHSA-m2qf-hxjv-5gpq | Vulnerable dependency: flask@2.0.1 | None |
| High | osv-scanner | GHSA-2g68-c3qc-8985 | Vulnerable dependency: werkzeug@2.0.1 | None |
| High | osv-scanner | GHSA-xg9f-g7g7-2323 | Vulnerable dependency: werkzeug@2.0.1 | None |
| High | osv-scanner | GHSA-xqr8-7jwr-rhp7 | Vulnerable dependency: certifi@2022.12.7 | None |
| High | osv-scanner | GHSA-hc5x-x2vx-497g | Vulnerable dependency: gunicorn@21.2.0 | None |
| High | osv-scanner | GHSA-w3h3-4rj7-4ph4 | Vulnerable dependency: gunicorn@21.2.0 | None |
| High | osv-scanner | GHSA-2xpw-w6gg-jr37 | Vulnerable dependency: urllib3@1.26.5 | None |
| High | osv-scanner | GHSA-38jv-5279-wg99 | Vulnerable dependency: urllib3@1.26.5 | None |
| High | osv-scanner | GHSA-8988-9cw3-xx77 | Vulnerable dependency: urllib3@1.26.5 | None |
| High | osv-scanner | GHSA-gm62-xv2j-4w53 | Vulnerable dependency: urllib3@1.26.5 | None |
| High | osv-scanner | GHSA-qccp-gfcp-xxvc | Vulnerable dependency: urllib3@1.26.5 | None |
| High | osv-scanner | GHSA-v845-jxx5-vc9f | Vulnerable dependency: urllib3@1.26.5 | None |
| High | osv-scanner | GHSA-vxq7-64xx-v4gw | Vulnerable dependency: urllib3@1.26.5 | None |
| High | trivy | CVE-2023-1234 | Buffer overflow in libc6 in libc6 | devsecops-pipeline:1.0.0-vulnerable |
| High | trivy | CVE-2023-30861 | Flask route traversal vulnerability in Flask | devsecops-pipeline:1.0.0-vulnerable |

## Detailed Findings

### High (19)

#### gitleaks: generic-secret
**Message:** Generic secret pattern
**Location:** app/app.py:30

#### gitleaks: generic-secret
**Message:** Generic secret pattern
**Location:** app/tests/test_security.py:51

#### gitleaks: generic-secret
**Message:** Generic secret pattern
**Location:** app/tests/test_security.py:126

#### bandit: B602
**Message:** subprocess call with shell=True identified, security issue.
**Location:** app/app.py:238
**CWEs:** CWE-78

#### osv-scanner: GHSA-m2qf-hxjv-5gpq
**Message:** Vulnerable dependency: flask@2.0.1
**Location:** None
**CVEs:** CVE-2023-30861
**Fixed Versions:** 2.3.2, 2.2.5
**References:** https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq, https://nvd.nist.gov/vuln/detail/CVE-2023-30861, https://github.com/pallets/flask/commit/70f906c51ce49c485f1d355703e9cc3386b1cc2b

#### osv-scanner: GHSA-2g68-c3qc-8985
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2024-34069
**Fixed Versions:** 3.0.3
**References:** https://github.com/pallets/werkzeug/security/advisories/GHSA-2g68-c3qc-8985, https://nvd.nist.gov/vuln/detail/CVE-2024-34069, https://github.com/pallets/werkzeug/commit/3386395b24c7371db11a5b8eaac0c91da5362692

#### osv-scanner: GHSA-xg9f-g7g7-2323
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2023-25577
**Fixed Versions:** 2.2.3
**References:** https://github.com/pallets/werkzeug/security/advisories/GHSA-xg9f-g7g7-2323, https://nvd.nist.gov/vuln/detail/CVE-2023-25577, https://github.com/pallets/werkzeug/commit/517cac5a804e8c4dc4ed038bb20dacd038e7a9f1

#### osv-scanner: GHSA-xqr8-7jwr-rhp7
**Message:** Vulnerable dependency: certifi@2022.12.7
**Location:** None
**CVEs:** CVE-2023-37920
**Fixed Versions:** 2023.7.22
**References:** https://github.com/certifi/python-certifi/security/advisories/GHSA-xqr8-7jwr-rhp7, https://nvd.nist.gov/vuln/detail/CVE-2023-37920, https://github.com/certifi/python-certifi/commit/8fb96ed81f71e7097ed11bc4d9b19afd7ea5c909

#### osv-scanner: GHSA-hc5x-x2vx-497g
**Message:** Vulnerable dependency: gunicorn@21.2.0
**Location:** None
**CVEs:** CVE-2024-6827
**Fixed Versions:** 22.0.0
**References:** https://nvd.nist.gov/vuln/detail/CVE-2024-6827, https://github.com/benoitc/gunicorn/issues/3087, https://github.com/benoitc/gunicorn/issues/3278

#### osv-scanner: GHSA-w3h3-4rj7-4ph4
**Message:** Vulnerable dependency: gunicorn@21.2.0
**Location:** None
**CVEs:** CVE-2024-1135
**Fixed Versions:** 22.0.0
**References:** https://nvd.nist.gov/vuln/detail/CVE-2024-1135, https://github.com/benoitc/gunicorn/issues/3091, https://github.com/benoitc/gunicorn/pull/3113

#### osv-scanner: GHSA-2xpw-w6gg-jr37
**Message:** Vulnerable dependency: urllib3@1.26.5
**Location:** None
**CVEs:** CVE-2025-66471
**Fixed Versions:** 2.6.0
**References:** https://github.com/urllib3/urllib3/security/advisories/GHSA-2xpw-w6gg-jr37, https://nvd.nist.gov/vuln/detail/CVE-2025-66471, https://github.com/urllib3/urllib3/commit/c19571de34c47de3a766541b041637ba5f716ed7

#### osv-scanner: GHSA-38jv-5279-wg99
**Message:** Vulnerable dependency: urllib3@1.26.5
**Location:** None
**CVEs:** CVE-2026-21441
**Fixed Versions:** 2.6.3
**References:** https://github.com/urllib3/urllib3/security/advisories/GHSA-38jv-5279-wg99, https://nvd.nist.gov/vuln/detail/CVE-2026-21441, https://github.com/urllib3/urllib3/commit/8864ac407bba8607950025e0979c4c69bc7abc7b

#### osv-scanner: GHSA-8988-9cw3-xx77
**Message:** Vulnerable dependency: urllib3@1.26.5
**Location:** None
**CVEs:** CVE-2026-97687
**Fixed Versions:** 2.8.0
**References:** https://github.com/urllib3/urllib3/security/advisories/GHSA-8988-9cw3-xx77, https://nvd.nist.gov/vuln/detail/CVE-2026-97687, https://github.com/urllib3/urllib3/pull/5093

#### osv-scanner: GHSA-gm62-xv2j-4w53
**Message:** Vulnerable dependency: urllib3@1.26.5
**Location:** None
**CVEs:** CVE-2025-66418
**Fixed Versions:** 2.6.0
**References:** https://github.com/urllib3/urllib3/security/advisories/GHSA-gm62-xv2j-4w53, https://nvd.nist.gov/vuln/detail/CVE-2025-66418, https://github.com/urllib3/urllib3/commit/24d7b67eac89f94e11003424bcf0d8f7b72222a8

#### osv-scanner: GHSA-qccp-gfcp-xxvc
**Message:** Vulnerable dependency: urllib3@1.26.5
**Location:** None
**CVEs:** CVE-2026-44431
**Fixed Versions:** 2.7.0
**References:** https://github.com/urllib3/urllib3/security/advisories/GHSA-qccp-gfcp-xxvc, https://nvd.nist.gov/vuln/detail/CVE-2026-44431, https://github.com/urllib3/urllib3

#### osv-scanner: GHSA-v845-jxx5-vc9f
**Message:** Vulnerable dependency: urllib3@1.26.5
**Location:** None
**CVEs:** CVE-2023-43804
**Fixed Versions:** 2.0.6, 1.26.17
**References:** https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f, https://nvd.nist.gov/vuln/detail/CVE-2023-43804, https://github.com/urllib3/urllib3/commit/01220354d389cd05474713f8c982d05c9b17aafb

#### osv-scanner: GHSA-vxq7-64xx-v4gw
**Message:** Vulnerable dependency: urllib3@1.26.5
**Location:** None
**CVEs:** CVE-2026-97689
**Fixed Versions:** 2.8.0
**References:** https://github.com/urllib3/urllib3/security/advisories/GHSA-vxq7-64xx-v4gw, https://nvd.nist.gov/vuln/detail/CVE-2026-97689, https://github.com/urllib3/urllib3/commit/cd770b059b543be29298ea5c52afb0b1b090f5ed

#### trivy: CVE-2023-1234
**Message:** Buffer overflow in libc6 in libc6
**Location:** devsecops-pipeline:1.0.0-vulnerable
**CVEs:** CVE-2023-1234
**Fixed Versions:** 2.36-10
**References:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234

#### trivy: CVE-2023-30861
**Message:** Flask route traversal vulnerability in Flask
**Location:** devsecops-pipeline:1.0.0-vulnerable
**CVEs:** CVE-2023-30861
**Fixed Versions:** 2.3.2
**References:** https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30861

### Medium (58)

#### osv-scanner: PYSEC-2023-62
**Message:** Vulnerable dependency: flask@2.0.1
**Location:** None
**CVEs:** CVE-2023-30861
**Fixed Versions:** 70f906c51ce49c485f1d355703e9cc3386b1cc2b, afd63b16170b7c047f5758eb910c416511e9c965, 2.2.5, 2.3.2
**References:** https://github.com/pallets/flask/commit/70f906c51ce49c485f1d355703e9cc3386b1cc2b, https://github.com/pallets/flask/releases/tag/2.3.2, https://github.com/pallets/flask/releases/tag/2.2.5

#### osv-scanner: PYSEC-2026-2151
**Message:** Vulnerable dependency: flask@2.0.1
**Location:** None
**CVEs:** CVE-2026-27205
**Fixed Versions:** 3.1.3
**References:** https://github.com/pallets/flask/releases/tag/3.1.3, https://github.com/pallets/flask/security/advisories/GHSA-68rp-wp8r-4726, https://github.com/pallets/flask/commit/089cb86dd22bff589a4eafb7ab8e42dc357623b4

#### osv-scanner: PYSEC-2026-1471
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2025-27516
**Fixed Versions:** 3.1.6
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7, https://nvd.nist.gov/vuln/detail/CVE-2025-27516, https://github.com/pallets/jinja/commit/90457bbf33b8662926ae65cdde4c4c32e756e403

#### osv-scanner: PYSEC-2026-1472
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-56201
**Fixed Versions:** 3.1.5
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-gmj6-6f8f-6699, https://nvd.nist.gov/vuln/detail/CVE-2024-56201, https://github.com/pallets/jinja/issues/1792

#### osv-scanner: PYSEC-2026-1473
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-22195
**Fixed Versions:** 3.1.3
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-h5c8-rqwp-cp95, https://nvd.nist.gov/vuln/detail/CVE-2024-22195, https://github.com/pallets/jinja/commit/716795349a41d4983a9a4771f7d883c96ea17be7

#### osv-scanner: PYSEC-2026-1474
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-34064
**Fixed Versions:** 3.1.4
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-h75v-3vvj-5mfj, https://nvd.nist.gov/vuln/detail/CVE-2024-34064, https://github.com/pallets/jinja/commit/0668239dc6b44ef38e7a6c9f91f312fd4ca581cb

#### osv-scanner: PYSEC-2026-1475
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-56326
**Fixed Versions:** 3.1.5
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-q2x7-8rv6-6q7h, https://nvd.nist.gov/vuln/detail/CVE-2024-56326, https://github.com/pallets/jinja/commit/48b0687e05a5466a91cd5812d604fa37ad0943b4

#### osv-scanner: GHSA-cpwx-vrp4-4pq7
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2025-27516
**Fixed Versions:** 3.1.6
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7, https://nvd.nist.gov/vuln/detail/CVE-2025-27516, https://github.com/pallets/jinja/commit/90457bbf33b8662926ae65cdde4c4c32e756e403

#### osv-scanner: GHSA-gmj6-6f8f-6699
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-56201
**Fixed Versions:** 3.1.5
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-gmj6-6f8f-6699, https://nvd.nist.gov/vuln/detail/CVE-2024-56201, https://github.com/pallets/jinja/issues/1792

#### osv-scanner: GHSA-h5c8-rqwp-cp95
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-22195
**Fixed Versions:** 3.1.3
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-h5c8-rqwp-cp95, https://nvd.nist.gov/vuln/detail/CVE-2024-22195, https://github.com/pallets/jinja/commit/716795349a41d4983a9a4771f7d883c96ea17be7

#### osv-scanner: GHSA-h75v-3vvj-5mfj
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-34064
**Fixed Versions:** 3.1.4
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-h75v-3vvj-5mfj, https://nvd.nist.gov/vuln/detail/CVE-2024-34064, https://github.com/pallets/jinja/commit/0668239dc6b44ef38e7a6c9f91f312fd4ca581cb

#### osv-scanner: GHSA-q2x7-8rv6-6q7h
**Message:** Vulnerable dependency: jinja2@3.0.1
**Location:** None
**CVEs:** CVE-2024-56326
**Fixed Versions:** 3.1.5
**References:** https://github.com/pallets/jinja/security/advisories/GHSA-q2x7-8rv6-6q7h, https://nvd.nist.gov/vuln/detail/CVE-2024-56326, https://github.com/pallets/jinja/commit/48b0687e05a5466a91cd5812d604fa37ad0943b4

#### osv-scanner: PYSEC-2022-203
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2022-29361
**Fixed Versions:** 9a3a981d70d2e9ec3344b5192f86fcaf3210cd85, 2.1.1
**References:** https://github.com/pallets/werkzeug/commit/9a3a981d70d2e9ec3344b5192f86fcaf3210cd85, https://github.com/pallets/werkzeug/issues/2420

#### osv-scanner: PYSEC-2023-221
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2023-46136
**Fixed Versions:** f3c803b3ade485a45f12b6d6617595350c0f03e2, f2300208d5e2a5076cbbb4c2aad71096fd040ef9, 2.3.8, 3.0.1
**References:** https://github.com/pallets/werkzeug/commit/f3c803b3ade485a45f12b6d6617595350c0f03e2, https://github.com/pallets/werkzeug/security/advisories/GHSA-hrfv-mqp8-q5rw

#### osv-scanner: PYSEC-2023-57
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2023-23934
**Fixed Versions:** cf275f42acad1b5950c50ffe8ef58fe62cdce028, 2.2.3
**References:** https://github.com/pallets/werkzeug/security/advisories/GHSA-px8h-6qxv-m22q, https://github.com/pallets/werkzeug/commit/cf275f42acad1b5950c50ffe8ef58fe62cdce028, https://github.com/pallets/werkzeug/releases/tag/2.2.3

#### osv-scanner: PYSEC-2023-58
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2023-25577
**Fixed Versions:** 517cac5a804e8c4dc4ed038bb20dacd038e7a9f1, 2.2.3
**References:** https://github.com/pallets/werkzeug/commit/517cac5a804e8c4dc4ed038bb20dacd038e7a9f1, https://github.com/pallets/werkzeug/releases/tag/2.2.3, https://github.com/pallets/werkzeug/security/advisories/GHSA-xg9f-g7g7-2323

#### osv-scanner: PYSEC-2026-2043
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2024-34069
**Fixed Versions:** 3.0.3
**References:** https://github.com/pallets/werkzeug/security/advisories/GHSA-2g68-c3qc-8985, https://nvd.nist.gov/vuln/detail/CVE-2024-34069, https://github.com/pallets/werkzeug/commit/3386395b24c7371db11a5b8eaac0c91da5362692

#### osv-scanner: PYSEC-2026-2044
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2026-21860
**Fixed Versions:** 3.1.5
**References:** https://github.com/pallets/werkzeug/security/advisories/GHSA-87hc-h4r5-73f7, https://nvd.nist.gov/vuln/detail/CVE-2026-21860, https://github.com/pallets/werkzeug/commit/7ae1d254e04a0c33e241ac1cca4783ce6c875ca3

#### osv-scanner: PYSEC-2026-2045
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2024-49766
**Fixed Versions:** 3.0.6
**References:** https://github.com/pallets/werkzeug/security/advisories/GHSA-f9vj-2wh5-fj8j, https://nvd.nist.gov/vuln/detail/CVE-2024-49766, https://github.com/pallets/werkzeug/commit/2767bcb10a7dd1c297d812cc5e6d11a474c1f092

#### osv-scanner: PYSEC-2026-2046
**Message:** Vulnerable dependency: werkzeug@2.0.1
**Location:** None
**CVEs:** CVE-2025-66221
**Fixed Versions:** 3.1.4
**References:** https://github.com/pallets/werkzeug/security/advisories/GHSA-hgf8-39gv-g3f2, https://nvd.nist.gov/vuln/detail/CVE-2025-66221, https://github.com/pallets/werkzeug/commit/4b833376a45c323a189cd11d2362bcffdb1c0c13

*... and 38 more medium findings*

### Low (95)

#### bandit: B404
**Message:** Consider possible security implications associated with the subprocess module.
**Location:** app/app.py:13
**CWEs:** CWE-78

#### bandit: B105
**Message:** Possible hardcoded password: 'scrypt:32768:8:1$salt$hash'
**Location:** app/app.py:69
**CWEs:** CWE-259

#### bandit: B607
**Message:** Starting a process with a partial executable path
**Location:** app/app.py:214
**CWEs:** CWE-78

#### bandit: B603
**Message:** subprocess call - check for execution of untrusted input.
**Location:** app/app.py:214
**CWEs:** CWE-78

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:31
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:32
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:38
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:39
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:40
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:49
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:54
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:60
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:69
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:71
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:72
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:77
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:79
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:84
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:86
**CWEs:** CWE-703

#### bandit: B101
**Message:** Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.
**Location:** app/tests\test_app.py:96
**CWEs:** CWE-703

*... and 75 more low findings*

## Remediation Guidance

### GITLEAKS Remediation

- Remove hardcoded secrets from source code
- Use environment variables or secret management systems
- Rotate any exposed credentials immediately
- Add secret scanning to pre-commit hooks

### BANDIT Remediation

- Review and fix insecure code patterns identified
- Use safe APIs (e.g., `subprocess.run` without `shell=True`)
- Implement input validation and sanitization
- Use parameterized queries for database operations

### OSV-SCANNER Remediation

- Update vulnerable dependencies to fixed versions
- Check for breaking changes before upgrading
- Pin dependencies to specific secure versions
- Enable Dependabot or similar automated updates

### TRIVY Remediation

- Update base image to latest secure version
- Remove unnecessary packages from container
- Use distroless or minimal base images
- Scan images regularly in CI/CD

## Execution Metadata

| Property | Value |
|----------|-------|
| evaluated_at | 2026-09-30T23:28:44.418947Z |
| total_findings | 172 |
| policy_violations | 19 |
| suppressed_findings | 0 |
| scanner_failures | 1 |
| missing_reports | 1 |
| policy | {"mode": "strict", "severity": {"critical": "fail", "high": "fail", "medium": "warn", "low": "info", "informational": "info", "unknown": "fail"}, "scanner_failures": "fail", "missing_reports": "fail"} |

---
*Report generated by DevSecOps Security Pipeline*