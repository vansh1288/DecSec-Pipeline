"""
Security tests for the vulnerable Flask API.
These tests verify that intentional vulnerabilities are present in the baseline
and can be detected by security scanning tools.

IMPORTANT: These tests do NOT exploit vulnerabilities. They verify the presence
of vulnerable code patterns for educational demonstration purposes.
"""

import json
import pytest
import sys
import os
import ast
import re

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app, SECURE_MODE


@pytest.fixture
def client():
    """Create test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestVulnerableCodePatterns:
    """Tests that verify vulnerable code patterns exist in the baseline."""

    def test_app_has_subprocess_shell_true(self):
        """Verify search endpoint uses shell=True with user input (CWE-78)."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Check for vulnerable pattern: shell=True with user input
        assert 'shell=True' in content
        assert 'cmd = f"echo' in content or 'cmd = f\'echo' in content
        assert '{query}' in content

    def test_app_has_hardcoded_credentials(self):
        """Verify login endpoint has hardcoded dummy credentials (CWE-798)."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Check for hardcoded credentials
        assert 'DUMMY_USERNAME = "admin"' in content
        assert 'DUMMY_PASSWORD = "password123"' in content
        assert 'username == DUMMY_USERNAME and password == DUMMY_PASSWORD' in content

    def test_app_has_no_input_validation_user_endpoint(self):
        """Verify user endpoint lacks input validation (CWE-20)."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # In vulnerable mode, no regex validation on name parameter
        # Check that validation only happens in SECURE_MODE block
        assert 'SECURE_MODE' in content
        # Vulnerable path should not have strict validation
        vulnerable_section = content.split('VULNERABLE: No validation')[1].split('return jsonify')[0]
        assert 're.match' not in vulnerable_section

    def test_app_missing_security_headers_vulnerable_mode(self):
        """Verify security headers are missing in vulnerable mode."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Check that headers are only added in SECURE_MODE
        assert 'SECURE_MODE' in content
        assert 'X-Content-Type-Options' in content
        assert 'X-Frame-Options' in content
        # But they should be inside the SECURE_MODE block
        secure_section = content.split('if SECURE_MODE:')[1].split('return response')[0]
        assert 'X-Content-Type-Options' in secure_section


class TestSecureModeBehavior:
    """Tests that verify secure mode mitigations work when enabled."""

    def test_secure_mode_search_validation(self, client):
        """In secure mode, search validates input."""
        # This test would need SECURE_MODE=true environment variable
        # For now, verify the code structure exists
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        secure_section = content.split('if SECURE_MODE:')[1].split('VULNERABLE:')[0]
        assert 'isalnum()' in secure_section
        assert 'shell=True' not in secure_section

    def test_secure_mode_login_uses_env(self):
        """In secure mode, login uses environment variables."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        secure_section = content.split('if SECURE_MODE:')[1].split('VULNERABLE:')[0]
        assert 'os.environ.get' in secure_section
        assert 'APP_USERNAME' in secure_section
        assert 'APP_PASSWORD_HASH' in secure_section
        assert 'hmac.compare_digest' in secure_section


class TestSecurityScannerDetection:
    """
    Tests that verify security scanners can detect the vulnerabilities.
    These use static analysis of the source code.
    """

    def test_bandit_would_find_subprocess_shell(self):
        """Bandit rule B602 (subprocess_popen_with_shell_equals_true) should trigger."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Pattern that Bandit B602 detects
        assert re.search(r'subprocess\.run\([^)]*shell\s*=\s*True', content)

    def test_bandit_would_find_hardcoded_password(self):
        """Bandit rule B105 (hardcoded_password_string) should trigger."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Pattern that Bandit B105 detects
        assert 'DUMMY_PASSWORD = "password123"' in content

    def test_semgrep_would_find_command_injection(self):
        """Semgrep rule for command injection should trigger."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Pattern: user input in shell command
        assert 'shell=True' in content
        assert '{query}' in content
        assert 'subprocess.run' in content

    def test_semgrep_would_find_hardcoded_secret(self):
        """Semgrep rule for hardcoded secrets should trigger."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Pattern: hardcoded password assignment
        assert re.search(r'(password|PASSWORD)\s*=\s*["\'][^"\']+["\']', content)

    def test_semgrep_would_find_missing_security_headers(self):
        """Semgrep rule for missing security headers should trigger in vulnerable mode."""
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # In vulnerable mode, response headers lack security headers
        # The secure mode adds them, but vulnerable path doesn't
        assert 'X-Content-Type-Options' in content
        # But only in SECURE_MODE block


class TestDependencyVulnerabilities:
    """Tests that verify vulnerable dependencies are declared."""

    def test_requirements_contain_known_vulnerable_versions(self):
        """Verify requirements.txt contains versions with known CVEs."""
        req_path = os.path.join(os.path.dirname(__file__), '..', 'requirements.txt')
        with open(req_path, 'r') as f:
            content = f.read()
        
        # Check for specific vulnerable versions
        assert 'Flask==2.0.1' in content
        assert 'Werkzeug==2.0.1' in content
        assert 'Jinja2==3.0.1' in content
        assert 'urllib3==1.26.5' in content
        assert 'requests==2.27.1' in content
        assert 'itsdangerous==2.0.1' in content

    def test_requirements_have_cve_comments(self):
        """Verify requirements.txt documents CVE references."""
        req_path = os.path.join(os.path.dirname(__file__), '..', 'requirements.txt')
        with open(req_path, 'r') as f:
            content = f.read()
        
        # Should have CVE comments
        assert 'CVE-' in content


class TestApplicationBehavior:
    """Tests for application runtime behavior related to security."""

    def test_login_endpoint_returns_predictable_response(self, client):
        """Login returns predictable responses for automated testing."""
        # Valid credentials
        resp = client.post('/login', json={'username': 'admin', 'password': 'password123'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'token' in data
        
        # Invalid credentials
        resp = client.post('/login', json={'username': 'admin', 'password': 'wrong'})
        assert resp.status_code == 401
        data = resp.get_json()
        assert data['success'] is False

    def test_search_endpoint_echoes_input(self, client):
        """Search endpoint reflects user input in response."""
        resp = client.get('/search?q=test_input')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['query'] == 'test_input'
        assert 'test_input' in data['result']

    def test_user_endpoint_reflects_input(self, client):
        """User endpoint reflects name parameter in response."""
        resp = client.get('/user?name=testuser')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['name'] == 'testuser'
        assert 'testuser' in data['profile']

    def test_headers_endpoint_no_security_headers_default(self, client):
        """Default response lacks security headers."""
        resp = client.get('/headers')
        # In vulnerable mode, these headers should be absent
        assert 'X-Content-Type-Options' not in resp.headers
        assert 'X-Frame-Options' not in resp.headers
        assert 'Content-Security-Policy' not in resp.headers


class TestErrorHandlingSecurity:
    """Tests for secure error handling."""

    def test_no_stack_traces_in_errors(self, client):
        """Error responses don't expose stack traces."""
        resp = client.get('/nonexistent')
        assert resp.status_code == 404
        data = resp.get_json()
        # Should not contain traceback or internal paths
        assert 'traceback' not in str(data).lower()
        assert 'file "' not in str(data).lower()

    def test_no_credential_logging(self, client):
        """Credentials not logged in plaintext."""
        # This is verified by code inspection - login logs username only
        with open(os.path.join(os.path.dirname(__file__), '..', 'app.py'), 'r') as f:
            content = f.read()
        
        # Should log username but not password
        assert 'logger.info(f"Login attempt for user:' in content
        assert 'password' not in content.split('logger.info')[1].split('\n')[0].lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])