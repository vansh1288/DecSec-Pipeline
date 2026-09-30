"""
DevSecOps Pipeline - Vulnerable Flask Application (Educational Baseline)

This application intentionally contains security vulnerabilities for educational purposes.
It demonstrates common web application security flaws that should be detected by
security scanning tools in a DevSecOps pipeline.

WARNING: This application is intentionally vulnerable. Do not deploy publicly.
Use only in isolated CI environments or localhost for security testing.
"""

import os
import subprocess
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Application metadata
APP_NAME = "devsecops-pipeline"
APP_VERSION = "1.0.0-vulnerable"

# Dummy hardcoded credentials for educational demonstration only
# In production, use environment variables and proper password hashing
DUMMY_USERNAME = "admin"
DUMMY_PASSWORD = "password123"  # nosec - intentional dummy credential for testing

# Secure mode flag - when enabled, applies mitigations
SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() == "true"


@app.route("/")
def index():
    """Return welcome message with application info."""
    logger.info("Root endpoint accessed")
    return jsonify({
        "message": f"Welcome to {APP_NAME}",
        "version": APP_VERSION,
        "secure_mode": SECURE_MODE,
        "description": "Educational vulnerable application for DevSecOps pipeline testing"
    })


@app.route("/health")
def health():
    """Health check endpoint for CI/CD pipeline."""
    logger.info("Health check requested")
    return jsonify({
        "status": "healthy",
        "application": APP_NAME,
        "version": APP_VERSION
    }), 200


@app.route("/search")
def search():
    """
    VULNERABLE ENDPOINT: Command Injection Demonstration
    
    This endpoint demonstrates unsafe command construction using user input.
    In secure mode, input validation and safe execution patterns are used.
    
    Vulnerability: User input directly interpolated into shell command.
    CWE-78: Improper Neutralization of Special Elements used in an OS Command
    """
    query = request.args.get("q", "")
    logger.info(f"Search requested with query: {query}")

    if SECURE_MODE:
        # Secure implementation: validate input, use allowlist, avoid shell
        if not query or not query.isalnum():
            return jsonify({
                "error": "Invalid query parameter. Only alphanumeric characters allowed.",
                "vulnerability": "command_injection_prevented"
            }), 400
        
        # Safe execution without shell=True
        try:
            result = subprocess.run(
                ["echo", f"Searching for: {query}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return jsonify({
                "query": query,
                "result": result.stdout.strip(),
                "mode": "secure"
            })
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Search timeout"}), 500
        except Exception as e:
            logger.error(f"Search error: {e}")
            return jsonify({"error": "Internal server error"}), 500

    # VULNERABLE: Direct user input in shell command
    # This is intentionally unsafe for educational demonstration
    try:
        # Using shell=True with user input - VULNERABLE to command injection
        cmd = f"echo 'Searching for: {query}'"
        result = subprocess.run(
            cmd,
            shell=True,  # VULNERABILITY: shell=True with user input
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({
            "query": query,
            "result": result.stdout.strip(),
            "mode": "vulnerable",
            "warning": "This endpoint demonstrates command injection vulnerability"
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Search timeout"}), 500
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/login", methods=["POST"])
def login():
    """
    VULNERABLE ENDPOINT: Insecure Authentication
    
    This endpoint demonstrates multiple authentication vulnerabilities:
    - Hardcoded credentials
    - Plaintext password comparison
    - No rate limiting
    - No password hashing
    
    In secure mode, uses environment variables and proper authentication practices.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    logger.info(f"Login attempt for user: {username}")

    if SECURE_MODE:
        # Secure implementation: environment-based config, constant-time comparison
        import hmac
        import hashlib
        
        expected_user = os.environ.get("APP_USERNAME", "admin")
        expected_pass_hash = os.environ.get("APP_PASSWORD_HASH", "")
        
        if not expected_pass_hash:
            return jsonify({"error": "Server misconfiguration"}), 500
        
        # In real app, use bcrypt/argon2. Here we demonstrate constant-time compare
        provided_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if hmac.compare_digest(username, expected_user) and hmac.compare_digest(provided_hash, expected_pass_hash):
            return jsonify({
                "success": True,
                "message": "Login successful (secure mode)",
                "token": "demo-jwt-token-secure"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Invalid credentials"
            }), 401

    # VULNERABLE: Hardcoded credentials, plaintext comparison
    if username == DUMMY_USERNAME and password == DUMMY_PASSWORD:
        return jsonify({
            "success": True,
            "message": "Login successful (vulnerable mode)",
            "token": "dummy-token-123",
            "warning": "This endpoint demonstrates insecure authentication"
        })
    else:
        return jsonify({
            "success": False,
            "error": "Invalid credentials"
        }), 401


@app.route("/user")
def user():
    """
    VULNERABLE ENDPOINT: Improper Input Validation
    
    Demonstrates lack of input validation and potential path traversal.
    In secure mode, implements proper validation and sanitization.
    """
    name = request.args.get("name", "")
    logger.info(f"User endpoint accessed with name: {name}")

    if SECURE_MODE:
        # Secure implementation: strict validation
        import re
        if not name or not re.match(r'^[a-zA-Z0-9_-]{1,50}$', name):
            return jsonify({
                "error": "Invalid name parameter. Use alphanumeric, underscore, hyphen only (1-50 chars).",
                "vulnerability": "input_validation_enforced"
            }), 400
        
        return jsonify({
            "name": name,
            "profile": f"User profile for {name}",
            "mode": "secure"
        })

    # VULNERABLE: No validation, potential for injection/path traversal
    # In real vulnerable app, this might be used in file operations or SQL
    return jsonify({
        "name": name,
        "profile": f"User profile for {name}",
        "mode": "vulnerable",
        "warning": "This endpoint demonstrates improper input validation"
    })


@app.route("/headers")
def headers():
    """
    ENDPOINT: Security Headers Testing
    
    Returns response headers for security header analysis.
    In vulnerable mode, omits security headers.
    In secure mode, adds security headers.
    """
    logger.info("Headers endpoint accessed")
    
    response = jsonify({
        "headers": dict(request.headers),
        "server_info": {
            "app": APP_NAME,
            "version": APP_VERSION,
            "secure_mode": SECURE_MODE
        }
    })
    
    if SECURE_MODE:
        # Add security headers in secure mode
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    
    return response


@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.path}")
    return jsonify({"error": "Not found", "path": request.path}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    
    logger.info(f"Starting {APP_NAME} v{APP_VERSION} on {host}:{port}")
    logger.info(f"Secure mode: {SECURE_MODE}")
    app.run(host=host, port=port, debug=debug)