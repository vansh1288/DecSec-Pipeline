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
import hashlib
import hmac
import time
from functools import wraps
from flask import Flask, request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash

# Optional imports for secure mode
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False

try:
    from flask_wtf.csrf import CSRFProtect
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Application metadata
APP_NAME = "devsecops-pipeline"
APP_VERSION = "1.0.0-vulnerable"

# Configuration
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-in-production"),
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes
    WTF_CSRF_ENABLED=os.environ.get("WTF_CSRF_ENABLED", "false").lower() == "true",
    WTF_CSRF_TIME_LIMIT=None,
)

# Dummy hardcoded credentials for educational demonstration only
# In production, use environment variables and proper password hashing
DUMMY_USERNAME = "admin"
DUMMY_PASSWORD = "password123"  # nosec - intentional dummy credential for testing

# Pre-computed hash for secure mode demo (password123)
DUMMY_PASSWORD_HASH = "scrypt:32768:8:1$salt$hash"  # placeholder

# Secure mode flag - when enabled, applies mitigations
SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() == "true"

# Rate limiter for secure mode
limiter = None
if SECURE_MODE and HAS_LIMITER:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.environ.get("RATELIMIT_STORAGE_URL", "memory://"),
    )

# CSRF protection for secure mode
csrf = None
if SECURE_MODE and HAS_CSRF:
    app.config["WTF_CSRF_ENABLED"] = True
    csrf = CSRFProtect(app)

# Store failed login attempts for rate limiting (in-memory, use Redis in production)
_failed_logins = {}


def get_client_ip() -> str:
    """Get client IP address, respecting proxies."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit_login(f):
    """Decorator to rate limit login attempts."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not SECURE_MODE:
            return f(*args, **kwargs)
        
        client_ip = get_client_ip()
        now = time.time()
        
        # Clean old entries
        _failed_logins[client_ip] = [
            t for t in _failed_logins.get(client_ip, []) if now - t < 300  # 5 minutes
        ]
        
        if len(_failed_logins.get(client_ip, [])) >= 5:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return jsonify({
                "error": "Too many failed attempts. Please try again later.",
                "retry_after": 300
            }), 429
        
        return f(*args, **kwargs)
    return decorated_function


def record_failed_login(ip: str):
    """Record a failed login attempt."""
    now = time.time()
    if ip not in _failed_logins:
        _failed_logins[ip] = []
    _failed_logins[ip].append(now)


def clear_failed_logins(ip: str):
    """Clear failed login attempts for an IP."""
    if ip in _failed_logins:
        del _failed_logins[ip]


def add_security_headers(response):
    """Add security headers to response."""
    # These headers are added in both modes for defense in depth
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    
    if SECURE_MODE:
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Remove server header
    response.headers.pop("Server", None)
    
    return response


app.after_request(add_security_headers)


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
        "version": APP_VERSION,
        "secure_mode": SECURE_MODE
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
@rate_limit_login
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

    client_ip = get_client_ip()

    if SECURE_MODE:
        # Secure implementation: environment-based config, proper password hashing
        expected_user = os.environ.get("APP_USERNAME", "admin")
        expected_pass_hash = os.environ.get("APP_PASSWORD_HASH", "")
        
        if not expected_pass_hash:
            logger.error("Server misconfiguration: APP_PASSWORD_HASH not set")
            return jsonify({"error": "Server misconfiguration"}), 500
        
        # Use bcrypt for password verification
        if HAS_BCRYPT:
            try:
                if hmac.compare_digest(username, expected_user) and bcrypt.checkpw(
                    password.encode(), expected_pass_hash.encode()
                ):
                    clear_failed_logins(client_ip)
                    # Generate a secure session token
                    session_token = generate_secure_token()
                    session["user"] = username
                    session["token"] = session_token
                    logger.info(f"Successful login for user: {username}")
                    return jsonify({
                        "success": True,
                        "message": "Login successful (secure mode)",
                        "token": session_token
                    })
            except Exception as e:
                logger.error(f"Bcrypt verification error: {e}")
                return jsonify({"error": "Authentication error"}), 500
        else:
            # Fallback to constant-time comparison with SHA-256 (less secure)
            provided_hash = hashlib.sha256(password.encode()).hexdigest()
            if hmac.compare_digest(username, expected_user) and hmac.compare_digest(provided_hash, expected_pass_hash):
                clear_failed_logins(client_ip)
                session_token = generate_secure_token()
                session["user"] = username
                session["token"] = session_token
                logger.info(f"Successful login for user: {username}")
                return jsonify({
                    "success": True,
                    "message": "Login successful (secure mode - fallback)",
                    "token": session_token
                })
        
        record_failed_login(client_ip)
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


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    import secrets
    return secrets.token_urlsafe(length)


@app.route("/logout", methods=["POST"])
def logout():
    """Logout endpoint - clears session."""
    if SECURE_MODE:
        session.clear()
        return jsonify({"success": True, "message": "Logged out successfully"})
    return jsonify({"success": True, "message": "Logged out (vulnerable mode)"})


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
    In vulnerable mode, omits security headers (added by after_request).
    In secure mode, adds comprehensive security headers.
    
    NOTE: In secure mode, sensitive headers like Authorization are filtered out.
    """
    logger.info("Headers endpoint accessed")
    
    # Filter sensitive headers in secure mode
    safe_headers = {}
    sensitive_headers = {"authorization", "cookie", "x-csrf-token", "x-api-key"}
    
    for key, value in request.headers.items():
        if SECURE_MODE and key.lower() in sensitive_headers:
            safe_headers[key] = "[FILTERED]"
        else:
            safe_headers[key] = value
    
    response = jsonify({
        "headers": safe_headers,
        "server_info": {
            "app": APP_NAME,
            "version": APP_VERSION,
            "secure_mode": SECURE_MODE
        }
    })
    
    return response


@app.route("/secure-info")
def secure_info():
    """
    Endpoint that returns security configuration info (secure mode only).
    Demonstrates what security features are active.
    """
    if not SECURE_MODE:
        return jsonify({"error": "Only available in secure mode"}), 403
    
    return jsonify({
        "secure_mode": True,
        "features": {
            "bcrypt": HAS_BCRYPT,
            "rate_limiting": HAS_LIMITER,
            "csrf_protection": HAS_CSRF and app.config.get("WTF_CSRF_ENABLED", False),
            "secure_cookies": app.config.get("SESSION_COOKIE_SECURE", False),
            "httponly_cookies": app.config.get("SESSION_COOKIE_HTTPONLY", True),
            "samesite_cookies": app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        },
        "headers": {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
    })


@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.path}")
    return jsonify({"error": "Not found", "path": request.path}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    # Never expose stack traces in production
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(429)
def ratelimit_error(error):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(error.description) if hasattr(error, 'description') else "Too many requests"
    }), 429


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # Bind to localhost by default for security
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    
    logger.info(f"Starting {APP_NAME} v{APP_VERSION} on {host}:{port}")
    logger.info(f"Secure mode: {SECURE_MODE}")
    logger.info(f"Debug mode: {debug}")
    
    if SECURE_MODE:
        # Use production WSGI server in secure mode
        try:
            import gunicorn.app.base
            
            class StandaloneApplication(gunicorn.app.base.BaseApplication):
                def __init__(self, app, options=None):
                    self.application = app
                    self.options = options or {}
                    super().__init__()
                
                def load_config(self):
                    for key, value in self.options.items():
                        if key in self.cfg.settings and value is not None:
                            self.cfg.set(key.lower(), value)
                
                def load(self):
                    return self.application
            
            options = {
                "bind": f"{host}:{port}",
                "workers": int(os.environ.get("WORKERS", "4")),
                "timeout": 30,
                "accesslog": "-",
                "errorlog": "-",
            }
            StandaloneApplication(app, options).run()
        except ImportError:
            logger.warning("Gunicorn not available, falling back to Flask dev server")
            app.run(host=host, port=port, debug=debug)
    else:
        # Vulnerable mode uses Flask dev server
        app.run(host=host, port=port, debug=debug)