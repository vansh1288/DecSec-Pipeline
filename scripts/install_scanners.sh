#!/usr/bin/env bash
# DevSecOps Pipeline - Scanner Installation Script
# Installs required security scanners for Ubuntu GitHub Actions runners
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Pinned versions for reproducible installs
GITLEAKS_VERSION="8.23.1"
SEMGREP_VERSION="1.113.0"
BANDIT_VERSION="1.7.10"
OSV_SCANNER_VERSION="1.9.1"
PIP_AUDIT_VERSION="2.8.0"
TRIVY_VERSION="0.57.1"
ZAP_DOCKER_VERSION="2.14.0"

# Installation directory for binaries
INSTALL_DIR="/usr/local/bin"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

install_gitleaks() {
    log_info "Installing Gitleaks ${GITLEAKS_VERSION}..."
    
    if check_command gitleaks; then
        current_version=$(gitleaks version 2>/dev/null | head -1 || echo "unknown")
        log_info "Gitleaks already installed: ${current_version}"
        return 0
    fi
    
    cd /tmp
    local archive="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    local url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${archive}"
    
    log_info "Downloading ${url}..."
    curl -fsSL "${url}" -o "${archive}" || {
        log_error "Failed to download Gitleaks"
        return 1
    }
    
    tar -xzf "${archive}" gitleaks || {
        log_error "Failed to extract Gitleaks"
        return 1
    }
    
    sudo mv gitleaks "${INSTALL_DIR}/" || {
        log_error "Failed to install Gitleaks"
        return 1
    }
    
    sudo chmod +x "${INSTALL_DIR}/gitleaks"
    
    log_info "Gitleaks installed successfully: $(gitleaks version 2>/dev/null | head -1)"
    return 0
}

install_semgrep() {
    log_info "Installing Semgrep ${SEMGREP_VERSION}..."
    
    if check_command semgrep; then
        current_version=$(semgrep --version 2>/dev/null || echo "unknown")
        log_info "Semgrep already installed: ${current_version}"
        return 0
    fi
    
    # Semgrep is a Python package - install via pip with pinned version
    python3 -m pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" || {
        log_error "Failed to install Semgrep via pip"
        return 1
    }
    
    log_info "Semgrep installed successfully: $(semgrep --version 2>/dev/null || echo 'unknown')"
    return 0
}

install_bandit() {
    log_info "Installing Bandit ${BANDIT_VERSION}..."
    
    if check_command bandit; then
        current_version=$(bandit --version 2>/dev/null | head -1 || echo "unknown")
        log_info "Bandit already installed: ${current_version}"
        return 0
    fi
    
    python3 -m pip install --no-cache-dir "bandit==${BANDIT_VERSION}" || {
        log_error "Failed to install Bandit via pip"
        return 1
    }
    
    log_info "Bandit installed successfully: $(bandit --version 2>/dev/null | head -1)"
    return 0
}

install_osv_scanner() {
    log_info "Installing OSV-Scanner ${OSV_SCANNER_VERSION}..."
    
    if check_command osv-scanner; then
        current_version=$(osv-scanner --version 2>/dev/null | head -1 || echo "unknown")
        log_info "OSV-Scanner already installed: ${current_version}"
        return 0
    fi
    
    cd /tmp
    local archive="osv-scanner_${OSV_SCANNER_VERSION}_linux_amd64.tar.gz"
    local url="https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/${archive}"
    
    log_info "Downloading ${url}..."
    curl -fsSL "${url}" -o "${archive}" || {
        log_error "Failed to download OSV-Scanner"
        return 1
    }
    
    tar -xzf "${archive}" osv-scanner || {
        log_error "Failed to extract OSV-Scanner"
        return 1
    }
    
    sudo mv osv-scanner "${INSTALL_DIR}/" || {
        log_error "Failed to install OSV-Scanner"
        return 1
    }
    
    sudo chmod +x "${INSTALL_DIR}/osv-scanner"
    
    log_info "OSV-Scanner installed successfully: $(osv-scanner --version 2>/dev/null | head -1)"
    return 0
}

install_pip_audit() {
    log_info "Installing pip-audit ${PIP_AUDIT_VERSION}..."
    
    if check_command pip-audit; then
        current_version=$(pip-audit --version 2>/dev/null || echo "unknown")
        log_info "pip-audit already installed: ${current_version}"
        return 0
    fi
    
    python3 -m pip install --no-cache-dir "pip-audit==${PIP_AUDIT_VERSION}" || {
        log_error "Failed to install pip-audit via pip"
        return 1
    }
    
    log_info "pip-audit installed successfully: $(pip-audit --version 2>/dev/null || echo 'unknown')"
    return 0
}

install_trivy() {
    log_info "Installing Trivy ${TRIVY_VERSION}..."
    
    if check_command trivy; then
        current_version=$(trivy --version 2>/dev/null | head -1 || echo "unknown")
        log_info "Trivy already installed: ${current_version}"
        return 0
    fi
    
    cd /tmp
    local archive="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    local url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${archive}"
    
    log_info "Downloading ${url}..."
    curl -fsSL "${url}" -o "${archive}" || {
        log_error "Failed to download Trivy"
        return 1
    }
    
    tar -xzf "${archive}" trivy || {
        log_error "Failed to extract Trivy"
        return 1
    }
    
    sudo mv trivy "${INSTALL_DIR}/" || {
        log_error "Failed to install Trivy"
        return 1
    }
    
    sudo chmod +x "${INSTALL_DIR}/trivy"
    
    log_info "Trivy installed successfully: $(trivy --version 2>/dev/null | head -1)"
    return 0
}

install_zap() {
    log_info "Verifying Docker availability for OWASP ZAP..."
    
    if ! check_command docker; then
        log_error "Docker is not installed. OWASP ZAP requires Docker."
        log_info "Install Docker using: sudo apt-get update && sudo apt-get install -y docker.io"
        return 1
    fi
    
    log_info "Pulling OWASP ZAP Docker image ${ZAP_DOCKER_VERSION}..."
    docker pull "owasp/zap2docker-stable:${ZAP_DOCKER_VERSION}" || {
        log_error "Failed to pull OWASP ZAP Docker image"
        return 1
    }
    
    log_info "OWASP ZAP Docker image ready: owasp/zap2docker-stable:${ZAP_DOCKER_VERSION}"
    return 0
}

verify_installations() {
    log_info "Verifying all scanner installations..."
    
    local failed=0
    
    for cmd in gitleaks semgrep bandit osv-scanner pip-audit trivy; do
        if check_command "$cmd"; then
            version=$("$cmd" --version 2>/dev/null | head -1 || echo "unknown")
            log_info "  ${cmd}: ${version}"
        else
            log_error "  ${cmd}: NOT FOUND"
            failed=1
        fi
    done
    
    if check_command docker; then
        if docker image inspect "owasp/zap2docker-stable:${ZAP_DOCKER_VERSION}" >/dev/null 2>&1; then
            log_info "  ZAP (Docker): owasp/zap2docker-stable:${ZAP_DOCKER_VERSION}"
        else
            log_warn "  ZAP (Docker): Image not found locally (will be pulled at runtime)"
        fi
    else
        log_error "  Docker: NOT FOUND (required for ZAP)"
        failed=1
    fi
    
    if [ $failed -eq 0 ]; then
        log_info "All required scanners are installed and verified!"
        return 0
    else
        log_error "Some scanners failed verification"
        return 1
    fi
}

main() {
    log_info "Starting scanner installation for DevSecOps Pipeline..."
    log_info "Target OS: $(uname -s) $(uname -r)"
    log_info "Install directory: ${INSTALL_DIR}"
    
    # Update package list and install prerequisites
    log_info "Installing prerequisites..."
    sudo apt-get update -qq || {
        log_error "Failed to update package list"
        exit 1
    }
    
    sudo apt-get install -y -qq curl tar python3-pip || {
        log_error "Failed to install prerequisites"
        exit 1
    }
    
    # Upgrade pip
    python3 -m pip install --upgrade pip --quiet || {
        log_warn "Failed to upgrade pip, continuing..."
    }
    
    # Install setuptools for pkg_resources (required by Semgrep)
    python3 -m pip install --no-cache-dir setuptools || {
        log_warn "Failed to install setuptools, continuing..."
    }
    
    # Install all scanners
    install_gitleaks || exit 1
    install_semgrep || exit 1
    install_bandit || exit 1
    install_osv_scanner || exit 1
    install_pip_audit || exit 1
    install_trivy || exit 1
    install_zap || exit 1
    
    # Verify all installations
    verify_installations || exit 1
    
    log_info "All scanners installed successfully!"
}

main "$@"