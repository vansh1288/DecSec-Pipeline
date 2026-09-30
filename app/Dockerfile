# DevSecOps Pipeline - Dockerfile for Vulnerable Flask Application
# Educational baseline with intentional security issues for scanning demonstration

# Use official Python slim image - specific version for reproducibility
FROM python:3.11-slim-bookworm

# Set build arguments for metadata
ARG BUILD_DATE
ARG VERSION=1.0.0-vulnerable
ARG VCS_REF

# Labels for image metadata
LABEL maintainer="DevSecOps Pipeline Project" \
      org.opencontainers.image.title="devsecops-pipeline" \
      org.opencontainers.image.description="Educational vulnerable Flask app for DevSecOps security scanning" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/example/devsecops-pipeline" \
      org.opencontainers.image.licenses="MIT"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOME=/app \
    PORT=5000

# Create non-root user and group
RUN groupadd -r appuser --gid 1000 && \
    useradd -r -g appuser --uid 1000 --home-dir /app --shell /bin/bash appuser

# Set working directory
WORKDIR ${APP_HOME}

# Install system dependencies required for runtime
# Using --no-install-recommends to reduce attack surface
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Copy requirements first for better layer caching
COPY --chown=appuser:appuser requirements.txt .

# Install Python dependencies as root (pip needs write access to site-packages)
# Then change ownership to appuser
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    chown -R appuser:appuser /usr/local/lib/python3.11/site-packages

# Copy application code
COPY --chown=appuser:appuser app.py .

# Create necessary directories with proper ownership
RUN mkdir -p /app/logs /app/tmp && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 5000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command - run the Flask application
# Using exec form for proper signal handling
CMD ["python", "app.py"]