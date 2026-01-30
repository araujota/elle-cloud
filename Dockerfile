# ELLE Cloud Container
# Lightweight, ultra-secure container for anonymized incident reports

FROM python:3.10-slim-bookworm AS base

# Install PostgreSQL client libraries for psycopg
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Security: Run as non-root user
RUN useradd -r -s /bin/false -d /app elle

WORKDIR /app

# Install dependencies first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY elle_cloud/ ./elle_cloud/

# Create data and cert directories
RUN mkdir -p /data /certs && chown -R elle:elle /data /certs

# Switch to non-root user
USER elle

# Environment defaults
ENV ELLE_CLOUD_MODE=org \
    ELLE_CLOUD_DATA_DIR=/data \
    ELLE_CLOUD_CERT_DIR=/certs \
    ELLE_CLOUD_BIND_HOST=0.0.0.0 \
    ELLE_CLOUD_BIND_PORT=8443 \
    ELLE_CLOUD_HEALTH_PORT=8080 \
    ELLE_CLOUD_LOG_LEVEL=info \
    ELLE_CLOUD_LOG_FORMAT=json

# Expose ports
# 8443 = mTLS API
# 8080 = HTTP health checks (internal only)
EXPOSE 8443 8080

# Volumes for persistence
VOLUME ["/data", "/certs"]

# Health check (uses internal HTTP port)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Entry point
ENTRYPOINT ["python", "-m", "elle_cloud.main"]

# Default command is to run the server
CMD ["server"]
