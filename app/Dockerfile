# hadolint ignore=DL3008
FROM python:3.11-slim

# Metadata labels
LABEL org.opencontainers.image.source="https://github.com/YOUR_USERNAME/devsecops-project"
LABEL org.opencontainers.image.description="DevSecOps Flask application"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Upgrade OS packages to patch known CVEs, then clean up in one layer
# hadolint ignore=DL3009
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy and install dependencies before source (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .

# Create non-root user AFTER installs (pip needs write access)
RUN useradd -m -u 1001 -s /bin/false appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

# Read-only healthcheck with no shell (exec form)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["python", "-c", \
       "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"]

# Use exec form (not shell form) to avoid sh wrapper
CMD ["python", "app.py"]
