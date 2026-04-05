# DevSecOps Flask Application - Production Dockerfile
# hadolint ignore=DL3008,DL3009
FROM python:3.11-slim

# Metadata labels (best practice)
LABEL org.opencontainers.image.source="https://github.com/YOUR_USERNAME/devsecops-project"
LABEL org.opencontainers.image.description="DevSecOps Flask application"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Upgrade OS packages to patch known CVEs + clean up in one layer
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy and install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py .

# Create non-root user
RUN useradd -m -u 1001 -s /bin/false appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

# Healthcheck (exec form - no shell)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5000/health') || exit 1"]

# Production server: Gunicorn (recommended over flask app.run())
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]