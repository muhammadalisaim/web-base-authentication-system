# Multi-stage / minimal, security-hardened Dockerfile for Security Scanner API
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Create non-root system user and group for safe container operation
RUN groupadd --gid 10001 scanner && \
    useradd --uid 10001 --gid scanner --shell /bin/bash --create-home scanner

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend /app/backend

# Copy root-level modules the API imports (server.py, phone_trace.py) plus the
# static frontend served at "/"
COPY server.py phone_trace.py generate_ssl.py index.html /app/
COPY assets /app/assets

# Create data directory for database with proper permissions
RUN mkdir -p /data && chown -R scanner:scanner /data /app

# Switch to non-root user
USER scanner

WORKDIR /app/backend

# Expose port
EXPOSE 8000

# Healthcheck using Python standard library (no external curl required)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start FastAPI application with production Uvicorn settings
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
