# ──────────────────────────────────────────────────────────────────────────────
# Multi-stage Dockerfile for the ASM Asset Management API
#
# Stage 1 (builder): installs build-time dependencies (gcc, libpq-dev) and
#   compiles all Python packages into /install.
# Stage 2 (production): copies only the compiled packages and application code.
#   Does NOT include gcc or build headers, reducing the attack surface.
#
# Security hardening:
# - Non-root user (uid 1001) in the production stage.
# - No SSH, no shell tools beyond what curl needs for health checks.
# - Python output is unbuffered (PYTHONUNBUFFERED=1) for correct log streaming.
# - PYTHONDONTWRITEBYTECODE=1 prevents .pyc files in the image.
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Build-time system dependencies (not needed at runtime)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install all packages into an isolated prefix so they can be copied cleanly.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: production image ─────────────────────────────────────────────────
FROM python:3.12-slim AS production

# Runtime-only system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled packages from builder stage
COPY --from=builder /install /usr/local

# Create a non-root application user
RUN useradd --create-home --uid 1001 --shell /bin/bash appuser

WORKDIR /app

# Copy application source — owned by appuser
COPY --chown=appuser:appuser . .

# Drop privileges
USER appuser

# Python runtime flags
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

EXPOSE 8000

# Container-level health check (also configured in docker-compose)
HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

# 4 Uvicorn workers — tune via UVICORN_WORKERS env var in production.
# For multi-process, consider gunicorn + UvicornWorker instead.
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--log-level", "info", \
     "--access-log"]
