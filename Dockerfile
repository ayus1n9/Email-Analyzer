# ============================================
# STAGE 1: Builder
# ============================================
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

# Create an isolated environment containing the exact
# application dependencies.
RUN python -m venv /opt/venv

RUN /opt/venv/bin/python -m pip install --no-cache-dir \
    --upgrade \
    "pip>=26.2.0" \
    "setuptools>=83.0.0" \
    "wheel>=0.46.2" \
    "msgpack>=1.2.1"

RUN /opt/venv/bin/python -m pip install --no-cache-dir \
    -r requirements.txt

# ============================================
# STAGE 2: Final Image
# ============================================
FROM python:3.12-slim AS runtime

RUN rm -rf \
    /usr/local/lib/python3.12/site-packages/pip \
    /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
    /usr/local/bin/pip \
    /usr/local/bin/pip3 \
    /usr/local/bin/pip3.12

RUN adduser --disabled-password --gecos '' appuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ========== FIX: Remove system Python packages ==========
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip* \
    && rm -rf /usr/local/lib/python3.12/site-packages/msgpack* \
    && rm -rf /usr/local/lib/python3.12/site-packages/setuptools* \
    && rm -rf /usr/local/lib/python3.12/site-packages/wheel*

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=appuser:appuser . .

RUN find . -type f -name "*.pyc" -delete && \
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

RUN chown -R appuser:appuser /app

USER appuser

ENV FLASK_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000

RUN mkdir -p /app/data /app/uploads && \
    chmod 755 /app/data /app/uploads

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/health || exit 1

EXPOSE 5000

CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "app:app"]