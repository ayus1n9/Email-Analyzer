# ============================================
# STAGE 1: Builder
# ============================================
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

# Install application dependencies and immediately enforce
# security-fixed versions in the SAME Docker layer.
RUN python -m pip install --no-cache-dir -r requirements.txt && \
    python -m pip install --no-cache-dir --upgrade \
        "pip>=26.2.0" \
        "setuptools>=83.0.0" \
        "wheel>=0.46.2" \
        "msgpack>=1.2.1"

# ============================================
# STAGE 2: Runtime
# ============================================
FROM builder AS runtime

# Remove build-only compiler.
RUN apt-get purge -y gcc && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Install runtime dependency.
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --gecos '' appuser

WORKDIR /app

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

CMD ["python", "app.py"]