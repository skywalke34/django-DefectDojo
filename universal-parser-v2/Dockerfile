# Universal Parser V2 Microservice
# Multi-stage build for smaller production image

# Build stage
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Production stage
FROM python:3.12-slim

# Create non-root user for security
RUN groupadd -r upv2 && useradd -r -g upv2 upv2

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder and install
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache /wheels/*

# Copy application code
COPY app/ ./app/
COPY configs/ ./configs/

# Create directories for templates if they exist
RUN mkdir -p app/templates app/static

# Set ownership
RUN chown -R upv2:upv2 /app

# Switch to non-root user
USER upv2

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UPV2_HOST=0.0.0.0 \
    UPV2_PORT=8000 \
    UPV2_LOG_LEVEL=info \
    UPV2_WORKERS=4

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with uvicorn
CMD ["sh", "-c", "uvicorn app.main:app --host ${UPV2_HOST} --port ${UPV2_PORT} --workers ${UPV2_WORKERS} --log-level ${UPV2_LOG_LEVEL}"]
