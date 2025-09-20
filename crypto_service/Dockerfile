# Multi-stage build for security and size optimization
FROM python:3.13-alpine AS builder

# Install build dependencies for Alpine
RUN apk add --no-cache \
    gcc \
    libffi-dev \
    linux-headers \
    musl-dev \
    openssl-dev

WORKDIR /code

# Copy requirements and install Python dependencies
COPY crypto_service/requirements.txt /code/crypto_service/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --user -r /code/crypto_service/requirements.txt

# Runtime stage - minimal Alpine base image
FROM python:3.13-alpine AS runtime

# Create non-root user and install runtime dependencies
RUN addgroup -g 1001 -S appuser && \
    adduser -u 1001 -S appuser -G appuser && \
    apk add --no-cache \
        ca-certificates \
        libffi \
        libssl3

WORKDIR /code

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code (only necessary files)
COPY crypto_service/ /code/crypto_service/
COPY common/ /code/common/
COPY run.py /code/

# Set proper ownership and permissions
RUN chown -R appuser:appuser /code /home/appuser/.local && \
    chmod +x /code/crypto_service/healthcheck.sh

# Switch to non-root user
USER appuser

# Add user's local bin to PATH
ENV PATH=/home/appuser/.local/bin:$PATH
ENV PYTHONPATH=/code

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/code/crypto_service/healthcheck.sh"]

# Expose port
EXPOSE 8001

# Use exec form for better signal handling
CMD ["uvicorn", "crypto_service.app.main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]