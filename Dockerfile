# Stage 1: Build virtualenv with dependencies
FROM python:3.14-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Final minimal runtime
FROM python:3.14-slim AS runner

WORKDIR /app

# Create a dedicated non-root user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin appuser

# Copy installed Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

# Set ownership and secure permissions
RUN chown -R appuser:appgroup /app /home/appuser/.local

ENV PATH="/home/appuser/.local/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER appuser

EXPOSE 8000

# --proxy-headers: trust the hosting proxy for the real client IP (used for sign-in rate limits).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
