# Agent + Temporal worker image for one division (Phase 1, item 5).
# Same image runs both roles; the compose service picks the entrypoint:
#   agent  -> python -m api.main         (FastAPI/uvicorn on :8000)
#   worker -> python -m workflow.worker  (Temporal worker, no port)
#
# Deps are installed from the frozen, portable lock (win32-only packages are markered
# out, so this builds on linux). FastEmbed downloads its model at first run to a mounted
# cache volume, not at build time.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FASTEMBED_CACHE_PATH=/cache/fastembed

WORKDIR /app

# System libs some wheels need at runtime (onnxruntime for fastembed, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

# Install deps first (cached layer) from the lock.
COPY requirements.lock.txt /app/requirements.lock.txt
RUN pip install -r /app/requirements.lock.txt

# App source.
COPY . /app

# Non-root runtime user; owns the fastembed cache mount point.
RUN useradd -m -u 1000 appuser && mkdir -p /cache/fastembed && chown -R appuser /cache /app
USER appuser

EXPOSE 8000

# Default to the API; the worker service overrides `command:` in compose.
CMD ["python", "-m", "api.main"]
