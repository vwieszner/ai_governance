FROM python:3.11-slim

WORKDIR /app

# System deps for spaCy + Presidio
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]" --break-system-packages 2>/dev/null || \
    pip install --no-cache-dir -e "."

# Download spaCy model for Presidio
RUN python -m spacy download en_core_web_lg

# Copy source
COPY . .

EXPOSE 8000

# Default: run the API server
CMD ["python", "-m", "api.main"]
