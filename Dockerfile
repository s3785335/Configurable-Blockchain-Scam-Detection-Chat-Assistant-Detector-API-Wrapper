# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

# Keep Python output unbuffered and avoid .pyc clutter in the image.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so this layer is cached across code changes.
COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir ".[api]"

# Non-root user for the container process.
RUN useradd --create-home --uid 1000 appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "detector_api_wrapper.api:app", "--host", "0.0.0.0", "--port", "8000"]
