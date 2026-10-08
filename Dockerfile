FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LOG_DIR=/app/logs

WORKDIR /app

RUN useradd --create-home --uid 10001 appuser

COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src

# Presidio's default NLP engine loads en_core_web_lg; without it the analyzer
# fails (or tries to download the model) on the first request.
RUN pip install --upgrade pip \
    && pip install . \
    && python -m spacy download en_core_web_lg

# /app is root-owned; the app creates LOG_DIR at import time, so it must exist
# and be writable by the unprivileged runtime user.
RUN mkdir -p /app/logs && chown appuser:appuser /app/logs

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn", "pii_tokenizer.main:app", "--host", "0.0.0.0", "--port", "8000"]
