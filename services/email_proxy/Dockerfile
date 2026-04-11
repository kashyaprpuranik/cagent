FROM python:3.11-slim

WORKDIR /app

# Install uv for deterministic dependency installation
COPY --from=ghcr.io/astral-sh/uv:0.7 /uv /usr/local/bin/uv

# Install Python dependencies from lock file (supply chain protection:
# exclude-newer in pyproject.toml rejects packages uploaded after a cutoff date)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev && rm -rf /root/.cache
ENV PATH="/app/.venv/bin:$PATH"

COPY . /app/

RUN useradd -r -s /bin/false appuser
USER appuser

ENV PYTHONUNBUFFERED=1

EXPOSE 8025

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8025", "--log-level", "info"]
