FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    docker==7.0.0 \
    requests==2.31.0

COPY main.py /app/

# Run as non-root for security
RUN useradd -m -u 1000 appuser
USER appuser

ENV PYTHONUNBUFFERED=1

# No port exposed - polling-based, outbound only
CMD ["python", "main.py"]
