FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN useradd -r -s /bin/false appuser
USER appuser

ENV PYTHONUNBUFFERED=1

EXPOSE 8025

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8025", "--log-level", "info"]
