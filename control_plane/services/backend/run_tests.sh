#!/bin/bash
# Run integration tests for control-plane API

set -e

cd "$(dirname "$0")"


# Install test dependencies if needed
pip install -q -r requirements-test.txt

# Also need the main dependencies
pip install -q \
    fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    sqlalchemy==2.0.25 \
    cryptography==42.0.0 \
    pydantic==2.5.3 \
    python-multipart==0.0.6 \
    psycopg2-binary==2.9.9 \
    httpx==0.26.0

# Run tests
pytest "$@"
