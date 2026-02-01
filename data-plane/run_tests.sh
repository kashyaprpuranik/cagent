#!/bin/bash
# Run data-plane tests

set -e

cd "$(dirname "$0")"

# Install test dependencies
pip install -q -r requirements-test.txt

echo "=== Running unit and config tests ==="
pytest tests/ -v --ignore=tests/test_e2e.py "$@"

echo ""
echo "=== E2E tests ==="
echo "To run E2E tests, first start the data plane:"
echo "  docker-compose up -d"
echo ""
echo "Then run:"
echo "  pytest tests/test_e2e.py -v"
