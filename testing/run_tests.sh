#!/bin/bash
# test runner script for fmcrypto service with coverage
# this script runs all tests and generates coverage reports

set -e

echo "running fmcrypto service tests with coverage..."

# create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "creating virtual environment..."
    python3 -m venv .venv
fi

# activate virtual environment
source .venv/bin/activate

# upgrade pip first to avoid compatibility issues
python -m pip install --upgrade pip

# install test dependencies
pip install pytest pytest-cov pytest-asyncio httpx

# install project dependencies
pip install -r ../crypto_service/requirements.txt
pip install -r ../pki_service/requirements.txt

# set environment variables for testing
export HSM_IP="localhost"
export HSM_PORT="1234"
export CRYPTO_HSM="GP"
export CRYPTO_HOST="localhost"
export CRYPTO_PORT="8001"
export ENVIRONMENT="test"
export PKI_HOST="localhost"
export PKI_PORT="8000"
export PROTOCOL="http"

# add parent directory to python path for imports
export PYTHONPATH="../:$PYTHONPATH"

# run all tests with combined coverage (using .coveragerc configuration)
echo "running all tests and generating combined coverage report..."
pytest unit_tests/ integration_tests/ e2e_tests/ \
    --cov \
    --cov-fail-under=50

echo "tests completed successfully!"
echo "coverage report generated: coverage.xml"
echo "HTML coverage report: htmlcov/index.html"