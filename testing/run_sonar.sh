#!/bin/bash
# sonarqube analysis script for fmcrypto service
# this script runs tests first, then performs sonarqube analysis

set -e

echo "running sonarqube analysis for fmcrypto service..."

# check if sonarqube scanner is installed
if ! command -v sonar-scanner &> /dev/null; then
    echo "error: sonarqube scanner not found. please install it first."
    exit 1
fi

echo "running tests to generate coverage data..."
./run_tests.sh

# change to project root directory for sonarqube analysis
cd ..

# check if sonarqube server is running
echo "checking sonarqube server status..."
if ! curl -s http://localhost:9000/api/system/status > /dev/null; then
    echo "error: sonarqube server is not running at http://localhost:9000"
    echo "please start your sonarqube server first."
    exit 1
fi

# check if sonarqube token is provided
if [ -z "$SONAR_TOKEN" ]; then
    echo "error: SONAR_TOKEN environment variable is not set."
    echo "pls set your SonarQube token:"
    echo "  export SONAR_TOKEN=\"your_token_here\""
    echo "  ./run_sonar.sh"
    echo ""
    echo "to generate a new token:"
    echo "  1. go to http://localhost:9000"
    echo "  2. login as admin"
    echo "  3. go to User > My Account > Security"
    echo "  4. generate a new token"
    exit 1
fi

echo "using sonarqube token for authentication..."

# run sonarqube analysis from project root
echo "running sonarqube analysis..."
sonar-scanner \
    -Dsonar.host.url=http://localhost:9000 \
    -Dsonar.projectKey=fmcrypto \
    -Dsonar.sources=crypto_service,pki_service,common \
    -Dsonar.tests=testing \
    -Dsonar.exclusions="**/test_*.py,**/tests/**,**/*_test.py,**/test.py,**/Dockerfile*,**/docker-compose*.yml,**/.dockerignore,**/requirements.txt,**/healthcheck.sh,**/DEPLOYMENT.md,**/README.md,**/run.py,**/.venv/**,**/__pycache__/**" \
    -Dsonar.python.coverage.reportPaths=testing/coverage.xml \
    -Dsonar.python.xunit.reportPath=testing/test-results.xml \
    -Dsonar.coverage.exclusions="**/test_*.py,**/tests/**,**/*_test.py,**/test.py" \
    -Dsonar.sourceEncoding=UTF-8 \
    -Dsonar.python.version=3.13

echo "sonarqube analysis completed!"
echo "view results at: http://localhost:9000/dashboard?id=fmcrypto"