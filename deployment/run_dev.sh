#!/bin/bash
# development deployment script for fmcrypto service
# this script builds and runs the services in development mode

set -e

echo "starting fmcrypto service development environment..."

# check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "err: docker is not running. pls start docker first."
    exit 1
fi

# build and run services
echo "building and starting services..."
docker-compose up --build

echo "development environment started successfully!"
echo "crypto service: http://localhost:8001"
echo "pki service: http://localhost:8000"
