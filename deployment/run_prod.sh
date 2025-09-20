#!/bin/bash
# production deployment script for fmcrypto service
# this script builds and runs the services in production mode

set -e

echo "starting fmcrypto service production environment..."

# check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "err: docker is not running. pls start docker first."
    exit 1
fi

# check for production environment file
if [ ! -f ".env.production" ]; then
    echo "warn: .env.production file not found. using default environment variables."
fi

# build and run services in production mode
echo "building and starting services in production mode..."
docker-compose -f docker-compose.prod.yml up --build -d

echo "production environment started successfully!"
echo "crypto service: http://localhost:8001"
echo "pki service: http://localhost:8000"
echo "use 'docker-compose -f docker-compose.prod.yml logs -f' to view logs"
