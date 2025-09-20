#!/bin/bash
# start both services for local testing
# this mimics what you do manually in separate terminals

set -e

echo "starting fmcrypto services..."

# check if services are already running
if curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "crypto service already running on port 8001"
else
    echo "starting crypto service on port 8001..."
    cd crypto_service
    nohup uvicorn app.main:app --host 0.0.0.0 --port 8001 > ../crypto.log 2>&1 &
    echo $! > ../crypto.pid
    cd ..
fi

if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "pki service already running on port 8000"
else
    echo "starting pki service on port 8000..."
    cd pki_service
    nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 > ../pki.log 2>&1 &
    echo $! > ../pki.pid
    cd ..
fi

# wait for services to be ready
echo "waiting for services to start..."
timeout 30s bash -c 'until curl -f http://localhost:8001/health > /dev/null 2>&1; do sleep 2; done'
echo "crypto service is ready at http://localhost:8001"

timeout 30s bash -c 'until curl -f http://localhost:8000/health > /dev/null 2>&1; do sleep 2; done'
echo "pki service is ready at http://localhost:8000"

echo ""
echo "both services are running!"
echo "crypto service: http://localhost:8001"
echo "pki service: http://localhost:8000"
echo ""
echo "to run tests + sonar analysis: cd testing && ./run_sonar.sh"
echo "to run tests only: cd testing && ./run_tests.sh"
echo "to stop services: ./stop_services.sh"
echo "to view logs: tail -f crypto.log pki.log"
