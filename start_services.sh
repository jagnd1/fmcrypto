#!/bin/bash
# start the crypto service for local testing
# this mimics what you do manually in separate terminals

set -e

echo "starting fmcrypto services..."

# check if the service is already running
if curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "crypto service already running on port 8001"
else
    echo "starting crypto service on port 8001..."
    cd crypto_service
    nohup uvicorn app.main:app --host 0.0.0.0 --port 8001 > ../crypto.log 2>&1 &
    echo $! > ../crypto.pid
    cd ..
fi

# wait for the service to be ready
echo "waiting for the service to start..."
timeout 30s bash -c 'until curl -f http://localhost:8001/health > /dev/null 2>&1; do sleep 2; done'
echo "crypto service is ready at http://localhost:8001"

echo ""
echo "crypto service is running!"
echo "crypto service: http://localhost:8001"
echo ""
echo "to run tests + sonar analysis: cd testing && ./run_sonar.sh"
echo "to run tests only: cd testing && ./run_tests.sh"
echo "to stop the service: ./stop_services.sh"
echo "to view logs: tail -f crypto.log"