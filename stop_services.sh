#!/bin/bash
# stop both services
# companion script to start_services.sh

echo "stopping fmcrypto services..."

# stop crypto service
if [ -f crypto.pid ]; then
    crypto_pid=$(cat crypto.pid)
    if kill -0 $crypto_pid 2>/dev/null; then
        kill $crypto_pid
        echo "stopped crypto service (pid: $crypto_pid)"
    fi
    rm crypto.pid
else
    echo "crypto service not found or already stopped"
fi

# stop pki service
if [ -f pki.pid ]; then
    pki_pid=$(cat pki.pid)
    if kill -0 $pki_pid 2>/dev/null; then
        kill $pki_pid
        echo "stopped pki service (pid: $pki_pid)"
    fi
    rm pki.pid
else
    echo "pki service not found or already stopped"
fi

# clean up log files if they exist
if [ -f crypto.log ]; then
    rm crypto.log
fi
if [ -f pki.log ]; then
    rm pki.log
fi

echo "all services stopped and cleaned up"
