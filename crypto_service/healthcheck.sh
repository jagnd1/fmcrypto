#!/bin/sh
python -c "import requests; requests.get('http://localhost:8001/health', timeout=5)"
