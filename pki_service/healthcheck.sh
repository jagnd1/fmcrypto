#!/bin/sh
python -c "import requests; requests.get('http://localhost:8000/health', timeout=5)"
