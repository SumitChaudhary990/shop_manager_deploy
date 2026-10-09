#!/bin/bash
echo "==================================================="
echo "  Starting Shop Management System..."
echo "==================================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.9+"
    exit 1
fi

# Install dependencies
echo "[*] Checking dependencies..."
pip install -r requirements.txt --quiet

# Launch with Gunicorn if available, fallback to python3 app.py
echo "[*] Starting server on http://0.0.0.0:5000 ..."
if command -v gunicorn &> /dev/null; then
    exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 wsgi:app
else
    exec python3 app.py
fi
