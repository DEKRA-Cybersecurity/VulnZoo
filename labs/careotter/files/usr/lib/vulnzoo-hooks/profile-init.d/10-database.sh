#!/bin/sh
# CareOtter Database Initialization Hook
# Initializes SQLite database and creates schema

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}

log_message "Initializing CareOtter database..."

# Ensure data directory exists
mkdir -p /root/careotter/data /root/careotter/logs
chmod 700 /root/careotter/data

# Initialize database using Python
cd /root/careotter || exit 1

python3 << 'PYEOF'
import sys
import os
sys.path.insert(0, '/root/careotter')

try:
    from core.data_store import DataStore
    db = DataStore()
    print("Database initialized successfully")
except Exception as e:
    print(f"Database initialization failed: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

if [ $? -eq 0 ]; then
    log_message "Database initialization complete"
    exit 0
else
    log_message "Database initialization FAILED"
    exit 1
fi
