#!/bin/sh
# 15-canary-python-deps.sh - verify runtime deps.
# The services use only the Python standard library (AF_CAN raw sockets, UDP), so
# this hook only verifies python3 is present. Packages are baked into the base
# image at build time; the lab never installs at runtime.
LOG=/root/vulnzoo.log

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [canary] $1" >> "$LOG_FILE"
}

if command -v python3 >/dev/null 2>&1; then
	log_message "dep OK: python3 (services use only the standard library)"
else
	log_message "ERROR: python3 not found in image (bake it into the base image)"
fi
exit 0
