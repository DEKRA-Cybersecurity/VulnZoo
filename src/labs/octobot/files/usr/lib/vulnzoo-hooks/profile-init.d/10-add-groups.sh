#!/bin/sh

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}
# Checking and creation of group 
if ! grep -q '^easyuser:' /etc/group; then
    echo 'easyuser:x:1000:' >> /etc/group
    log_message "Group easyuser created."
else
    log_message "Group easyuser already exists."
fi

exit 0
