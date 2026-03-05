#!/bin/sh

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}
# Checking and creation of group 
if ! grep -q '^openwrtuser:' /etc/group; then
    echo 'openwrtuser:x:1000:' >> /etc/group
    log_message "Group openwrtuser created."
else
    log_message "Group openwrtuser already exists."
fi

if ! grep -q '^anonymous:' /etc/group; then
    echo 'anonymous:x:1001:' >> /etc/group
    log_message "Group anonymous created."
else
    log_message "Group anonymous already exists."
fi

if ! grep -q '^nobody:' /etc/group; then
    echo 'nobody:x:1002:' >> /etc/group
    log_message "Group nobody created."
else
    log_message "Group nobody already exists."
fi

exit 0
