#!/bin/sh

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [octobot] $1" >> "$LOG_FILE"
}

if ! grep -q '^easyuser:' /etc/passwd; then
    mkdir -p /home/easyuser
    chown -R "easyuser:easyuser" /home/easyuser
    chmod 700 /home/easyuser
    adduser -D -h /home/easyuser -s /bin/ash -G easyuser easyuser
    log_message "User easyuser created."
else
    log_message "User easyuser already exists."
fi

echo "This user is out of scope for this lab. Its existence is only to let the student log in and explore the system. You may want to perform some firmware analysis, so check IoT_Firmware_Static_Analysis.md on the documentation folder. Good luck!" >> /home/easyuser/README.txt
echo "easyuser:easyuser" | chpasswd
log_message "Passwords for easyuser set."
echo "root:dococtopus" | chpasswd
log_message "Passwords for root set."

exit 0