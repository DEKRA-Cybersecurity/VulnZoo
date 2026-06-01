#!/bin/ash
# /opt/oem-updates/scripts/auto-updater.sh

PENDING_DIR="/opt/oem-updates/pending"
LOG_FILE="/var/log/oem-update.log"

echo "[$(date)] Checking for pending updates..." >> $LOG_FILE

for file in $PENDING_DIR/*.sh $PENDING_DIR/*.img $PENDING_DIR/*.bin; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        echo "[$(date)] Processing: $filename" >> $LOG_FILE
        
        if sysupgrade -t "$file" >/dev/null 2>&1; then
            echo "[$(date)] Valid firmware detected, upgrading..." >> $LOG_FILE
            sysupgrade -v -n "$file" >> $LOG_FILE 2>&1 &
        else
            echo "[$(date)] Executing update preparation script: $filename" >> $LOG_FILE
            /bin/sh "$file" >> $LOG_FILE 2>&1
        fi
        
        rm -f "$file"
        echo "[$(date)] Update processed, file removed" >> $LOG_FILE
    fi
done