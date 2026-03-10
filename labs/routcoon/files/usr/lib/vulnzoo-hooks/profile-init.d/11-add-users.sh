#!/bin/sh

LOG_FILE="/root/vulnzoo.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}

# Crear grupos si no existen
for user in openwrtuser anonymous nobody; do
    if ! grep -q "^$user:" /etc/group; then
        gid=$(awk -F: 'END{print $3+1}' /etc/group)
        echo "$user:x:$gid:" >> /etc/group
    fi
done

# Crear usuarios si no existen
if ! grep -q '^openwrtuser:' /etc/passwd; then
    mkdir -p /home/openwrtuser
    chown -R "openwrtuser:openwrtuser" /home/openwrtuser
    chmod 700 /home/openwrtuser
    adduser -D -h /home/openwrtuser -s /usr/bin/rshell -G openwrtuser openwrtuser
    log_message "User openwrtuser created."
else
    log_message "User openwrtuser already exists."
fi

if ! grep -q '^anonymous:' /etc/passwd; then
    adduser -D -h /tmp/ftp -s /bin/false -G anonymous anonymous
    log_message "User anonymous created."
else
    log_message "User anonymous already exists."
fi

if ! grep -q '^nobody:' /etc/passwd; then
    adduser -D -h /var -s /bin/false -G nobody nobody
    log_message "User nobody created."
else
    log_message "User nobody already exists."
fi

echo "root:uncrackable" | chpasswd
echo "openwrtuser:openwrtuserpwned" | chpasswd
log_message "Passwords for root and openwrtuser set."

exit 0