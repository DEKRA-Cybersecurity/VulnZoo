#!/bin/sh
# 15-octobot-python-deps.sh - verify gateway runtime deps.
# Packages are baked into the base image at build time (make menuconfig); the lab
# runs offline, so this hook only VERIFIES presence and never installs at runtime.
LOG=/root/vulnzoo.log

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [octobot] $1" >> "$LOG"
}
command -v python3 >/dev/null 2>&1 || { log_message "ERROR: python3 not found in image"; exit 0; }

# import-name : module the corresponding service needs
for mod in serial flask paho.mqtt.client; do
	if python3 -c "import $mod" 2>/dev/null; then
		log_message "dep OK: $mod"
	else
		log_message "MISSING dep: $mod (bake it into the base image, do not install at runtime)"
	fi
done
exit 0
