#!/bin/sh
# CareOtter Security Policy Configuration Hook
# Applies security policy based on device profile (secure, phase2, phase3, phase4)

LOG_FILE="/root/vulnzoo.log"
CONFIG_FILE="/root/careotter/config/security_policy.yaml"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$$] $1" >> "$LOG_FILE"
}

# Determine profile from VULNZOO_DEVICE environment variable OR UCI config
# Devices: careotter (secure), careotter-phase2, careotter-phase3, careotter-phase4
VULNZOO_DEVICE="${VULNZOO_DEVICE:-$(uci -q get vulnzoo.state.current_device 2>/dev/null)}"
DEVICE="${VULNZOO_DEVICE:-careotter}"

log_message "Applying security policy for device: $DEVICE"

# Check config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    log_message "ERROR: Config file not found: $CONFIG_FILE"
    exit 1
fi

# Apply profile-specific configuration
case "$DEVICE" in
    careotter)
        # Secure profile - all protections enabled
        log_message "Profile: SECURE - All protections ENABLED"
        # Config file already has secure defaults, just validate
        ;;
        
    careotter-phase2)
        # Phase 2 profile - BLE encryption disabled for training
        log_message "Profile: PHASE2 - BLE encryption DISABLED (training mode)"
        log_message "WARNING: This disables security controls for training purposes"
        
        # Modify security policy using Python
        python3 << 'PYEOF'
import yaml
import sys

CONFIG_FILE = "/root/careotter/config/security_policy.yaml"

try:
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    
    # Backup original config
    with open(CONFIG_FILE + '.secure_backup', 'w') as f:
        yaml.dump(config, f)
    
    # Phase 2 changes: Disable BLE security
    if 'ble' in config:
        config['ble']['pairing_mode'] = 'just_works'
        config['ble']['encryption_required'] = False
        config['ble']['bonding'] = 'none'
    
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f)
    
    print("Phase 2 configuration applied successfully")
    
except Exception as e:
    print(f"Failed to apply Phase 2 config: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
        
        if [ $? -ne 0 ]; then
            log_message "ERROR: Failed to apply Phase 2 configuration"
            exit 1
        fi
        log_message "Phase 2 configuration applied: BLE attacks enabled"
        ;;
        
    careotter-phase3)
        # Phase 3 profile - API vulnerabilities for training
        log_message "Profile: PHASE3 - OAuth2/API protections DISABLED (training mode)"
        log_message "WARNING: This disables API security for training purposes"
        
        python3 << 'PYEOF'
import yaml
import sys

CONFIG_FILE = "/root/careotter/config/security_policy.yaml"

try:
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    
    # Backup original
    with open(CONFIG_FILE + '.secure_backup', 'w') as f:
        yaml.dump(config, f)
    
    # Phase 3 changes: Disable API security
    if 'api' in config:
        config['api']['authentication'] = 'basic'
        config['api']['tls_version'] = '1.2'
        config['api']['certificate_pinning'] = False
    
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f)
    
    print("Phase 3 configuration applied successfully")
    
except Exception as e:
    print(f"Failed to apply Phase 3 config: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
        
        if [ $? -ne 0 ]; then
            log_message "ERROR: Failed to apply Phase 3 configuration"
            exit 1
        fi
        log_message "Phase 3 configuration applied: API attacks enabled"
        ;;
        
    careotter-phase4)
        # Phase 4 profile - Storage vulnerabilities for training
        log_message "Profile: PHASE4 - Data encryption DISABLED (training mode)"
        log_message "WARNING: This disables storage security for training purposes"
        
        python3 << 'PYEOF'
import yaml
import sys

CONFIG_FILE = "/root/careotter/config/security_policy.yaml"

try:
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    
    # Backup original
    with open(CONFIG_FILE + '.secure_backup', 'w') as f:
        yaml.dump(config, f)
    
    # Phase 4 changes: Disable storage security
    if 'storage' in config:
        config['storage']['encryption_at_rest'] = 'none'
        config['storage']['pii_masking'] = False
        config['storage']['secure_deletion'] = False
    
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f)
    
    print("Phase 4 configuration applied successfully")
    
except Exception as e:
    print(f"Failed to apply Phase 4 config: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
        
        if [ $? -ne 0 ]; then
            log_message "ERROR: Failed to apply Phase 4 configuration"
            exit 1
        fi
        log_message "Phase 4 configuration applied: Storage attacks enabled"
        ;;
        
    *)
        log_message "WARNING: Unknown device profile: $DEVICE - using secure defaults"
        ;;
esac

# Validate YAML syntax
if python3 -c "import yaml; yaml.safe_load(open('$CONFIG_FILE'))" 2>/dev/null; then
    log_message "Security policy validated successfully"
else
    log_message "ERROR: Security policy is invalid YAML"
    exit 1
fi

# Set file permissions (read-only)
chmod 600 "$CONFIG_FILE"
log_message "Config file permissions set to 600"

log_message "Security policy configuration complete"
exit 0
