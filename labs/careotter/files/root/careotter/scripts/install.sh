#!/bin/bash
# CareOtter Installation Script for OpenWRT/Raspberry Pi
# Usage: ./install.sh

set -e

echo "[*] CareOtter Installation Script"
echo "[*] Target: OpenWRT 24.10.2 / Raspberry Pi 3B"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directories
CAREOTTER_DIR="/root/careotter"
DATA_DIR="$CAREOTTER_DIR/data"
CONFIG_DIR="$CAREOTTER_DIR/config"
LOG_DIR="$CAREOTTER_DIR/logs"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[-] This script must be run as root${NC}"
   exit 1
fi

# Step 1: Install system dependencies
echo -e "${YELLOW}[*] Step 1: Installing system dependencies...${NC}"

# Update package manager
opkg update 2>/dev/null || apt-get update 2>/dev/null

# List of packages for different systems
if command -v opkg &> /dev/null; then
    # OpenWRT
    PACKAGES="python3 python3-pip bluez bluez-utils i2c-tools"
    opkg install $PACKAGES 2>/dev/null || true
else
    # Debian/Ubuntu
    apt-get install -y python3 python3-pip bluez i2c-tools 2>/dev/null || true
fi

echo -e "${GREEN}[+] System dependencies installed${NC}"

# Step 2: Create directory structure
echo -e "${YELLOW}[*] Step 2: Creating directory structure...${NC}"

mkdir -p "$CAREOTTER_DIR"/{core,api,config,data,logs,scripts}
chmod 700 "$CAREOTTER_DIR"

echo -e "${GREEN}[+] Directories created${NC}"

# Step 3: Install Python dependencies
echo -e "${YELLOW}[*] Step 3: Installing Python dependencies...${NC}"

PYTHON_PACKAGES=(
    "bleak"
    "pyyaml"
    "aiohttp"
    "smbus2"
)

for pkg in "${PYTHON_PACKAGES[@]}"; do
    echo "[*] Installing $pkg..."
    pip3 install "$pkg" 2>/dev/null || echo -e "${YELLOW}[!] Failed to install $pkg${NC}"
done

echo -e "${GREEN}[+] Python dependencies installed${NC}"

# Step 4: Verify Python environment
echo -e "${YELLOW}[*] Step 4: Verifying Python environment...${NC}"

python3 << 'PYEOF'
import sys
print(f"[+] Python version: {sys.version}")

try:
    import bleak
    print("[+] bleak imported successfully")
except ImportError:
    print("[-] bleak not available")

try:
    import yaml
    print("[+] pyyaml imported successfully")
except ImportError:
    print("[-] pyyaml not available")

try:
    import aiohttp
    print("[+] aiohttp imported successfully")
except ImportError:
    print("[-] aiohttp not available (cloud sync disabled)")

try:
    import smbus2
    print("[+] smbus2 imported successfully")
except ImportError:
    print("[-] smbus2 not available (I2C sensor disabled)")
PYEOF

# Step 5: Setup Bluetooth
echo -e "${YELLOW}[*] Step 5: Configuring Bluetooth...${NC}"

# Enable Bluetooth service
if command -v systemctl &> /dev/null; then
    systemctl enable bluetooth 2>/dev/null || true
    systemctl start bluetooth 2>/dev/null || true
    echo -e "${GREEN}[+] Bluetooth service started${NC}"
else
    echo -e "${YELLOW}[!] systemctl not available (OpenWRT?)${NC}"
fi

# Check for bluetooth hardware
if hciconfig &> /dev/null; then
    hciconfig
    echo -e "${GREEN}[+] Bluetooth hardware detected${NC}"
else
    echo -e "${YELLOW}[!] hciconfig not available - check Bluetooth manually${NC}"
fi

# Step 6: Initialize database
echo -e "${YELLOW}[*] Step 6: Initializing database...${NC}"

python3 << 'PYEOF'
import sys
sys.path.insert(0, '/root/careotter')

try:
    from core.data_store import DataStore
    db = DataStore()
    print("[+] Database initialized successfully")
except Exception as e:
    print(f"[-] Database initialization failed: {e}")
    sys.exit(1)
PYEOF

# Step 7: Grant I2C permissions (if available)
echo -e "${YELLOW}[*] Step 7: Configuring I2C permissions...${NC}"

if [ -e /dev/i2c-1 ]; then
    chmod 666 /dev/i2c-1 2>/dev/null || true
    echo -e "${GREEN}[+] I2C device permissions set${NC}"
else
    echo -e "${YELLOW}[!] /dev/i2c-1 not found - I2C may not be available${NC}"
fi

# Step 8: Create init script
echo -e "${YELLOW}[*] Step 8: Creating init.d startup script...${NC}"

cat > "$CAREOTTER_DIR/scripts/careotter-daemon" << 'DAEMON_EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          careotter
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: CareOtter Cardiac Monitor
# Description:       OpenWRT/RPi cardiac monitoring daemon
### END INIT INFO

NAME="careotter"
DESC="CareOtter Cardiac Monitor"
DAEMON="/root/careotter/main.py"
PIDFILE="/var/run/$NAME.pid"
LOGFILE="/root/careotter/logs/careotter.log"

case "$1" in
  start)
    echo "Starting $DESC..."
    python3 "$DAEMON" > "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "$DESC started"
    ;;
  stop)
    echo "Stopping $DESC..."
    if [ -f "$PIDFILE" ]; then
      kill $(cat "$PIDFILE") 2>/dev/null || true
      rm "$PIDFILE"
    fi
    echo "$DESC stopped"
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  status)
    if [ -f "$PIDFILE" ]; then
      PID=$(cat "$PIDFILE")
      if ps -p "$PID" > /dev/null 2>&1; then
        echo "$DESC is running (PID: $PID)"
      else
        echo "$DESC is not running (stale PID file)"
      fi
    else
      echo "$DESC is not running"
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac

exit 0
DAEMON_EOF

chmod +x "$CAREOTTER_DIR/scripts/careotter-daemon"
echo -e "${GREEN}[+] Init script created${NC}"

# Step 9: Install init script
echo -e "${YELLOW}[*] Step 9: Installing init script...${NC}"

if [ -d /etc/init.d ]; then
    ln -sf "$CAREOTTER_DIR/scripts/careotter-daemon" /etc/init.d/careotter 2>/dev/null || true
    
    if command -v update-rc.d &> /dev/null; then
        update-rc.d careotter defaults 2>/dev/null || true
    elif command -v rc-service &> /dev/null; then
        # OpenWRT procd
        /etc/init.d/careotter enable 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Init script installed${NC}"
else
    echo -e "${YELLOW}[!] /etc/init.d not found - manual startup required${NC}"
fi

# Step 10: Verification
echo -e "${YELLOW}[*] Step 10: Verifying installation...${NC}"

if [ -f "$DATA_DIR/careotter.db" ]; then
    echo -e "${GREEN}[+] Database exists${NC}"
else
    echo -e "${RED}[-] Database not found${NC}"
fi

if [ -f "$CONFIG_DIR/security_policy.yaml" ]; then
    echo -e "${GREEN}[+] Configuration files present${NC}"
else
    echo -e "${YELLOW}[!] Configuration files not found - using defaults${NC}"
fi

# Final summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}[+] Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Installation directory: $CAREOTTER_DIR"
echo "Database: $DATA_DIR/careotter.db"
echo "Logs: $LOG_DIR/"
echo ""
echo "Next steps:"
echo "1. Verify Bluetooth: hciconfig"
echo "2. Check configuration: cat $CONFIG_DIR/security_policy.yaml"
echo "3. Start service: service careotter start"
echo "4. View logs: tail -f $LOG_DIR/careotter.log"
echo ""
