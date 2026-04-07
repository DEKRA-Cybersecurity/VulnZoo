#!/usr/bin/env python3
# BLE Advertisement Server for CareOtter - Synchronized with sensor

import os
import sys
import subprocess
import time
import json
import signal
import urllib.request

DEVICE_NAME = "CareOtter"
SENSOR_HTTP_URL = "http://127.0.0.1:8081/vitals"

# Configurable interval - sync with sensor (default: 1s for frequent updates)
BLE_EMIT_INTERVAL = int(os.environ.get("BLE_INTERVAL", "1"))

latest_vitals = {"bpm": 72, "spo2": 98}
running = True

def fetch_vitals():
    global latest_vitals
    try:
        with urllib.request.urlopen(SENSOR_HTTP_URL, timeout=2) as response:
            data = json.loads(response.read().decode())
            latest_vitals.update({
                "bpm": data.get("bpm", 72),
                "spo2": data.get("spo2", 98),
            })
    except:
        pass

def shutdown(signum=None, frame=None):
    global running
    running = False
    subprocess.run(["hciconfig", "hci0", "noleadv"], capture_output=True)
    print("[BLE] Stopped")
    sys.exit(0)

def main():
    global running
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    
    print("[BLE] Starting CareOtter BLE Server")
    print("[BLE] Emit interval: %d second(s)" % BLE_EMIT_INTERVAL)
    
    # Setup Bluetooth
    subprocess.run(["hciconfig", "hci0", "up"], capture_output=True)
    time.sleep(0.5)
    subprocess.run(["hciconfig", "hci0", "reset"], capture_output=True)
    time.sleep(0.5)
    subprocess.run(["hciconfig", "hci0", "name", DEVICE_NAME], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "class", "0x7A0440"], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "piscan"], capture_output=True)
    subprocess.run(["hciconfig", "hci0", "leadv", "0"], capture_output=True)
    
    print("[BLE] Advertising as %s" % DEVICE_NAME)
    
    while running:
        fetch_vitals()
        print("[BLE] BPM: %d, SpO2: %d" % (latest_vitals["bpm"], latest_vitals["spo2"]))
        time.sleep(BLE_EMIT_INTERVAL)

if __name__ == "__main__":
    main()
