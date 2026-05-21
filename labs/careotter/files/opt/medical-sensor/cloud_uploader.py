#!/usr/bin/env python3
"""
cloud_uploader.py — Push vitals and alerts from the bedside monitor to the Cloud API.

Runs as a cron job every minute (or continuously via procd). Inside each run it
loops every UPLOAD_INTERVAL seconds so the Cloud receives data with ~10 s
granularity without keeping a long-running daemon.

Authentication: X-Device-MAC + X-Device-Hash (hardcoded factory secret).
"""

import json
import os
import sys
import time
import urllib.request

CONFIG_PATH = "/opt/medical-sensor/config.json"
SENSOR_URL = "http://127.0.0.1:8081"

# How often to push data (seconds)
UPLOAD_INTERVAL = 10
# How long this script runs before exiting (cron will restart it)
RUNTIME_SECONDS = 60

# Watermark file for alerts so we only send new events
_ALERT_WATERMARK_FILE = "/tmp/careotter_alert_watermark"


def _load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[Uploader] Could not read {CONFIG_PATH}: {e}")
        return {}


def _get_eth0_mac() -> str:
    try:
        with open("/sys/class/net/eth0/address", "r") as f:
            return f.read().strip().upper()
    except Exception:
        return "00:00:00:00:00:00"


def _sensor_get(endpoint: str, api_key: str) -> dict:
    url = f"{SENSOR_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode())


def _read_alert_watermark() -> float:
    try:
        with open(_ALERT_WATERMARK_FILE, "r") as f:
            return float(f.read().strip())
    except Exception:
        return 0.0


def _write_alert_watermark(ts: float):
    try:
        with open(_ALERT_WATERMARK_FILE, "w") as f:
            f.write(f"{ts}\n")
    except Exception as e:
        print(f"[Uploader] Failed to write watermark: {e}")


def _upload_vitals(cfg: dict, mac: str) -> bool:
    cloud_url = cfg.get("cloud_endpoint", "").rstrip("/")
    if not cloud_url:
        print("[Uploader] No cloud_endpoint configured — skipping vitals")
        return False

    api_key = cfg.get("api_key", "careotter-2024-lab")
    device_hash = cfg.get("device_hash", "9C0C306DEF2A")

    try:
        data = _sensor_get("/vitals", api_key)
    except Exception as e:
        print(f"[Uploader] Failed to read local /vitals: {e}")
        return False

    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        f"{cloud_url}/api/device/vitals",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Device-MAC": mac,
            "X-Device-Hash": device_hash,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"[Uploader] Vitals pushed → {resp.status}")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.read else ""
        print(f"[Uploader] Vitals push failed HTTP {e.code}: {body}")
    except Exception as e:
        print(f"[Uploader] Vitals push error: {e}")
    return False


def _upload_alerts(cfg: dict, mac: str) -> bool:
    cloud_url = cfg.get("cloud_endpoint", "").rstrip("/")
    if not cloud_url:
        return False

    api_key = cfg.get("api_key", "careotter-2024-lab")
    device_hash = cfg.get("device_hash", "9C0C306DEF2A")

    since = _read_alert_watermark()
    try:
        data = _sensor_get(f"/alerts/history?since={since}", api_key)
    except Exception as e:
        print(f"[Uploader] Failed to read local /alerts/history: {e}")
        return False

    alerts = data.get("alerts", [])
    if not alerts:
        return True  # nothing to send

    payload = json.dumps({"alerts": alerts}).encode("utf-8")
    req = urllib.request.Request(
        f"{cloud_url}/api/device/alerts",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Device-MAC": mac,
            "X-Device-Hash": device_hash,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"[Uploader] Alerts pushed ({len(alerts)} items) → {resp.status}")
            # Advance watermark to the newest alert timestamp
            newest = max(float(a.get("timestamp", 0)) for a in alerts)
            _write_alert_watermark(newest)
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.read else ""
        print(f"[Uploader] Alerts push failed HTTP {e.code}: {body}")
    except Exception as e:
        print(f"[Uploader] Alerts push error: {e}")
    return False


def main():
    cfg = _load_config()
    mac = _get_eth0_mac()
    print(f"[Uploader] Starting. MAC={mac} cloud={cfg.get('cloud_endpoint','<not set>')}")

    iterations = max(1, RUNTIME_SECONDS // UPLOAD_INTERVAL)
    for i in range(iterations):
        try:
            _upload_vitals(cfg, mac)
            _upload_alerts(cfg, mac)
        except Exception as e:
            print(f"[Uploader] Unexpected error in iteration {i}: {e}")
        if i < iterations - 1:
            time.sleep(UPLOAD_INTERVAL)

    print("[Uploader] Run complete.")


if __name__ == "__main__":
    main()
