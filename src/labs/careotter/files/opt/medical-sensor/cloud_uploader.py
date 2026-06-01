#!/usr/bin/env python3
"""
cloud_uploader.py — Push vitals and alerts from the bedside monitor to the Cloud API.

Runs as a cron job every minute (or continuously via procd). Inside each run it
loops every UPLOAD_INTERVAL seconds so the Cloud receives data with ~10 s
granularity without keeping a long-running daemon.

Authentication: X-Device-MAC + X-Device-Hash (hardcoded factory secret).
"""

import json
import logging
import logging.handlers
import os
import sys
import time
import urllib.request
import urllib.error

# ── Logging configuration ────────────────────────────────────────────────────
LOG_DIR = "/var/log/medical-logs"
LOG_FILE = os.path.join(LOG_DIR, "cloud_uploader.log")

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("cloud_uploader")
logger.setLevel(logging.DEBUG)

# Rotating file handler (max 100 KB per file, keep 3 backups)
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=100_000, backupCount=3
)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Also log to stdout so procd can capture it
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("[Uploader] %(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# ── Configuration ────────────────────────────────────────────────────────────
CONFIG_PATH = "/opt/medical-sensor/config.json"
SENSOR_URL = "http://127.0.0.1:8081"

UPLOAD_INTERVAL = 10       # seconds between pushes
RUNTIME_SECONDS = 60       # total runtime before exit (cron restarts)

_ALERT_WATERMARK_FILE = "/tmp/careotter_alert_watermark"


def _load_config() -> dict:
    logger.debug(f"Loading config from {CONFIG_PATH}")
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
            logger.debug(f"Config loaded: {cfg}")
            return cfg
    except Exception as e:
        logger.error(f"Could not read {CONFIG_PATH}: {e}")
        return {}


def _get_eth0_mac() -> str:
    try:
        with open("/sys/class/net/eth0/address", "r") as f:
            mac = f.read().strip().upper()
            logger.debug(f"eth0 MAC resolved: {mac}")
            return mac
    except Exception as e:
        logger.warning(f"Failed to read eth0 MAC: {e}; using fallback")
        return "00:00:00:00:00:00"


def _sensor_get(endpoint: str, api_key: str) -> dict:
    url = f"{SENSOR_URL}{endpoint}"
    logger.debug(f"Sensor GET {url}")
    req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req, timeout=3) as resp:
        data = json.loads(resp.read().decode())
        logger.debug(f"Sensor response: {data}")
        return data


def _read_alert_watermark() -> float:
    try:
        with open(_ALERT_WATERMARK_FILE, "r") as f:
            ts = float(f.read().strip())
            logger.debug(f"Alert watermark read: {ts}")
            return ts
    except Exception:
        logger.debug("Alert watermark not found or unreadable, defaulting to 0.0")
        return 0.0


def _write_alert_watermark(ts: float):
    try:
        with open(_ALERT_WATERMARK_FILE, "w") as f:
            f.write(f"{ts}\n")
        logger.debug(f"Alert watermark written: {ts}")
    except Exception as e:
        logger.error(f"Failed to write watermark: {e}")


def _upload_vitals(cfg: dict, mac: str) -> bool:
    cloud_url = cfg.get("cloud_endpoint", "").rstrip("/")
    if not cloud_url:
        logger.info("No cloud_endpoint configured — skipping vitals")
        return False

    api_key = cfg.get("api_key", "careotter-2024-lab")
    device_hash = cfg.get("device_hash", "9C0C306DEF2A")

    logger.info(f"Uploading vitals to {cloud_url}/api/device/vitals (MAC={mac})")
    try:
        data = _sensor_get("/vitals", api_key)
    except Exception as e:
        logger.error(f"Failed to read local /vitals: {e}")
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
            body = resp.read().decode() if resp.read else ""
            logger.info(f"Vitals pushed successfully → HTTP {resp.status} | {body}")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.read else ""
        logger.error(f"Vitals push failed HTTP {e.code}: {body}")
    except Exception as e:
        logger.error(f"Vitals push error: {e}")
    return False


def _upload_alerts(cfg: dict, mac: str) -> bool:
    cloud_url = cfg.get("cloud_endpoint", "").rstrip("/")
    if not cloud_url:
        logger.info("No cloud_endpoint configured — skipping alerts")
        return False

    api_key = cfg.get("api_key", "careotter-2024-lab")
    device_hash = cfg.get("device_hash", "9C0C306DEF2A")

    since = _read_alert_watermark()
    logger.info(f"Uploading alerts since watermark={since}")
    try:
        data = _sensor_get(f"/alerts/history?since={since}", api_key)
    except Exception as e:
        logger.error(f"Failed to read local /alerts/history: {e}")
        return False

    alerts = data.get("alerts", [])
    if not alerts:
        logger.debug("No new alerts to upload")
        return True

    logger.info(f"Found {len(alerts)} alert(s) to upload")
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
            body = resp.read().decode() if resp.read else ""
            logger.info(f"Alerts pushed ({len(alerts)} items) → HTTP {resp.status} | {body}")
            newest = max(float(a.get("timestamp", 0)) for a in alerts)
            _write_alert_watermark(newest)
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.read else ""
        logger.error(f"Alerts push failed HTTP {e.code}: {body}")
    except Exception as e:
        logger.error(f"Alerts push error: {e}")
    return False


def main():
    cfg = _load_config()
    mac = _get_eth0_mac()
    cloud = cfg.get("cloud_endpoint", "<not set>")
    logger.info(f"Starting. MAC={mac} cloud={cloud}")

    iterations = max(1, RUNTIME_SECONDS // UPLOAD_INTERVAL)
    for i in range(iterations):
        logger.debug(f"Iteration {i + 1}/{iterations}")
        try:
            _upload_vitals(cfg, mac)
            _upload_alerts(cfg, mac)
        except Exception as e:
            logger.exception(f"Unexpected error in iteration {i}: {e}")
        if i < iterations - 1:
            time.sleep(UPLOAD_INTERVAL)

    logger.info("Run complete.")


if __name__ == "__main__":
    main()
