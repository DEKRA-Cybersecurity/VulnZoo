#!/usr/bin/env python3

import asyncio
import json
import urllib.request
import os
import sys
import time
import struct
import binascii
import fcntl
import socket
from typing import Optional
from urllib.parse import urlparse

try:
    from Crypto.Cipher import AES
    _HAS_AES = True
except ImportError:
    _HAS_AES = False
    print("[BLE] WARNING: pycryptodome not available — CSCP v1 disabled")

from dbus_fast import Variant, BusType, Message, MessageType
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method, signal, dbus_property, PropertyAccess

# URLs and configuration
SENSOR_CONFIG_PATH = "/opt/medical-sensor/config.json"
SENSOR_URL = "http://127.0.0.1:8081/vitals"
DEVICE_NAME = "CareOtter_HR"


def _load_sensor_api_key() -> str:
    """Read api_key from /opt/medical-sensor/config.json.

    The sensor HTTP service on :8081 requires an X-API-Key header on every
    protected endpoint (vitals, log, alerts, …). Falling back to the same
    hardcoded literal that ``sensor_service.py`` uses keeps this file usable
    in environments where the config file has not been provisioned yet."""
    try:
        with open(SENSOR_CONFIG_PATH, "r") as f:
            return json.load(f).get("api_key", "careotter-2024-lab")
    except Exception as e:
        print(f"[BLE] Could not read api_key from {SENSOR_CONFIG_PATH}: {e}")
        return "careotter-2024-lab"


SENSOR_API_KEY = _load_sensor_api_key()


def _sensor_http_get(url: str, timeout: float = 2.0):
    """Issue a GET to the sensor HTTP service with the X-API-Key header set."""
    req = urllib.request.Request(url, headers={"X-API-Key": SENSOR_API_KEY})
    return urllib.request.urlopen(req, timeout=timeout)

# Cloud API address embedded in BLE advertising ManufacturerData (binary, 10 bytes):
#   [0:4]  Cloud API IPv4  big-endian  (e.g. 192.168.1.50)
#   [4:6]  Cloud API port  big-endian  (e.g. 5002)
#   [6:10] Device WiFi IP  big-endian  (wlan0, read at runtime)
#
# VULNERABILITY: passive BLE scan (no pairing, no auth) reveals both the
# cloud management endpoint and the device's WiFi address — information disclosure.
# Default cloud URL is EMPTY — the device ships with no pre-configured backend.
# A clinical technician must use the Factory Provisioning channel (0xFF10)
# to set both WiFi credentials and the Cloud API endpoint during initial
# bedside installation.  This mirrors real medical IoT onboarding workflows.
CLOUD_API_URL = os.getenv("CLOUD_API_URL", "")

# Hardcoded factory signature — identical across all CareOtter devices.
# Sent to the Cloud API during registration so the backend can verify
# the device is genuine. VULNERABILITY: any attacker who captures this
# signature can register a rogue device or replay it to a fake cloud.
DEVICE_SIGNATURE = "CareOtterFactorySig2026"

# Persisted provisioning state file — survives BLE server restarts.
_PROVISION_FILE = "/tmp/careotter-provision.json"


def _fetch_api_wifi_ip(api_base_url: str) -> tuple:
    """Query the Cloud API /api/health over Ethernet to get its WiFi IP.
    Retries with backoff so the BLE server can start before Docker is ready.
    Returns ('0.0.0.0', 0) if the URL is empty, malformed, or unreachable."""
    if not api_base_url:
        return "0.0.0.0", 0
    parsed = urlparse(api_base_url)
    if not parsed.scheme or not parsed.netloc:
        return "0.0.0.0", 0
    health_url = f"{parsed.scheme}://{parsed.netloc}/api/health"
    max_retries = 10
    delay = 2
    for attempt in range(1, max_retries + 1):
        try:
            with urllib.request.urlopen(health_url, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                ip = data.get("wifi_ip", "0.0.0.0")
                port = int(data.get("api_port", parsed.port or 5002))
                if ip != "0.0.0.0":
                    print(f"[BLE] API WiFi IP resolved: {ip}:{port} (attempt {attempt})")
                    return ip, port
                print(f"[BLE] API returned 0.0.0.0, retrying... ({attempt}/{max_retries})")
        except Exception as e:
            print(f"[BLE] API wifi_ip fetch failed (attempt {attempt}/{max_retries}): {e}")
        if attempt < max_retries:
            time.sleep(delay)
    print(f"[BLE] Could not resolve API wifi_ip after {max_retries} attempts")
    return "0.0.0.0", parsed.port or 5002


def _get_wlan0_ip() -> str:
    """Return the current IPv4 address of wlan0, or '0.0.0.0' on failure."""
    SIOCGIFADDR = 0x8915
    iface = b"wlan0\x00" * 1
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, iface.ljust(40, b"\x00"))
        s.close()
        return socket.inet_ntoa(res[20:24])
    except Exception:
        return os.getenv("DEVICE_WIFI_IP", "0.0.0.0")


def _build_mfr_payload(api_url: str) -> bytes:
    """Return 10-byte binary ManufacturerData payload.

    Layout (big-endian):
        [0:4]  Cloud API WiFi IPv4 (fetched from /api/health over Ethernet)
        [4:6]  Cloud API port
        [6:10] Device wlan0 IPv4

    If api_url is empty (device not yet provisioned), returns all zeros
    so the Android app knows no Cloud backend is configured yet.
    """
    if api_url:
        api_wifi_ip, api_port = _fetch_api_wifi_ip(api_url)
    else:
        api_wifi_ip, api_port = "0.0.0.0", 0
    dev_ip = _get_wlan0_ip()
    try:
        api_ip_bytes = socket.inet_aton(api_wifi_ip)
    except OSError:
        api_ip_bytes = b"\x00" * 4
    try:
        dev_ip_bytes = socket.inet_aton(dev_ip)
    except OSError:
        dev_ip_bytes = b"\x00" * 4
    return api_ip_bytes + struct.pack(">H", api_port) + dev_ip_bytes

# Fake company ID 0x08D4 ("CareOtter Medical Devices") used in ManufacturerData AD type.
# Any BLE scanner (nRF Connect, btmon, bleak) can read this without pairing.
CAREOTTER_COMPANY_ID = 0x08D4

# Standard Bluetooth SIG UUIDs
HR_SERVICE_UUID = "0000180d-0000-1000-8000-00805f9b34fb"
HR_MEASUREMENT_UUID = "00002a37-0000-1000-8000-00805f9b34fb"

PLX_SERVICE_UUID = "00001822-0000-1000-8000-00805f9b34fb"
PLX_CONTINUOUS_UUID = "00002a5f-0000-1000-8000-00805f9b34fb"

BATTERY_SERVICE_UUID = "0000180f-0000-1000-8000-00805f9b34fb"
BATTERY_LEVEL_UUID = "00002a19-0000-1000-8000-00805f9b34fb"

# Device Information Service (0x180A)
DEVINFO_SERVICE_UUID = "0000180a-0000-1000-8000-00805f9b34fb"
MANUFACTURER_NAME_UUID = "00002a29-0000-1000-8000-00805f9b34fb"
MODEL_NUMBER_UUID = "00002a24-0000-1000-8000-00805f9b34fb"

# Custom alert threshold characteristic (no pairing, no auth — intentional vuln)
ALERT_SERVICE_UUID = "0000ff00-0000-1000-8000-00805f9b34fb"
ALERT_THRESHOLD_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"

# ── Factory Provisioning Service (hidden — not advertised) ────────────────────
# VULNERABILITY P1: UUIDs are discoverable via GATT service discovery but NOT
# listed in the advertisement packet. Manufacturer claims this channel auto-
# disables after 30 minutes; in reality it never does (P8).
PROV_SERVICE_UUID     = "0000ff10-0000-1000-8000-00805f9b34fb"
PROV_CONFIG_UUID      = "0000ff11-0000-1000-8000-00805f9b34fb"
PROV_AUTH_UUID        = "0000ff12-0000-1000-8000-00805f9b34fb"
PROV_PIN_FACTORY      = "6767"

# Paths D-Bus
BUS_NAME = "org.bluez"
ADAPTER_PATH = "/org/bluez/hci0"
APP_PATH = "/org/careotter/app"

# Variables globales
# Shared vitals cache — updated by _vitals_refresh_loop(), read by all characteristics.
# All BLE notifications use this same snapshot so HR and SpO2 always match each other
# and match what the HTTP /vitals endpoint (and the cloud API) return.
latest_vitals = {"bpm": 72, "spo2": 98, "battery": 85}
_vitals_refresh_interval = 10   # seconds — mirrors sensor_service SNAPSHOT_INTERVAL
notifying_hr = False
notifying_spo2 = False
notifying_alert = False
connected_devices = {}  # MAC -> {name, connected_at}

# Alert thresholds — writable by any BLE client without auth (vulnerability #3)
alert_thresholds = {"bpm_min": 40, "bpm_max": 120, "spo2_min": 90}

# VULNERABILITY: derived value updated on each BLE write — no range validation
# If bpm_min >= bpm_max this becomes <= 0, triggering ZeroDivisionError in update_and_notify
_alert_bpm_window: float = float(
    alert_thresholds["bpm_max"] - alert_thresholds["bpm_min"]
)  # initial: 80.0 (120-40)

# Reference to the D-Bus message bus (set during main())
_system_bus = None

# Advertising registration state — populated in main() once the bus and the
# advertisement object path exist. Used by Release() and the connection
# monitor to re-register the advertisement automatically after BlueZ drops it
# (e.g. on client disconnect or on adapter power cycle).
_ad_bus = None
_ad_path = None
_ad_reregister_lock: Optional[asyncio.Lock] = None
# True when BlueZ currently holds a successful registration for our ad path.
# Cleared by Release() (BlueZ tore it down) and by any failed register call.
# Set by the next successful RegisterAdvertisement.
_ad_is_registered: bool = False


async def _ensure_advertisement_registered():
    """Register the LE advertisement against BlueZ — truly idempotent.

    Skips all D-Bus work if ``_ad_is_registered`` is already True. This keeps
    the periodic watchdog (every ``BLE_WATCHDOG_INTERVAL`` seconds) from
    bouncing a healthy advertisement, which on BCM4345C0 introduces a brief
    off-air window AND can rotate the LE Random Address — both of which
    cause scanners (bluetoothctl, Android, iOS) to lose sight of the
    peripheral or treat each rotation as a new device.

    BlueZ drops registrations under several conditions (peripheral connected
    on single-link chipsets, adapter power cycle, explicit Release()).
    Whenever any of those happen, ``_ad_is_registered`` is reset to False so
    that the next watchdog tick — or the explicit Release()/disconnect
    callbacks — performs an actual recovery.
    """
    global _ad_reregister_lock, _ad_is_registered
    if _ad_bus is None or _ad_path is None:
        return
    if _ad_reregister_lock is None:
        _ad_reregister_lock = asyncio.Lock()
    async with _ad_reregister_lock:
        if _ad_is_registered:
            return  # healthy — do not bounce the radio
        try:
            introspection = await _ad_bus.introspect(BUS_NAME, ADAPTER_PATH)
            manager_obj = _ad_bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
            ad_manager = manager_obj.get_interface("org.bluez.LEAdvertisingManager1")
            try:
                await ad_manager.call_register_advertisement(_ad_path, {})
                _ad_is_registered = True
                print("[BLE] Advertising registered")
                return
            except Exception as e:
                # AlreadyExists means BlueZ still has our registration from a
                # previous run — treat as success and stop touching the radio.
                if "AlreadyExists" in str(e) or "Already Exists" in str(e):
                    _ad_is_registered = True
                    print("[BLE] Advertising already registered in BlueZ (reused)")
                    return
                # Real failure — try a clean cycle (unregister + register) once.
                try:
                    await ad_manager.call_unregister_advertisement(_ad_path)
                except Exception:
                    pass
                await ad_manager.call_register_advertisement(_ad_path, {})
                _ad_is_registered = True
                print("[BLE] Advertising registered after cleanup")
        except Exception as e:
            _ad_is_registered = False
            print(f"[BLE] _ensure_advertisement_registered error: {e}")


# L1 watchdog — periodic self-healing of the LE advertisement.
#
# BlueZ only invokes Release() on the advertisement when *it* tears the
# registration down (client disconnect on single-link chipsets, adapter power
# cycle, explicit UnregisterAdvertisement). The Cypress BCM43430 firmware on
# the Pi 3B/4 occasionally stops emitting adverts on its own without notifying
# BlueZ — the controller stays UP, the bluetoothd process is happy, the
# ble_server.py process is happy, but no LE Advertising Report ever reaches a
# scanner. procd respawn cannot detect this (the process did not crash).
#
# This watchdog runs as a background asyncio task and re-registers the
# advertisement every BLE_WATCHDOG_INTERVAL seconds.  The re-registration is
# idempotent (unregister + register) and does not tear down any GATT
# connections that may already be established. A heartbeat file is written
# on every successful tick so the L3 external keepalive (cron) can detect
# total stack lock-ups that even D-Bus cannot recover from.
BLE_WATCHDOG_INTERVAL = int(os.getenv("BLE_WATCHDOG_INTERVAL", "60"))
BLE_HEARTBEAT_FILE   = os.getenv("BLE_HEARTBEAT_FILE", "/tmp/ble_advertising_heartbeat")


def _write_heartbeat():
    """Stamp the L1 heartbeat file with the current epoch second.

    The external L3 keepalive (cron) treats a missing or stale file as a
    signal to hard-reset the stack. We write the file from the very first
    moment the watchdog runs to prevent a race between the L1 warm-up
    window (BLE_WATCHDOG_INTERVAL) and the L3 cron tick (1 min)."""
    try:
        with open(BLE_HEARTBEAT_FILE, "w") as f:
            f.write(f"{int(time.time())}\n")
    except Exception as e:
        print(f"[BLE] heartbeat write failed: {e}")


async def _advertising_watchdog():
    """Re-register the LE advertisement on a fixed cadence and emit a
    heartbeat file. Survives transient D-Bus errors and adapter glitches."""
    print(f"[BLE] advertising watchdog armed (every {BLE_WATCHDOG_INTERVAL}s)")
    # Stamp the heartbeat right away so the L3 keepalive does not flap us
    # during the first BLE_WATCHDOG_INTERVAL seconds after process start.
    _write_heartbeat()
    while True:
        try:
            await asyncio.sleep(BLE_WATCHDOG_INTERVAL)
            await _ensure_advertisement_registered()
            _write_heartbeat()
        except asyncio.CancelledError:
            print("[BLE] advertising watchdog cancelled")
            raise
        except Exception as e:
            # Never let an exception kill the watchdog — log and continue.
            print(f"[BLE] advertising watchdog error: {e}")


def _schedule_advertisement_reregister():
    """Fire-and-forget the advertisement re-register coroutine from any context."""
    try:
        asyncio.ensure_future(_ensure_advertisement_registered())
    except RuntimeError:
        # No running event loop (server is tearing down) — nothing to do.
        pass

# ── Factory Provisioning state ────────────────────────────────────────────────
# VULNERABILITY P8: initialized_at marks the 30-minute "provisioning window",
# but the code never checks elapsed time — the channel stays open forever.


def _load_provisioning_state():
    """Load persisted provisioning state from disk, or return factory defaults."""
    defaults = {
        "authenticated": False,
        "pin_attempts": 0,
        "wifi_ssid": "",
        "wifi_psk": "",
        "cloud_url": CLOUD_API_URL,
        "patient_username": "",
        "patient_password": "",
        "admin_username": "",
        "admin_password": "",
        "initialized_at": time.time(),
    }
    try:
        with open(_PROVISION_FILE, "r") as f:
            data = json.load(f)
            defaults.update(data)
            print(f"[BLE] Loaded persisted provisioning state from {_PROVISION_FILE}")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[BLE] Error loading provisioning state: {e}")
    return defaults


def _save_provisioning_state():
    """Persist current provisioning state to disk so it survives restarts."""
    try:
        with open(_PROVISION_FILE, "w") as f:
            json.dump(_provisioning_state, f)
    except Exception as e:
        print(f"[BLE] Error saving provisioning state: {e}")


async def _send_registration_to_cloud():
    """Send the device's factory signature and configured accounts to the Cloud API.

    Triggered automatically after cloud_set, cloud_get, or any provisioning command
    that changes the cloud_url. Retries with backoff so the Cloud API can start
    after the Pi. VULNERABILITY: no TLS, no domain validation — any URL configured
    via cloud_set receives the secret signature and admin credentials.
    """
    url = _provisioning_state.get("cloud_url", "")
    if not url:
        print("[BLE] Registration skipped: no cloud_url configured")
        return

    # Gather registration payload
    payload = {
        "signature": DEVICE_SIGNATURE,
        "mac": _get_device_mac(),
        "patient": {
            "username": _provisioning_state.get("patient_username", ""),
            "password": _provisioning_state.get("patient_password", ""),
        },
        "admin": {
            "username": _provisioning_state.get("admin_username", ""),
            "password": _provisioning_state.get("admin_password", ""),
        },
        "device_ip": _get_wlan0_ip(),
    }

    register_url = f"{url.rstrip('/')}/admin/device/register"
    max_retries = 10
    delay = 3
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                register_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                response = json.loads(resp.read().decode())
                print(f"[BLE] Cloud registration OK (attempt {attempt}): {response}")
                return
        except Exception as e:
            print(f"[BLE] Cloud registration attempt {attempt}/{max_retries} failed: {e}")
        if attempt < max_retries:
            await asyncio.sleep(delay)
    print(f"[BLE] Cloud registration failed after {max_retries} attempts")


def _get_device_mac() -> str:
    """Return the eth0 MAC address, or a fallback string."""
    try:
        with open("/sys/class/net/eth0/address", "r") as f:
            return f.read().strip().upper()
    except Exception:
        return os.getenv("DEFAULT_DEVICE_MAC", "AA:BB:CC:DD:EE:FF")


_provisioning_state = _load_provisioning_state()


def _notify_characteristic(path: str, value_bytes: bytes):
    """Emit a genuine org.freedesktop.DBus.Properties.PropertiesChanged signal
    so that BlueZ forwards the notification to connected BLE clients."""
    if _system_bus is None:
        return
    try:
        msg = Message(
            message_type=MessageType.SIGNAL,
            interface="org.freedesktop.DBus.Properties",
            path=path,
            member="PropertiesChanged",
            signature="sa{sv}as",
            body=["org.bluez.GattCharacteristic1",
                  {"Value": Variant("ay", value_bytes)},
                  []]
        )
        _system_bus.send(msg)
    except Exception as e:
        print(f"[BLE] _notify_characteristic error: {e}")


def _refresh_vitals_cache():
    """Fetch one reading from the sensor and update latest_vitals.
    Called once at startup and then by _vitals_refresh_loop every 30s.
    """
    global latest_vitals
    try:
        with _sensor_http_get(SENSOR_URL, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            latest_vitals.update({
                "bpm":  data.get("bpm",  latest_vitals["bpm"]),
                "spo2": data.get("spo2", latest_vitals["spo2"]),
            })
            print(f"[BLE] Vitals cache updated: BPM={latest_vitals['bpm']} SpO2={latest_vitals['spo2']}")
    except Exception as e:
        print(f"[BLE] Error refreshing vitals cache: {e}")


async def _vitals_refresh_loop():
    """Refresh vitals cache aligned to the sensor's own snapshot timestamp.
    After each fetch, sleeps until response_timestamp + _vitals_refresh_interval
    so the next fetch arrives exactly when the sensor has a new snapshot ready.
    """
    while True:
        next_at = latest_vitals.get("timestamp", time.time()) + _vitals_refresh_interval
        delay = max(0.0, next_at - time.time())
        await asyncio.sleep(delay)
        _refresh_vitals_cache()


def fetch_vitals():
    """Return latest cached vitals — does NOT fetch from sensor (use cache only)."""
    pass   # cache is maintained by _vitals_refresh_loop; nothing to do here


class HeartRateMeasurementChrc(ServiceInterface):
    """Heart Rate Measurement Characteristic (0x2A37)"""
    
    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = HR_MEASUREMENT_UUID
        self.flags = ["notify", "read"]
        self.value = [0x06, 72]  # flags + BPM
        
    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid
    
    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service0"
    
    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags
    
    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return bytes(self.value)
    
    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        fetch_vitals()
        bpm = int(latest_vitals["bpm"])
        self.value = [0x06, bpm]
        return bytes(self.value)
    
    @method()
    def StartNotify(self):
        global notifying_hr
        notifying_hr = True
        print(f"[BLE] HR notifications enabled")
    
    @method()
    def StopNotify(self):
        global notifying_hr
        notifying_hr = False
        print(f"[BLE] HR notifications stopped")
    
    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}", invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]
    
    async def update_and_notify(self):
        """Update the value and send a notification if there are subscribers."""
        fetch_vitals()
        bpm = int(latest_vitals["bpm"])
        self.value = [0x06, bpm]

        if notifying_hr:
            try:
                _notify_characteristic(APP_PATH + "/service0/char0", bytes(self.value))
                print(f"[BLE] HR notification: {bpm} BPM")
            except Exception as e:
                print(f"[BLE] Error notificando HR: {e}")


class PulseOximeterChrc(ServiceInterface):
    """Pulse Oximeter Characteristic (0x2A5F)"""
    
    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = PLX_CONTINUOUS_UUID
        self.flags = ["notify", "read"]
        self.value = [0x03, 0x62, 0x00, 0x48, 0x00]  # flags (0x03=SpO2+PR uint16) + SpO2 + PR (little endian)
        
    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid
    
    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service1"
    
    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags
    
    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return bytes(self.value)
    
    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        fetch_vitals()
        spo2 = int(latest_vitals["spo2"])
        bpm = int(latest_vitals["bpm"])
        self.value = [0x03, spo2 & 0xFF, 0x00, bpm & 0xFF, 0x00]  # 0x03 = SpO2+PR uint16 (little endian)
        return bytes(self.value)
    
    @method()
    def StartNotify(self):
        global notifying_spo2
        notifying_spo2 = True
        print(f"[BLE] SpO2 notifications enabled")
    
    @method()
    def StopNotify(self):
        global notifying_spo2
        notifying_spo2 = False
        print(f"[BLE] SpO2 notifications stopped")
    
    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}", invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]
    
    async def update_and_notify(self):
        """Update the value and send a notification if there are subscribers."""
        fetch_vitals()
        spo2 = int(latest_vitals["spo2"])
        bpm = int(latest_vitals["bpm"])
        self.value = [0x03, spo2 & 0xFF, 0x00, bpm & 0xFF, 0x00]  # 0x03 = SpO2+PR uint16 (little endian)

        if notifying_spo2:
            try:
                _notify_characteristic(APP_PATH + "/service1/char0", bytes(self.value))
                print(f"[BLE] SpO2 notification: {spo2}%")
            except Exception as e:
                print(f"[BLE] Error notificando SpO2: {e}")


class BatteryLevelChrc(ServiceInterface):
    """Battery Level Characteristic (0x2A19)"""
    
    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = BATTERY_LEVEL_UUID
        self.flags = ["read"]
        self.value = [85]  # 85% battery
        
    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid
    
    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service2"
    
    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags
    
    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return bytes(self.value)
    
    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return bytes(self.value)


class ManufacturerNameChrc(ServiceInterface):
    """Device Information — Manufacturer Name (0x2A29)
    VULNERABILITY: leaks internal version string revealing Python + OpenWRT simulator"""

    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = MANUFACTURER_NAME_UUID
        self.flags = ["read"]

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service3"

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return b"CareOtter Medical v1.0"

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        # VULNERABILITY: leaks Python/OpenWRT internal info
        return b"CareOtter Medical v1.0 [Python/OpenWRT-sim]"


class ModelNumberChrc(ServiceInterface):
    """Device Information — Model Number (0x2A24)
    VULNERABILITY: reveals that MAX30102 is running in simulator mode"""

    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = MODEL_NUMBER_UUID
        self.flags = ["read"]

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service3"

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return b"MAX30102-SIM"

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return b"MAX30102-SIM"


class AlertThresholdChrc(ServiceInterface):
    """Custom alert threshold characteristic (0xFF01) — CSCP v1 (CareOtter Secure Config Protocol).

    READ + WRITE + NOTIFY — framed with AES-128-ECB + CRC32 "security".

    VULNERABILITY (M1 — Improper Credential Usage):
      CSCP_KEY is hardcoded in firmware and Android APK. Extracting either allows
      an attacker to forge valid 24-byte packets that the server accepts unconditionally.

    VULNERABILITY (M3 — Insecure Authentication/Authorization):
      Any BLE client (no pairing required) can write valid CSCP v1 packets.
      The "encryption" serves as serialisation format, not an authentication barrier.

    CSCP v1 packet layout (24 bytes, big-endian):
        [0:4]  Magic   — 0xCAFE0DDA
        [4:8]  CRC32   — crc32(ciphertext[8:24]) & 0xFFFFFFFF
        [8:24] Payload — AES-128-ECB(plaintext, key=CSCP_KEY)

    Plaintext block (16 bytes):
        [0]    bpm_min  (uint8)
        [1]    bpm_max  (uint8)
        [2]    spo2_min (uint8)
        [3:16] padding  (0x00)
    """

    # VULNERABILITY: hardcoded symmetric key — identical across all CareOtter devices
    CSCP_KEY   = b"careotter-key-16"   # 16 bytes AES-128
    CSCP_MAGIC = 0xCAFE0DDA

    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid  = ALERT_THRESHOLD_UUID
        self.flags = ["read", "write", "notify"]

    # ── CSCP v1 helpers ──────────────────────────────────────────────────────

    def _pack_and_encrypt(self, thresholds: dict) -> bytes:
        """Serialise thresholds to 24-byte CSCP v1 packet."""
        plaintext = struct.pack("BBB", thresholds["bpm_min"],
                                       thresholds["bpm_max"],
                                       thresholds["spo2_min"]) + b"\x00" * 13
        if _HAS_AES:
            cipher     = AES.new(self.CSCP_KEY, AES.MODE_ECB)
            ciphertext = cipher.encrypt(plaintext)
        else:
            ciphertext = plaintext   # fallback: no encryption (still exposes vuln structure)
        crc = binascii.crc32(ciphertext) & 0xFFFFFFFF
        return struct.pack(">II", self.CSCP_MAGIC, crc) + ciphertext

    def _decrypt_and_unpack(self, packet: bytes) -> Optional[dict]:
        """Parse and validate a 24-byte CSCP v1 packet. Returns None on error."""
        if len(packet) != 24:
            return None
        magic, crc = struct.unpack(">II", packet[:8])
        if magic != self.CSCP_MAGIC:
            return None
        ciphertext = packet[8:]
        if (binascii.crc32(ciphertext) & 0xFFFFFFFF) != crc:
            return None
        if _HAS_AES:
            cipher    = AES.new(self.CSCP_KEY, AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)
        else:
            plaintext = ciphertext
        bpm_min, bpm_max, spo2_min = struct.unpack("BBB", plaintext[:3])
        return {"bpm_min": bpm_min, "bpm_max": bpm_max, "spo2_min": spo2_min}

    # ── D-Bus properties ─────────────────────────────────────────────────────

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service4"

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return self._pack_and_encrypt(alert_thresholds)

    def _compute_alert_window(self) -> float:
        """Compute normalised position of current BPM within the alert window.

        VULNERABILITY: ZeroDivisionError when _alert_bpm_window == 0.
        Triggered if an attacker writes a valid CSCP v1 packet with bpm_min >= bpm_max.
        The key (CSCP_KEY) is hardcoded in firmware and APK — trivial to extract and forge.
        No exception handling — unhandled exception in the asyncio task kills the event loop task,
        stopping all BLE notifications permanently until the process is restarted manually.

        OWASP IoT I3 — Insecure Ecosystem Interface (writable without auth)
        OWASP IoT I7 — Insecure Data Transfer (no semantic validation of received data)
        """
        return (latest_vitals["bpm"] - alert_thresholds["bpm_min"]) / _alert_bpm_window

    # ── GATT operations ──────────────────────────────────────────────────────

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        pkt = self._pack_and_encrypt(alert_thresholds)
        print(f"[BLE] CSCP v1 ReadValue: {pkt.hex()} (thresholds={alert_thresholds})")
        return pkt

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        # VULNERABILITY (M3): no session authentication — any paired BLE client writes freely
        # VULNERABILITY (M1): key extracted from firmware/APK breaks "encryption" barrier
        raw = bytes(value)
        thresholds = self._decrypt_and_unpack(raw)
        if thresholds is None:
            print(f"[BLE] CSCP v1 WriteValue: rejected (bad magic/CRC/size) {raw.hex()}")
            return
        # VULNERABILITY: no clinical range validation — bpm_min=0, bpm_max=255, spo2_min=0 accepted
        alert_thresholds["bpm_min"]  = thresholds["bpm_min"]
        alert_thresholds["bpm_max"]  = thresholds["bpm_max"]
        alert_thresholds["spo2_min"] = thresholds["spo2_min"]
        # VULNERABILITY: _alert_bpm_window recomputed without validating bpm_max > bpm_min
        # An attacker sending bpm_min >= bpm_max produces window <= 0
        # Crash is DEFERRED — occurs in update_and_notify(), not here
        # This makes triage harder: WriteValue returns success but the service dies 2s later
        global _alert_bpm_window
        _alert_bpm_window = float(
            alert_thresholds["bpm_max"] - alert_thresholds["bpm_min"]
        )
        # Persist to shared file so sensor_service and careservice stay in sync
        try:
            with open("/var/log/careotter.thresholds", "w") as fh:
                fh.write(f"bpm_min={alert_thresholds['bpm_min']}\n")
                fh.write(f"bpm_max={alert_thresholds['bpm_max']}\n")
                fh.write(f"spo2_min={alert_thresholds['spo2_min']}\n")
        except OSError:
            pass
        print(f"[BLE] CSCP v1 thresholds updated: {alert_thresholds}")
        if notifying_alert:
            try:
                _notify_characteristic(APP_PATH + "/service4/char0",
                                       self._pack_and_encrypt(alert_thresholds))
            except Exception as e:
                print(f"[BLE] Error notificando AlertThreshold: {e}")

    @method()
    def StartNotify(self):
        global notifying_alert
        notifying_alert = True
        print("[BLE] AlertThreshold notifications enabled")

    @method()
    def StopNotify(self):
        global notifying_alert
        notifying_alert = False
        print("[BLE] AlertThreshold notifications stopped")

    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}", invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]

    async def update_and_notify(self):
        # VULNERABILITY: triggers ZeroDivisionError if _alert_bpm_window <= 0
        # This runs every 2s via update_loop() — crash occurs on the first cycle after a
        # malicious WriteValue, not immediately, giving the attacker plausible deniability
        _pct = self._compute_alert_window()
        if notifying_alert:
            try:
                _notify_characteristic(APP_PATH + "/service4/char0",
                                       self._pack_and_encrypt(alert_thresholds))
            except Exception as e:
                print(f"[BLE] Error notificando AlertThreshold: {e}")


class ProvisioningAuthChrc(ServiceInterface):
    """Factory Provisioning — Auth/PIN (0xFF12)

    VULNERABILITY P3: hardcoded 4-digit PIN ('6767'), never rotated across devices.
    VULNERABILITY: no rate limiting — brute force of 10.000 combinations is trivial.
    """

    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = PROV_AUTH_UUID
        self.flags = ["read", "write"]

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service5"

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        remaining = max(0, 3 - (_provisioning_state["pin_attempts"] % 3))
        locked = False
        return json.dumps({"attempts_remaining": remaining, "locked": locked}).encode()

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        # VULNERABILITY: leaks attempt-counter state to any connected client
        remaining = max(0, 3 - (_provisioning_state["pin_attempts"] % 3))
        locked = False  # P3: never locks out permanently
        return json.dumps({"attempts_remaining": remaining, "locked": locked}).encode()

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        pin = bytes(value).decode("utf-8", errors="ignore").strip()
        if pin == PROV_PIN_FACTORY:
            _provisioning_state["authenticated"] = True
            _provisioning_state["pin_attempts"] = 0
            print(f"[BLE] Provisioning AUTH success")
        else:
            _provisioning_state["pin_attempts"] += 1
            print(f"[BLE] Provisioning AUTH failed (PIN={pin}, attempts={_provisioning_state['pin_attempts']})")


class ProvisioningConfigChrc(ServiceInterface):
    """Factory Provisioning — Config (0xFF11)

    VULNERABILITY P4: shell injection via wifi_set — SSID/PSK interpolated into
    a system() call without escaping metacharacters.
    VULNERABILITY P5: ReadValue returns the current WiFi PSK in plaintext.
    VULNERABILITY P6: cloud_set accepts any URL without validation → SSRF.
    VULNERABILITY P7: factory_reset executes with a single write, no confirmation.
    VULNERABILITY P8: channel never auto-closes (initialized_at is recorded but
    never checked against current time).
    """

    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = PROV_CONFIG_UUID
        self.flags = ["read", "write", "notify"]

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return APP_PATH + "/service5"

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        # VULNERABILITY P5: plaintext WiFi PSK leak
        data = {
            "wifi_ssid": _provisioning_state["wifi_ssid"],
            "wifi_psk": _provisioning_state["wifi_psk"],
            "cloud_url": _provisioning_state["cloud_url"],
            "uptime_sec": int(time.time() - _provisioning_state["initialized_at"]),
            "provision_expired": False,  # P8: always False
        }
        return json.dumps(data).encode()

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        # Gate: same rule as WriteValue — no plaintext provisioning state
        # (wifi_ssid / wifi_psk / cloud_url) leaks before the PIN has been
        # verified on the AuthChrc (0xFF12). P5 (plaintext PSK storage) is
        # preserved: once the PIN gate is passed the PSK is still returned
        # in cleartext — same downgrade pattern as P4/P6/P7.
        if not _provisioning_state.get("authenticated", False):
            print("[BLE] Provisioning read rejected — PIN not verified")
            return json.dumps({"error": "PIN_REQUIRED"}).encode()
        return self.Value

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        # Gate: require a successful PIN write on the AuthChrc (0xFF12) before
        # accepting any provisioning command on the ConfigChrc (0xFF11).
        # NOTE: this closes the "command accepted without PIN" gap (P0 below),
        # but the surrounding lab vulnerabilities are kept intact on purpose:
        #   * P3 — hardcoded PIN "6767", identical across all devices.
        #   * P3 — no rate limiting / lockout: 10 000 PINs remain brute-forceable.
        #   * P8 — no temporal expiry: `authenticated=True` never auto-clears.
        if not _provisioning_state.get("authenticated", False):
            print("[BLE] Provisioning command rejected — PIN not verified")
            return
        try:
            cmd = json.loads(bytes(value).decode("utf-8", errors="ignore"))
        except Exception:
            print("[BLE] Provisioning: invalid JSON")
            return

        action = cmd.get("cmd")
        print(f"[BLE] Provisioning command: {action}")

        if action == "wifi_set":
            ssid = str(cmd.get("ssid", ""))
            psk  = str(cmd.get("psk", ""))
            # VULNERABILITY P4: direct shell interpolation — no escaping
            shell_cmd = (
                f"uci set wireless.@wifi-iface[0].ssid='{ssid}' && "
                f"uci set wireless.@wifi-iface[0].key='{psk}' && "
                f"uci commit wireless && wifi reload"
            )
            os.system(shell_cmd)
            _provisioning_state["wifi_ssid"] = ssid
            _provisioning_state["wifi_psk"] = psk
            _save_provisioning_state()
            print(f"[BLE] Provisioning WiFi configured: {ssid}")

        elif action == "wifi_get":
            # Nothing to do — ReadValue already leaks everything
            pass

        elif action == "cloud_set":
            url = str(cmd.get("url", ""))
            # VULNERABILITY P6: no URL validation → SSRF potential
            _provisioning_state["cloud_url"] = url
            _save_provisioning_state()
            print(f"[BLE] Provisioning Cloud URL configured: {url}")
            # Trigger async registration so the cloud learns our WiFi IP and accounts
            asyncio.create_task(_send_registration_to_cloud())

        elif action == "cloud_get":
            pass

        elif action == "patient_set":
            _provisioning_state["patient_username"] = str(cmd.get("username", ""))
            _provisioning_state["patient_password"] = str(cmd.get("password", ""))
            _save_provisioning_state()
            print(f"[BLE] Provisioning patient account configured: {_provisioning_state['patient_username']}")

        elif action == "admin_set":
            _provisioning_state["admin_username"] = str(cmd.get("username", ""))
            _provisioning_state["admin_password"] = str(cmd.get("password", ""))
            _save_provisioning_state()
            print(f"[BLE] Provisioning admin account configured: {_provisioning_state['admin_username']}")

        elif action == "factory_reset":
            # VULNERABILITY P7: no confirmation, no auth escalation
            os.system("rm -f /etc/config/wireless && cp /rom/etc/config/wireless /etc/config/wireless 2>/dev/null; uci commit wireless; wifi reload")
            _provisioning_state["wifi_ssid"] = ""
            _provisioning_state["wifi_psk"] = ""
            _provisioning_state["cloud_url"] = ""
            _provisioning_state["patient_username"] = ""
            _provisioning_state["patient_password"] = ""
            _provisioning_state["admin_username"] = ""
            _provisioning_state["admin_password"] = ""
            _save_provisioning_state()
            print("[BLE] Provisioning FACTORY RESET executed")

        elif action == "reboot":
            os.system("reboot")

        else:
            print(f"[BLE] Provisioning: unknown command '{action}'")

    @method()
    def StartNotify(self):
        print("[BLE] ProvisioningConfig notifications started")

    @method()
    def StopNotify(self):
        print("[BLE] ProvisioningConfig notifications stopped")

    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}", invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]


class GattService(ServiceInterface):
    """GATT service"""
    
    def __init__(self, uuid: str, primary: bool = True):
        super().__init__("org.bluez.GattService1")
        self.uuid = uuid
        self.primary = primary
        self.chrcs = []
        
    def add_characteristic(self, chrc_path: str):
        self.chrcs.append(chrc_path)
    
    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid
    
    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> "b":
        return self.primary
    
    @dbus_property(access=PropertyAccess.READ)
    def Characteristics(self) -> "ao":
        return self.chrcs


class Advertisement(ServiceInterface):
    """Advertising LE — peripheral only, BR/EDR Not Supported flag set.

    ManufacturerData embeds the Cloud API URL (CLOUD_API_URL env var).

    VULNERABILITY: any passive BLE scanner discovers the management API
    endpoint without connecting or authenticating — information disclosure.
    The URL is visible in nRF Connect, btmon, bleak ScanResult.metadata, etc.
    """

    def __init__(self):
        super().__init__("org.bluez.LEAdvertisement1")
        self.type = "peripheral"
        self.local_name = DEVICE_NAME
        self.service_uuids = [HR_SERVICE_UUID, PLX_SERVICE_UUID]
        self.flags = ["general-discoverable", "le-only"]
        self.includes: list[str] = []
        # Fixed advertising intervals (ms). Forces the controller to honour
        # one stable AdvA per advertising train instead of falling back to a
        # sentinel address (AA:AA:AA:AA:AA:AA on Cypress BCM43430).
        self.min_interval = 100
        self.max_interval = 200
        # Encode API URL as manufacturer-specific data:
        #   [Company ID 2 bytes LE] [URL bytes UTF-8]
        # BlueZ ManufacturerData dict maps company_id (uint16) -> Variant("ay", bytes)
        mfr_bytes = _build_mfr_payload(CLOUD_API_URL)
        self.manufacturer_data = {CAREOTTER_COMPANY_ID: Variant("ay", mfr_bytes)}
        import struct as _s
        api_ip = socket.inet_ntoa(mfr_bytes[0:4])
        api_port = _s.unpack(">H", mfr_bytes[4:6])[0]
        dev_ip = socket.inet_ntoa(mfr_bytes[6:10])
        print(f"[BLE] ManufacturerData (0x{CAREOTTER_COMPANY_ID:04X}): "
              f"api_wifi={api_ip}:{api_port} dev_wifi={dev_ip}")

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":
        return self.type

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":
        return self.local_name

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return self.service_uuids

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def ManufacturerData(self) -> "a{qv}":  # type: ignore[return]
        return self.manufacturer_data

    @dbus_property(access=PropertyAccess.READ)
    def Includes(self) -> "as":  # type: ignore[return]
        return self.includes

    @dbus_property(access=PropertyAccess.READ)
    def MinInterval(self) -> "u":
        return self.min_interval

    @dbus_property(access=PropertyAccess.READ)
    def MaxInterval(self) -> "u":
        return self.max_interval

    @method()
    def Release(self):
        # BlueZ calls Release() when it stops advertising on our behalf
        # (peripheral connection on single-link chipsets, adapter power cycle,
        # explicit UnregisterAdvertisement, …). Clear the cached "is
        # registered" flag so the idempotent helper actually performs the
        # re-registration on the next tick, then re-arm advertising so the
        # device stays discoverable to subsequent clients.
        global _ad_is_registered
        _ad_is_registered = False
        print("[BLE] Advertising released by BlueZ — reprogramming RegisterAdvertisement")
        _schedule_advertisement_reregister()


class ObjectManager(ServiceInterface):
    """ObjectManager para BlueZ"""
    
    def __init__(self):
        super().__init__("org.freedesktop.DBus.ObjectManager")
        self.objects = {}
        
    def add_object(self, path: str, interfaces: dict):
        self.objects[path] = interfaces
    
    @method()
    def GetManagedObjects(self) -> "a{oa{sa{sv}}}":
        return self.objects


def _force_random_static_address() -> None:
    """Program the controller's LE Random Static Address so every advertising
    train carries the same AdvA. Works around the Cypress BCM43430 firmware
    quirk that emits AA:AA:AA:AA:AA:AA as a sentinel when no Random Address
    has been set since the last reset.

    Uses the raw HCI command ``LE_Set_Random_Address`` (OGF 0x08, OCF 0x0005)
    via ``hcitool``, which does not contend with the bluetoothd mgmt socket
    (unlike ``btmgmt``, which deadlocks while bluetoothd is running).
    """
    import subprocess
    try:
        out = subprocess.check_output(["hciconfig", "hci0"], timeout=3).decode()
        # Line: "    BD Address: 43:45:C0:00:1F:AC  ACL MTU: ..."
        mac = next((tok for line in out.splitlines() if "BD Address:" in line
                    for tok in line.split() if ":" in tok and len(tok) == 17), None)
        if not mac:
            print("[BLE] could not parse BD Address from hciconfig")
            return
        # HCI expects MAC bytes LSB-first
        octets = list(reversed(mac.split(":")))
        cmd = ["hcitool", "-i", "hci0", "cmd", "0x08", "0x0005", *octets]
        subprocess.run(cmd, capture_output=True, timeout=3, check=False)
        print(f"[BLE] LE_Set_Random_Address → {mac}")
    except Exception as exc:
        print(f"[BLE] LE_Set_Random_Address failed: {exc!r}")


async def setup_adapter(bus: MessageBus):
    """Configure the Bluetooth adapter."""
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    adapter_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    adapter = adapter_obj.get_interface("org.bluez.Adapter1")

    # Use set_ methods for properties
    await adapter.set_alias(DEVICE_NAME)
    await adapter.set_powered(True)
    await adapter.set_discoverable(True)
    await adapter.set_pairable(False)  # BLE-only — BR/EDR pairing disabled

    # Pin the LE Random Address so the controller never falls back to the
    # AA:AA:AA:AA:AA:AA sentinel. Done AFTER the adapter is powered.
    _force_random_static_address()

    print(f"[BLE] Adapter configured: {DEVICE_NAME}")


async def register_app(bus: MessageBus):
    """Register the GATT application."""
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    manager_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    gatt_manager = manager_obj.get_interface("org.bluez.GattManager1")
    
    await gatt_manager.call_register_application(APP_PATH, {})
    print("[BLE] GATT application registered")


async def register_advertisement(bus: MessageBus, ad_path: str):
    """Register advertising."""
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    manager_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    ad_manager = manager_obj.get_interface("org.bluez.LEAdvertisingManager1")
    
    await ad_manager.call_register_advertisement(ad_path, {})
    print("[BLE] Advertising registered")


async def update_loop(hr_chrc: HeartRateMeasurementChrc, plx_chrc: PulseOximeterChrc,
                      alert_chrc: AlertThresholdChrc):
    """Value and notification update loop — 2s interval"""
    while True:
        await asyncio.sleep(2)
        await hr_chrc.update_and_notify()
        await plx_chrc.update_and_notify()
        await alert_chrc.update_and_notify()


def log_connection_event(event_type, name, mac):
    """Write BLE connection events to the log and file."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    msg = f"[BLE] {event_type}: {name} ({mac})"
    print(msg)
    try:
        with open("/tmp/ble_connections.log", "a") as f:
            f.write(f"{ts} {event_type} {name} {mac}\n")
    except Exception:
        pass


async def monitor_connections(bus: MessageBus):
    """Monitor BlueZ PropertiesChanged to detect connections and disconnections."""
    def on_message(msg):
        if msg.interface != "org.freedesktop.DBus.Properties" or msg.member != "PropertiesChanged":
            return
        if len(msg.body) < 2 or msg.body[0] != "org.bluez.Device1":
            return
        
        changed = msg.body[1]
        if "Connected" not in changed:
            return
        
        connected = changed["Connected"].value
        # Extract the MAC from the D-Bus path: /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX
        mac = msg.path.split("/")[-1].replace("dev_", "").replace("_", ":")
        
        # Try to obtain the device name from the changed dictionary
        name = changed.get("Name", Variant("s", "Unknown")).value if isinstance(changed.get("Name"), Variant) else "Unknown"
        
        if connected is True:
            connected_devices[mac] = {"name": name, "connected_at": time.time()}
            log_connection_event("CONNECTED", name, mac)
        else:
            info = connected_devices.pop(mac, {})
            log_connection_event("DISCONNECTED", info.get("name", name), mac)
            # BlueZ frequently stops advertising while a peripheral has an
            # active link. Re-arm RegisterAdvertisement so the device becomes
            # discoverable again to other clients without manual intervention.
            _schedule_advertisement_reregister()
    
    bus.add_message_handler(on_message)
    print("[BLE] Connection monitor started")


async def main():
    print("[BLE] Starting CareOtter BLE GATT Server")
    print("[BLE] Using dbus-fast for OpenWRT")
    
    # Configure the D-Bus environment
    if "DBUS_SYSTEM_BUS_ADDRESS" not in os.environ:
        os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/dbus/system_bus_socket"
    
    # Connect to the system D-Bus
    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        global _system_bus
        _system_bus = bus
        print(f"[BLE] Connected to D-Bus: {bus.unique_name}")
    except Exception as e:
        print(f"[BLE] Error connecting to D-Bus: {e}")
        sys.exit(1)
    
    # Create services
    hr_service    = GattService(HR_SERVICE_UUID)
    plx_service   = GattService(PLX_SERVICE_UUID)
    batt_service  = GattService(BATTERY_SERVICE_UUID)
    dev_service   = GattService(DEVINFO_SERVICE_UUID)
    alert_service = GattService(ALERT_SERVICE_UUID)
    prov_service  = GattService(PROV_SERVICE_UUID, primary=False)  # hidden secondary

    # Create characteristics
    hr_chrc     = HeartRateMeasurementChrc()
    plx_chrc    = PulseOximeterChrc()
    batt_chrc   = BatteryLevelChrc()
    mfr_chrc    = ManufacturerNameChrc()
    model_chrc  = ModelNumberChrc()
    alert_chrc  = AlertThresholdChrc()
    prov_cfg_chrc = ProvisioningConfigChrc()
    prov_auth_chrc = ProvisioningAuthChrc()

    # Create ObjectManager
    obj_manager = ObjectManager()

    # Export objects to the bus
    bus.export(APP_PATH, obj_manager)
    bus.export(APP_PATH + "/service0", hr_service)
    bus.export(APP_PATH + "/service1", plx_service)
    bus.export(APP_PATH + "/service2", batt_service)
    bus.export(APP_PATH + "/service3", dev_service)
    bus.export(APP_PATH + "/service4", alert_service)
    bus.export(APP_PATH + "/service5", prov_service)
    bus.export(APP_PATH + "/service0/char0", hr_chrc)
    bus.export(APP_PATH + "/service1/char0", plx_chrc)
    bus.export(APP_PATH + "/service2/char0", batt_chrc)
    bus.export(APP_PATH + "/service3/char0", mfr_chrc)
    bus.export(APP_PATH + "/service3/char1", model_chrc)
    bus.export(APP_PATH + "/service4/char0", alert_chrc)
    bus.export(APP_PATH + "/service5/char0", prov_cfg_chrc)
    bus.export(APP_PATH + "/service5/char1", prov_auth_chrc)

    # Associate characteristics with services
    hr_service.add_characteristic(APP_PATH + "/service0/char0")
    plx_service.add_characteristic(APP_PATH + "/service1/char0")
    batt_service.add_characteristic(APP_PATH + "/service2/char0")
    dev_service.add_characteristic(APP_PATH + "/service3/char0")
    dev_service.add_characteristic(APP_PATH + "/service3/char1")
    alert_service.add_characteristic(APP_PATH + "/service4/char0")
    prov_service.add_characteristic(APP_PATH + "/service5/char0")
    prov_service.add_characteristic(APP_PATH + "/service5/char1")

    # ── Register ALL exported objects in ObjectManager so BlueZ discovers them ──
    # BlueZ GattManager1.RegisterApplication() calls GetManagedObjects on APP_PATH
    # to build the local attribute database. If we return {}, services are invisible.
    def _add_svc(path: str, svc: GattService):
        obj_manager.add_object(path, {
            "org.bluez.GattService1": {
                "UUID": Variant("s", svc.uuid),
                "Primary": Variant("b", svc.primary),
                "Characteristics": Variant("ao", svc.chrcs),
            }
        })

    def _add_chrc(path: str, chrc: ServiceInterface):
        # Each characteristic class exposes UUID, Service, Flags, Value via D-Bus props
        obj_manager.add_object(path, {
            "org.bluez.GattCharacteristic1": {
                "UUID": Variant("s", chrc.uuid),
                "Service": Variant("o", chrc.Service),
                "Flags": Variant("as", chrc.flags),
                "Value": Variant("ay", chrc.Value),
            }
        })

    _add_svc(APP_PATH + "/service0", hr_service)
    _add_svc(APP_PATH + "/service1", plx_service)
    _add_svc(APP_PATH + "/service2", batt_service)
    _add_svc(APP_PATH + "/service3", dev_service)
    _add_svc(APP_PATH + "/service4", alert_service)
    _add_svc(APP_PATH + "/service5", prov_service)

    _add_chrc(APP_PATH + "/service0/char0", hr_chrc)
    _add_chrc(APP_PATH + "/service1/char0", plx_chrc)
    _add_chrc(APP_PATH + "/service2/char0", batt_chrc)
    _add_chrc(APP_PATH + "/service3/char0", mfr_chrc)
    _add_chrc(APP_PATH + "/service3/char1", model_chrc)
    _add_chrc(APP_PATH + "/service4/char0", alert_chrc)
    _add_chrc(APP_PATH + "/service5/char0", prov_cfg_chrc)
    _add_chrc(APP_PATH + "/service5/char1", prov_auth_chrc)

    # Create and export advertising
    ad = Advertisement()
    ad_path = "/org/careotter/advertisement0"
    bus.export(ad_path, ad)

    # Publish references so Release() and the connection monitor can re-register
    # the advertisement on demand (single source of truth for the BlueZ ad state).
    global _ad_bus, _ad_path
    _ad_bus = bus
    _ad_path = ad_path

    # Configure adapter
    await setup_adapter(bus)

    # Register GATT application
    await register_app(bus)

    # Register advertising
    await register_advertisement(bus, ad_path)

    print("[BLE] Server started successfully")
    print("[BLE] Services:")
    print(f"       - Heart Rate (0x180D):          {HR_MEASUREMENT_UUID}")
    print(f"       - Pulse Oximeter (0x1822):       {PLX_CONTINUOUS_UUID}")
    print(f"       - Battery (0x180F):              {BATTERY_LEVEL_UUID}")
    print(f"       - Device Information (0x180A):   {DEVINFO_SERVICE_UUID}")
    print(f"       - Alert Threshold (custom):      {ALERT_THRESHOLD_UUID}")
    print(f"       - Factory Provisioning (hidden): {PROV_SERVICE_UUID}  <-- NOT advertised")
    print("[BLE] Waiting for connections...")

    # Start connection monitor
    await monitor_connections(bus)
    
    # Fetch initial vitals so BLE characteristics have real values before first notify
    _refresh_vitals_cache()

    # Periodic vitals cache refresh (30s) — keeps BLE and HTTP /vitals in sync
    asyncio.create_task(_vitals_refresh_loop())

    # GATT notification update loop (2s)
    asyncio.create_task(update_loop(hr_chrc, plx_chrc, alert_chrc))

    # L1 self-healing — periodic LE advertisement refresh + heartbeat.
    # Fixes the "process alive but advertising stopped" Cypress quirk that
    # procd respawn cannot detect.
    asyncio.create_task(_advertising_watchdog())

    # Keep running
    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[BLE] Deteniendo servidor...")
    except Exception as e:
        print(f"[BLE] Error fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
