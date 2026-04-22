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

# URLs y configuración
SENSOR_URL = "http://127.0.0.1:8081/vitals"
DEVICE_NAME = "CareOtter_HR"

# Cloud API address embedded in BLE advertising ManufacturerData (binary, 10 bytes):
#   [0:4]  Cloud API IPv4  big-endian  (e.g. 192.168.1.50)
#   [4:6]  Cloud API port  big-endian  (e.g. 5002)
#   [6:10] Device WiFi IP  big-endian  (wlan0, read at runtime)
#
# VULNERABILITY: passive BLE scan (no pairing, no auth) reveals both the
# cloud management endpoint and the device's WiFi address — information disclosure.
CLOUD_API_URL = os.getenv("CLOUD_API_URL", "http://192.168.2.2:5002")


def _fetch_api_wifi_ip(api_base_url: str) -> str:
    """Query the Cloud API /api/health over Ethernet to get its WiFi IP.
    Returns '0.0.0.0' if unreachable or not configured."""
    try:
        parsed = urlparse(api_base_url)
        health_url = f"{parsed.scheme}://{parsed.netloc}/api/health"
        with urllib.request.urlopen(health_url, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            ip = data.get("wifi_ip", "0.0.0.0")
            port = int(data.get("api_port", parsed.port or 5002))
            return ip, port
    except Exception as e:
        print(f"[BLE] Could not fetch API wifi_ip: {e}")
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

    The API WiFi IP is queried at startup so the Android app (WiFi-only)
    gets an address it can actually reach, not the Ethernet IP.
    """
    api_wifi_ip, api_port = _fetch_api_wifi_ip(api_url)
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

# UUIDs estándar Bluetooth SIG
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

# Paths D-Bus
BUS_NAME = "org.bluez"
ADAPTER_PATH = "/org/bluez/hci0"
APP_PATH = "/org/careotter/app"

# Variables globales
latest_vitals = {"bpm": 72, "spo2": 98, "battery": 85}
notifying_hr = False
notifying_spo2 = False
notifying_alert = False
connected_devices = {}  # MAC -> {name, connected_at}

# Alert thresholds — writable by any BLE client without auth (vulnerability #3)
alert_thresholds = {"bpm_min": 40, "bpm_max": 120, "spo2_min": 90}

# Reference to the D-Bus message bus (set during main())
_system_bus = None


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


def fetch_vitals():
    """Lee datos del sensor HTTP"""
    global latest_vitals
    try:
        with urllib.request.urlopen(SENSOR_URL, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            latest_vitals.update({
                "bpm": data.get("bpm", 72),
                "spo2": data.get("spo2", 98),
            })
    except Exception as e:
        print(f"[BLE] Error leyendo sensor: {e}")


class HeartRateMeasurementChrc(ServiceInterface):
    """Característica de Medición de Frecuencia Cardíaca (0x2A37)"""
    
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
        print(f"[BLE] Notificaciones HR activadas")
    
    @method()
    def StopNotify(self):
        global notifying_hr
        notifying_hr = False
        print(f"[BLE] Notificaciones HR detenidas")
    
    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}", invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]
    
    async def update_and_notify(self):
        """Actualiza valor y envía notificación si hay suscriptores"""
        fetch_vitals()
        bpm = int(latest_vitals["bpm"])
        self.value = [0x06, bpm]

        if notifying_hr:
            try:
                _notify_characteristic(APP_PATH + "/service0/char0", bytes(self.value))
                print(f"[BLE] Notificación HR: {bpm} BPM")
            except Exception as e:
                print(f"[BLE] Error notificando HR: {e}")


class PulseOximeterChrc(ServiceInterface):
    """Característica de Oxímetro de Pulso (0x2A5F)"""
    
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
        print(f"[BLE] Notificaciones SpO2 activadas")
    
    @method()
    def StopNotify(self):
        global notifying_spo2
        notifying_spo2 = False
        print(f"[BLE] Notificaciones SpO2 detenidas")
    
    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}", invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]
    
    async def update_and_notify(self):
        """Actualiza valor y envía notificación si hay suscriptores"""
        fetch_vitals()
        spo2 = int(latest_vitals["spo2"])
        bpm = int(latest_vitals["bpm"])
        self.value = [0x03, spo2 & 0xFF, 0x00, bpm & 0xFF, 0x00]  # 0x03 = SpO2+PR uint16 (little endian)

        if notifying_spo2:
            try:
                _notify_characteristic(APP_PATH + "/service1/char0", bytes(self.value))
                print(f"[BLE] Notificación SpO2: {spo2}%")
            except Exception as e:
                print(f"[BLE] Error notificando SpO2: {e}")


class BatteryLevelChrc(ServiceInterface):
    """Característica de Nivel de Batería (0x2A19)"""
    
    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = BATTERY_LEVEL_UUID
        self.flags = ["read"]
        self.value = [85]  # 85% batería
        
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
        print("[BLE] Notificaciones AlertThreshold activadas")

    @method()
    def StopNotify(self):
        global notifying_alert
        notifying_alert = False
        print("[BLE] Notificaciones AlertThreshold detenidas")

    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}", invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]

    async def update_and_notify(self):
        if notifying_alert:
            try:
                _notify_characteristic(APP_PATH + "/service4/char0",
                                       self._pack_and_encrypt(alert_thresholds))
            except Exception as e:
                print(f"[BLE] Error notificando AlertThreshold: {e}")


class GattService(ServiceInterface):
    """Servicio GATT"""
    
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

    @method()
    def Release(self):
        print("[BLE] Advertising liberado")


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


async def setup_adapter(bus: MessageBus):
    """Configura el adaptador Bluetooth"""
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    adapter_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    adapter = adapter_obj.get_interface("org.bluez.Adapter1")
    
    # Usar set_ methods para propiedades
    await adapter.set_alias(DEVICE_NAME)
    await adapter.set_powered(True)
    await adapter.set_discoverable(True)
    await adapter.set_pairable(False)  # BLE-only — BR/EDR pairing disabled
    
    print(f"[BLE] Adaptador configurado: {DEVICE_NAME}")


async def register_app(bus: MessageBus):
    """Registra la aplicación GATT"""
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    manager_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    gatt_manager = manager_obj.get_interface("org.bluez.GattManager1")
    
    await gatt_manager.call_register_application(APP_PATH, {})
    print("[BLE] Aplicación GATT registrada")


async def register_advertisement(bus: MessageBus, ad_path: str):
    """Registra el advertising"""
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    manager_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    ad_manager = manager_obj.get_interface("org.bluez.LEAdvertisingManager1")
    
    await ad_manager.call_register_advertisement(ad_path, {})
    print("[BLE] Advertising registrado")


async def update_loop(hr_chrc: HeartRateMeasurementChrc, plx_chrc: PulseOximeterChrc,
                      alert_chrc: AlertThresholdChrc):
    """Loop de actualización de valores y notificaciones — 2s interval"""
    while True:
        await asyncio.sleep(2)
        await hr_chrc.update_and_notify()
        await plx_chrc.update_and_notify()
        await alert_chrc.update_and_notify()


def log_connection_event(event_type, name, mac):
    """Escribe eventos de conexión BLE a log y archivo."""
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    msg = f"[BLE] {event_type}: {name} ({mac})"
    print(msg)
    try:
        with open("/tmp/ble_connections.log", "a") as f:
            f.write(f"{ts} {event_type} {name} {mac}\n")
    except Exception:
        pass


async def monitor_connections(bus: MessageBus):
    """Monitorea PropertiesChanged de BlueZ para detectar conexiones/disconexiones."""
    def on_message(msg):
        if msg.interface != "org.freedesktop.DBus.Properties" or msg.member != "PropertiesChanged":
            return
        if len(msg.body) < 2 or msg.body[0] != "org.bluez.Device1":
            return
        
        changed = msg.body[1]
        if "Connected" not in changed:
            return
        
        connected = changed["Connected"].value
        # Extraer MAC de la ruta D-Bus: /org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX
        mac = msg.path.split("/")[-1].replace("dev_", "").replace("_", ":")
        
        # Intentar obtener nombre del dispositivo del diccionario changed
        name = changed.get("Name", Variant("s", "Unknown")).value if isinstance(changed.get("Name"), Variant) else "Unknown"
        
        if connected is True:
            connected_devices[mac] = {"name": name, "connected_at": time.time()}
            log_connection_event("CONNECTED", name, mac)
        else:
            info = connected_devices.pop(mac, {})
            log_connection_event("DISCONNECTED", info.get("name", name), mac)
    
    bus.add_message_handler(on_message)
    print("[BLE] Connection monitor started")


async def main():
    print("[BLE] Iniciando CareOtter BLE GATT Server")
    print("[BLE] Usando dbus-fast para OpenWRT")
    
    # Configurar entorno D-Bus
    if "DBUS_SYSTEM_BUS_ADDRESS" not in os.environ:
        os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/dbus/system_bus_socket"
    
    # Conectar a D-Bus system
    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        global _system_bus
        _system_bus = bus
        print(f"[BLE] Conectado a D-Bus: {bus.unique_name}")
    except Exception as e:
        print(f"[BLE] Error conectando a D-Bus: {e}")
        sys.exit(1)
    
    # Crear servicios
    hr_service   = GattService(HR_SERVICE_UUID)
    plx_service  = GattService(PLX_SERVICE_UUID)
    batt_service = GattService(BATTERY_SERVICE_UUID)
    dev_service  = GattService(DEVINFO_SERVICE_UUID)
    alert_service = GattService(ALERT_SERVICE_UUID)

    # Crear características
    hr_chrc     = HeartRateMeasurementChrc()
    plx_chrc    = PulseOximeterChrc()
    batt_chrc   = BatteryLevelChrc()
    mfr_chrc    = ManufacturerNameChrc()
    model_chrc  = ModelNumberChrc()
    alert_chrc  = AlertThresholdChrc()

    # Crear ObjectManager
    obj_manager = ObjectManager()

    # Exportar objetos al bus
    bus.export(APP_PATH, obj_manager)
    bus.export(APP_PATH + "/service0", hr_service)
    bus.export(APP_PATH + "/service1", plx_service)
    bus.export(APP_PATH + "/service2", batt_service)
    bus.export(APP_PATH + "/service3", dev_service)
    bus.export(APP_PATH + "/service4", alert_service)
    bus.export(APP_PATH + "/service0/char0", hr_chrc)
    bus.export(APP_PATH + "/service1/char0", plx_chrc)
    bus.export(APP_PATH + "/service2/char0", batt_chrc)
    bus.export(APP_PATH + "/service3/char0", mfr_chrc)
    bus.export(APP_PATH + "/service3/char1", model_chrc)
    bus.export(APP_PATH + "/service4/char0", alert_chrc)

    # Asociar características a servicios
    hr_service.add_characteristic(APP_PATH + "/service0/char0")
    plx_service.add_characteristic(APP_PATH + "/service1/char0")
    batt_service.add_characteristic(APP_PATH + "/service2/char0")
    dev_service.add_characteristic(APP_PATH + "/service3/char0")
    dev_service.add_characteristic(APP_PATH + "/service3/char1")
    alert_service.add_characteristic(APP_PATH + "/service4/char0")

    # Crear y exportar advertising
    ad = Advertisement()
    ad_path = "/org/careotter/advertisement0"
    bus.export(ad_path, ad)

    # Configurar adaptador
    await setup_adapter(bus)

    # Registrar aplicación GATT
    await register_app(bus)

    # Registrar advertising
    await register_advertisement(bus, ad_path)

    print("[BLE] Servidor iniciado correctamente")
    print("[BLE] Servicios:")
    print(f"       - Heart Rate (0x180D):          {HR_MEASUREMENT_UUID}")
    print(f"       - Pulse Oximeter (0x1822):       {PLX_CONTINUOUS_UUID}")
    print(f"       - Battery (0x180F):              {BATTERY_LEVEL_UUID}")
    print(f"       - Device Information (0x180A):   {DEVINFO_SERVICE_UUID}")
    print(f"       - Alert Threshold (custom):      {ALERT_THRESHOLD_UUID}")
    print("[BLE] Esperando conexiones...")

    # Iniciar monitor de conexiones
    await monitor_connections(bus)
    
    # Iniciar loop de actualización (2s)
    asyncio.create_task(update_loop(hr_chrc, plx_chrc, alert_chrc))
    
    # Mantener corriendo
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
