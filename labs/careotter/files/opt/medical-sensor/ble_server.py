#!/usr/bin/env python3

import asyncio
import json
import urllib.request
import os
import sys
import time

from dbus_fast import Variant, BusType
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method, signal, dbus_property, PropertyAccess

# URLs y configuración
SENSOR_URL = "http://127.0.0.1:8081/vitals"
DEVICE_NAME = "CareOtter_HR"

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
                self.PropertiesChanged(
                    "org.bluez.GattCharacteristic1",
                    {"Value": Variant("ay", self.value)},
                    []
                )
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
                self.PropertiesChanged(
                    "org.bluez.GattCharacteristic1",
                    {"Value": Variant("ay", self.value)},
                    []
                )
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
    """Custom alert threshold characteristic (0xFF01).
    READ + WRITE + NOTIFY — no authentication required.
    VULNERABILITY: any BLE client can overwrite alarm thresholds."""

    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = ALERT_THRESHOLD_UUID
        self.flags = ["read", "write", "notify"]

    def _encode(self):
        return json.dumps(alert_thresholds).encode()

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
        return self._encode()

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return self._encode()

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        # VULNERABILITY: unauthenticated write — any BLE client can change thresholds
        try:
            data = json.loads(bytes(value).decode())
            if "bpm_min"  in data: alert_thresholds["bpm_min"]  = int(data["bpm_min"])
            if "bpm_max"  in data: alert_thresholds["bpm_max"]  = int(data["bpm_max"])
            if "spo2_min" in data: alert_thresholds["spo2_min"] = int(data["spo2_min"])
            print(f"[BLE] Alert thresholds updated: {alert_thresholds}")
        except Exception as e:
            print(f"[BLE] WriteValue error: {e}")

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
                self.PropertiesChanged(
                    "org.bluez.GattCharacteristic1",
                    {"Value": Variant("ay", self._encode())},
                    []
                )
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
    """Advertising LE"""
    
    def __init__(self):
        super().__init__("org.bluez.LEAdvertisement1")
        self.type = "peripheral"
        self.local_name = DEVICE_NAME
        self.service_uuids = [HR_SERVICE_UUID, PLX_SERVICE_UUID]
        self.discoverable = True
        
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
    def Discoverable(self) -> "b":
        return self.discoverable
    
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
    await adapter.set_pairable(True)
    
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
