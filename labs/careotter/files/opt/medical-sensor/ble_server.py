#!/usr/bin/env python3
"""
BLE GATT Server para CareOtter - Usa dbus-fast para OpenWRT
Expone servicios de Heart Rate (0x180D) y Pulse Oximeter (0x1822)
"""

import asyncio
import json
import urllib.request
import os
import sys

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

# Paths D-Bus
BUS_NAME = "org.bluez"
ADAPTER_PATH = "/org/bluez/hci0"
APP_PATH = "/org/careotter/app"

# Variables globales
latest_vitals = {"bpm": 72, "spo2": 98, "battery": 85}
notifying_hr = False
notifying_spo2 = False


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


async def update_loop(hr_chrc: HeartRateMeasurementChrc, plx_chrc: PulseOximeterChrc):
    """Loop de actualización de valores y notificaciones"""
    while True:
        await asyncio.sleep(1)
        await hr_chrc.update_and_notify()
        await plx_chrc.update_and_notify()


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
    hr_service = GattService(HR_SERVICE_UUID)
    plx_service = GattService(PLX_SERVICE_UUID)
    batt_service = GattService(BATTERY_SERVICE_UUID)
    
    # Crear características
    hr_chrc = HeartRateMeasurementChrc()
    plx_chrc = PulseOximeterChrc()
    batt_chrc = BatteryLevelChrc()
    
    # Crear ObjectManager
    obj_manager = ObjectManager()
    
    # Exportar objetos al bus
    bus.export(APP_PATH, obj_manager)
    bus.export(APP_PATH + "/service0", hr_service)
    bus.export(APP_PATH + "/service1", plx_service)
    bus.export(APP_PATH + "/service2", batt_service)
    bus.export(APP_PATH + "/service0/char0", hr_chrc)
    bus.export(APP_PATH + "/service1/char0", plx_chrc)
    bus.export(APP_PATH + "/service2/char0", batt_chrc)
    
    # Asociar características a servicios
    hr_service.add_characteristic(APP_PATH + "/service0/char0")
    plx_service.add_characteristic(APP_PATH + "/service1/char0")
    batt_service.add_characteristic(APP_PATH + "/service2/char0")
    
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
    print(f"       - Heart Rate (0x180D): {HR_MEASUREMENT_UUID}")
    print(f"       - Pulse Oximeter (0x1822): {PLX_CONTINUOUS_UUID}")
    print(f"       - Battery (0x180F): {BATTERY_LEVEL_UUID}")
    print("[BLE] Esperando conexiones...")
    
    # Iniciar loop de actualización
    asyncio.create_task(update_loop(hr_chrc, plx_chrc))
    
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
