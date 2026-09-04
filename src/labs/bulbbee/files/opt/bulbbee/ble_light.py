#!/usr/bin/env python3
"""BulbBee BLE GATT lighting-control server (the Android app's channel).

BULB-A1 functional bring-up, no intentional weakness. Modeled on CareOtter's
ble_server.py (dbus-fast over the BlueZ system bus). This is a BLE front-end
over the localhost HTTP lighting service on :8082 (BULB-A0), which stays the
single owner of the ring and the lighting state, so there is never a second
writer to the SPI/ring.

GATT layout:
  Lighting Control service 0xFF30
    Control 0xFF31  (write, write-without-response, read)  JSON command,
                    mirrors the HTTP /set + /scene API
    State   0xFF32  (read, notify)                         JSON snapshot,
                    mirrors GET /state

The unauthenticated (no bonding) and unencrypted properties of this channel are
the later findings BULB-02 and BULB-03, not part of A1. Onboarding/provisioning
over BLE is BULB-01.
"""

import asyncio
import json
import os
import sys
import time
import urllib.request

# dbus-fast is present on the image (CareOtter depends on it). Guard the import
# so the pure command-translation logic (_plan_calls) can be unit-checked in an
# environment without dbus-fast, and so a missing dep degrades to a clean exit
# instead of a procd crash-loop. ponytail: stub is test scaffolding, not a fallback runtime.
try:
    from dbus_fast import Variant, BusType, Message, MessageType
    from dbus_fast.aio import MessageBus
    from dbus_fast.service import (ServiceInterface, method, signal,
                                   dbus_property, PropertyAccess)
    _HAS_DBUS = True
except ImportError:
    _HAS_DBUS = False

    class ServiceInterface:
        def __init__(self, *a, **k):
            pass

    def method(*a, **k):
        def deco(f):
            return f
        return deco

    signal = method
    dbus_property = method

    class PropertyAccess:
        READ = 0

    class Variant:
        def __init__(self, *a, **k):
            pass

CONFIG_PATH = os.environ.get("BULBBEE_CONFIG", "/opt/bulbbee/config.json")


def _load_config():
    cfg = {"http_port": 8082, "ble_name": "BulbBee", "ble_interval": 1}
    try:
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


_CFG = _load_config()
HTTP_PORT = int(_CFG.get("http_port", 8082))
BLE_NAME = str(_CFG.get("ble_name", "BulbBee"))
BLE_INTERVAL = int(os.environ.get("BLE_INTERVAL", _CFG.get("ble_interval", 1)))
# BULB-01: hardcoded factory pairing PIN, identical across every device.
PROV_PIN = str(_CFG.get("prov_pin", "8080"))
# BULB-SEC: secure-mode toggle (neutralizes the provisioning + storage findings).
SECURE = bool(_CFG.get("secure"))

LIGHT_SERVICE_UUID = "0000ff30-0000-1000-8000-00805f9b34fb"
CONTROL_CHAR_UUID = "0000ff31-0000-1000-8000-00805f9b34fb"
STATE_CHAR_UUID = "0000ff32-0000-1000-8000-00805f9b34fb"
# BULB-01: provisioning service (discoverable on connect but not advertised)
PROV_SERVICE_UUID = "0000ff40-0000-1000-8000-00805f9b34fb"
PROV_AUTH_UUID = "0000ff41-0000-1000-8000-00805f9b34fb"
PROV_CONFIG_UUID = "0000ff42-0000-1000-8000-00805f9b34fb"

APP_PATH = "/org/bulbbee/app"
BUS_NAME = "org.bluez"
ADAPTER_PATH = "/org/bluez/hci0"
SERVICE0 = APP_PATH + "/service0"
CONTROL_PATH = SERVICE0 + "/char0"
STATE_PATH = SERVICE0 + "/char1"
SERVICE1 = APP_PATH + "/service1"
PROV_AUTH_PATH = SERVICE1 + "/char0"
PROV_CONFIG_PATH = SERVICE1 + "/char1"
AD_PATH = "/org/bulbbee/advertisement0"
HEARTBEAT_FILE = "/tmp/bulbbee/ble_advertising_heartbeat"
PROV_STATE_FILE = "/tmp/bulbbee/provisioning.json"

_system_bus = None
_ad_bus = None
_ad_is_registered = False
_ad_reregister_lock = None
notifying_state = False

# BULB-01: provisioning state. authenticated never auto-clears, pin_attempts
# never locks out (no rate limiting), wifi_psk is stored in cleartext (read
# back by BULB-05).
_prov_state = {
    "authenticated": False,
    "pin_attempts": 0,
    "wifi_ssid": "",
    "wifi_psk": "",
    "cloud_url": "",
    "pair_token": "",
}


def _log(msg):
    print("[BLE] %s" % msg, flush=True)


# ── localhost HTTP bridge to the :8082 lighting service (single state owner) ──

def _get_state_bytes() -> bytes:
    try:
        with urllib.request.urlopen(
                "http://127.0.0.1:%d/state" % HTTP_PORT, timeout=2) as r:
            return r.read()
    except Exception as e:  # service not up yet, or transient — tolerate
        _log("state fetch failed (%s)" % e)
        return b"{}"


def _post(path: str, obj: dict):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (HTTP_PORT, path), data=data, method="POST")
    with urllib.request.urlopen(req, timeout=2) as r:
        return r.read()


def _plan_calls(command: dict):
    """Pure: map a control-characteristic JSON command to the HTTP calls it
    triggers. Returns a list of (path, payload). Unit-checkable without BLE."""
    calls = []
    setk = {k: command[k] for k in ("power", "brightness", "color") if k in command}
    if setk:
        calls.append(("/set", setk))
    if "scene" in command:
        calls.append(("/scene", {"scene": command["scene"]}))
    return calls


def _apply_command(command: dict):
    for path, payload in _plan_calls(command):
        try:
            _post(path, payload)
        except Exception as e:
            _log("command forward to %s failed (%s)" % (path, e))


# ── BULB-01: provisioning (unauthenticated onboarding) ──

def _load_prov_state():
    try:
        with open(PROV_STATE_FILE) as f:
            saved = json.load(f)
        for k in ("wifi_ssid", "wifi_psk", "cloud_url", "pair_token"):
            if k in saved:
                _prov_state[k] = saved[k]
    except (OSError, ValueError):
        pass


def _save_prov_state():
    try:
        os.makedirs(os.path.dirname(PROV_STATE_FILE), exist_ok=True)
        with open(PROV_STATE_FILE, "w") as f:
            json.dump({k: _prov_state[k] for k in
                       ("wifi_ssid", "wifi_psk", "cloud_url", "pair_token")}, f)
        if SECURE:                                  # BULB-05 fix: restrictive mode
            os.chmod(PROV_STATE_FILE, 0o600)
    except OSError:
        pass


def _wifi_set_argv(ssid: str, psk: str):
    """Pure: the uci argv sequence to point the station WiFi at (ssid, psk).
    A clean argv list, NOT a shell string, so BULB-01 is only the weak-auth
    finding, not command injection (that would be a separate finding)."""
    return [
        ["uci", "set", "wireless.@wifi-iface[0].ssid=%s" % ssid],
        ["uci", "set", "wireless.@wifi-iface[0].key=%s" % psk],
        ["uci", "commit", "wireless"],
        ["wifi", "reload"],
    ]


def _do_wifi_set(ssid: str, psk: str):
    import subprocess
    for argv in _wifi_set_argv(ssid, psk):
        try:
            subprocess.run(argv, capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError) as e:
            _log("wifi_set step %r failed (%s)" % (argv[:2], e))


def _prov_auth(pin: str) -> bool:
    """Check the factory PIN. Default (vulnerable): no lockout, the counter only
    climbs, the hardcoded PIN always works (BULB-01). Secure (BULB-SEC): lock out
    after 5 attempts and refuse the shared default PIN."""
    if SECURE:
        if _prov_state["pin_attempts"] >= 5:        # BULB-01 fix: lockout
            _log("Provisioning AUTH locked out")
            return False
        if pin == "8080":                           # BULB-01 fix: refuse the shared default
            _prov_state["pin_attempts"] += 1
            _log("Provisioning AUTH refused (default PIN not allowed in secure mode)")
            return False
    if pin == PROV_PIN:
        _prov_state["authenticated"] = True
        _prov_state["pin_attempts"] = 0
        _log("Provisioning AUTH success")
    else:
        _prov_state["pin_attempts"] += 1
        _log("Provisioning AUTH failed (attempts=%d)" % _prov_state["pin_attempts"])
    return _prov_state["authenticated"]


def _prov_apply(cmd: dict):
    """Handle a provisioning command, gated only by the (hardcoded) PIN."""
    if not _prov_state["authenticated"]:
        _log("Provisioning command rejected — PIN not verified")
        return
    action = cmd.get("cmd")
    if action == "wifi_set":
        ssid = str(cmd.get("ssid", ""))
        psk = str(cmd.get("psk", ""))
        _prov_state["wifi_ssid"] = ssid
        _prov_state["wifi_psk"] = psk
        _save_prov_state()
        _do_wifi_set(ssid, psk)
        _log("Provisioning wifi_set: %s" % ssid)
    elif action == "pair_set":
        _prov_state["pair_token"] = str(cmd.get("token", ""))
        _prov_state["cloud_url"] = str(cmd.get("cloud_url", ""))
        _save_prov_state()
        _log("Provisioning pair_set")
    else:
        _log("Provisioning: unknown cmd %r" % action)


def _prov_read() -> dict:
    """Read the provisioning state. PIN-gated, then returns the WiFi PSK in
    cleartext (that plaintext read is finding BULB-05)."""
    if not _prov_state["authenticated"]:
        return {"error": "PIN_REQUIRED"}
    if SECURE:                                       # BULB-05 fix: never return the PSK
        return {"wifi_ssid": _prov_state["wifi_ssid"], "cloud_url": _prov_state["cloud_url"]}
    return {
        "wifi_ssid": _prov_state["wifi_ssid"],
        "wifi_psk": _prov_state["wifi_psk"],
        "cloud_url": _prov_state["cloud_url"],
    }


# ── notifications (hand-emitted PropertiesChanged, as in CareOtter) ──

def _notify_characteristic(path: str, value_bytes: bytes):
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
                  []])
        _system_bus.send(msg)
    except Exception as e:
        _log("_notify_characteristic error: %s" % e)


# ── advertising self-healing (L1), mirrors CareOtter ──

def _write_heartbeat():
    try:
        os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(int(time.time())))
    except OSError:
        pass


async def _ensure_advertisement_registered():
    global _ad_reregister_lock, _ad_is_registered
    if _ad_bus is None:
        return
    if _ad_reregister_lock is None:
        _ad_reregister_lock = asyncio.Lock()
    async with _ad_reregister_lock:
        if _ad_is_registered:
            return
        try:
            introspection = await _ad_bus.introspect(BUS_NAME, ADAPTER_PATH)
            manager_obj = _ad_bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
            ad_manager = manager_obj.get_interface("org.bluez.LEAdvertisingManager1")
            try:
                await ad_manager.call_register_advertisement(AD_PATH, {})
                _ad_is_registered = True
                _log("Advertising registered")
            except Exception as e:
                if "AlreadyExists" in str(e):
                    _ad_is_registered = True
                    _log("Advertising already registered (reused)")
                else:
                    try:
                        await ad_manager.call_unregister_advertisement(AD_PATH)
                    except Exception:
                        pass
                    await ad_manager.call_register_advertisement(AD_PATH, {})
                    _ad_is_registered = True
                    _log("Advertising registered after cleanup")
        except Exception as e:
            _ad_is_registered = False
            _log("_ensure_advertisement_registered error: %s" % e)


def _schedule_advertisement_reregister():
    try:
        asyncio.ensure_future(_ensure_advertisement_registered())
    except Exception:
        pass


async def _advertising_watchdog():
    _write_heartbeat()
    _log("advertising watchdog armed")
    interval = max(10, int(os.environ.get("BLE_WATCHDOG_INTERVAL", 60)))
    while True:
        await asyncio.sleep(interval)
        await _ensure_advertisement_registered()
        _write_heartbeat()


async def _state_notify_loop():
    """Poll /state and notify subscribed centrals on change."""
    last = None
    while True:
        await asyncio.sleep(BLE_INTERVAL)
        if not notifying_state:
            continue
        cur = _get_state_bytes()
        if cur != last:
            last = cur
            _notify_characteristic(STATE_PATH, cur)


# ── GATT characteristics ──

class ControlChrc(ServiceInterface):
    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = CONTROL_CHAR_UUID
        self.flags = ["read", "write", "write-without-response"]

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return SERVICE0

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return _get_state_bytes()

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return _get_state_bytes()

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        raw = bytes(value)
        try:
            command = json.loads(raw.decode())
        except (ValueError, UnicodeDecodeError):
            _log("Control WriteValue: bad JSON %r" % raw[:64])
            return
        _log("Control WriteValue: %s" % command)
        _apply_command(command)
        if notifying_state:
            _notify_characteristic(STATE_PATH, _get_state_bytes())


class StateChrc(ServiceInterface):
    def __init__(self):
        super().__init__("org.bluez.GattCharacteristic1")
        self.uuid = STATE_CHAR_UUID
        self.flags = ["read", "notify"]

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self.uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return SERVICE0

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return _get_state_bytes()

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return _get_state_bytes()

    @method()
    def StartNotify(self):
        global notifying_state
        notifying_state = True
        _log("State notifications enabled")

    @method()
    def StopNotify(self):
        global notifying_state
        notifying_state = False
        _log("State notifications stopped")

    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}",
                          invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]


class ProvisioningAuthChrc(ServiceInterface):
    """BULB-01: factory pairing PIN (0xFF41).

    Weaknesses: the PIN is hardcoded and identical across devices, there is no
    rate limiting or lockout (the counter never locks), and the link is not
    bonded, so the PIN is the only gate and it is trivially brute-forced or
    extracted from the app.
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
        return SERVICE1

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return json.dumps({"locked": False}).encode()

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return json.dumps({"attempts": _prov_state["pin_attempts"],
                           "locked": False}).encode()

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        _prov_auth(bytes(value).decode("utf-8", errors="ignore").strip())


class ProvisioningConfigChrc(ServiceInterface):
    """BULB-01: provisioning commands (0xFF42), gated only by the hardcoded PIN.

    wifi_set reconfigures the station WiFi (a clean uci write, no shell), so an
    attacker in range re-provisions the bulb onto their network. ReadValue
    returns the stored WiFi PSK in cleartext once the PIN gate is passed (that
    plaintext read is finding BULB-05, referenced here as the chain).
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
        return SERVICE1

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return self.flags

    @dbus_property(access=PropertyAccess.READ)
    def Value(self) -> "ay":
        return json.dumps({"provisioned": bool(_prov_state["wifi_ssid"])}).encode()

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return json.dumps(_prov_read()).encode()

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        try:
            cmd = json.loads(bytes(value).decode("utf-8", errors="ignore"))
        except (ValueError, UnicodeDecodeError):
            _log("Provisioning: invalid JSON")
            return
        _prov_apply(cmd)

    @method()
    def StartNotify(self):
        pass

    @method()
    def StopNotify(self):
        pass

    @signal()
    def PropertiesChanged(self, interface: "s", changed: "a{sv}",
                          invalidated: "as") -> "sa{sv}as":
        return [interface, changed, invalidated]


class GattService(ServiceInterface):
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
    def __init__(self):
        super().__init__("org.bluez.LEAdvertisement1")
        self.type = "peripheral"
        self.local_name = BLE_NAME
        self.service_uuids = [LIGHT_SERVICE_UUID]
        self.flags = ["general-discoverable", "le-only"]
        self.includes = []
        self.min_interval = 100
        self.max_interval = 200

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
    def Includes(self) -> "as":
        return self.includes

    @dbus_property(access=PropertyAccess.READ)
    def MinInterval(self) -> "u":
        return self.min_interval

    @dbus_property(access=PropertyAccess.READ)
    def MaxInterval(self) -> "u":
        return self.max_interval

    @method()
    def Release(self):
        global _ad_is_registered
        _ad_is_registered = False
        _log("Advertising released by BlueZ — reprogramming")
        _schedule_advertisement_reregister()


class ObjectManager(ServiceInterface):
    def __init__(self):
        super().__init__("org.freedesktop.DBus.ObjectManager")
        self.objects = {}

    def add_object(self, path: str, interfaces: dict):
        self.objects[path] = interfaces

    @method()
    def GetManagedObjects(self) -> "a{oa{sa{sv}}}":
        return self.objects


def _force_random_static_address():
    """Pin the LE Random Static Address so the Cypress BCM43430 controller stops
    emitting the AA:AA:AA:AA:AA:AA sentinel. Same workaround as CareOtter."""
    import subprocess
    try:
        out = subprocess.check_output(["hciconfig", "hci0"], timeout=3).decode()
        mac = next((tok for line in out.splitlines() if "BD Address:" in line
                    for tok in line.split() if ":" in tok and len(tok) == 17), None)
        if not mac:
            return
        octets = list(reversed(mac.split(":")))
        subprocess.run(["hcitool", "-i", "hci0", "cmd", "0x08", "0x0005", *octets],
                       capture_output=True, timeout=3, check=False)
        _log("LE_Set_Random_Address -> %s" % mac)
    except Exception as e:
        _log("LE_Set_Random_Address failed: %r" % e)


async def setup_adapter(bus):
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    adapter_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    adapter = adapter_obj.get_interface("org.bluez.Adapter1")
    await adapter.set_alias(BLE_NAME)
    await adapter.set_powered(True)
    await adapter.set_discoverable(True)
    await adapter.set_pairable(False)
    _force_random_static_address()
    _log("Adapter configured: %s" % BLE_NAME)


async def register_app(bus):
    introspection = await bus.introspect(BUS_NAME, ADAPTER_PATH)
    manager_obj = bus.get_proxy_object(BUS_NAME, ADAPTER_PATH, introspection)
    gatt_manager = manager_obj.get_interface("org.bluez.GattManager1")
    await gatt_manager.call_register_application(APP_PATH, {})
    _log("GATT application registered")


async def main():
    _log("Starting BulbBee BLE GATT server (dbus-fast)")
    if not _HAS_DBUS:
        _log("dbus-fast not available — cannot start BLE server, exiting")
        sys.exit(1)

    os.environ.setdefault("DBUS_SYSTEM_BUS_ADDRESS",
                          "unix:path=/run/dbus/system_bus_socket")
    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        global _system_bus, _ad_bus
        _system_bus = bus
        _ad_bus = bus
        _log("Connected to D-Bus: %s" % bus.unique_name)
    except Exception as e:
        _log("Error connecting to D-Bus: %s" % e)
        sys.exit(1)

    _load_prov_state()
    light_service = GattService(LIGHT_SERVICE_UUID)
    control_chrc = ControlChrc()
    state_chrc = StateChrc()
    prov_service = GattService(PROV_SERVICE_UUID, primary=False)  # not advertised
    prov_auth_chrc = ProvisioningAuthChrc()
    prov_config_chrc = ProvisioningConfigChrc()
    obj_manager = ObjectManager()

    bus.export(APP_PATH, obj_manager)
    bus.export(SERVICE0, light_service)
    bus.export(CONTROL_PATH, control_chrc)
    bus.export(STATE_PATH, state_chrc)
    bus.export(SERVICE1, prov_service)
    bus.export(PROV_AUTH_PATH, prov_auth_chrc)
    bus.export(PROV_CONFIG_PATH, prov_config_chrc)

    light_service.add_characteristic(CONTROL_PATH)
    light_service.add_characteristic(STATE_PATH)
    prov_service.add_characteristic(PROV_AUTH_PATH)
    prov_service.add_characteristic(PROV_CONFIG_PATH)

    def _add_svc(path, svc):
        obj_manager.add_object(path, {"org.bluez.GattService1": {
            "UUID": Variant("s", svc.uuid),
            "Primary": Variant("b", svc.primary),
            "Characteristics": Variant("ao", svc.chrcs)}})

    def _add_chrc(path, chrc):
        obj_manager.add_object(path, {"org.bluez.GattCharacteristic1": {
            "UUID": Variant("s", chrc.uuid),
            "Service": Variant("o", chrc.Service),
            "Flags": Variant("as", chrc.flags),
            "Value": Variant("ay", chrc.Value)}})

    _add_svc(SERVICE0, light_service)
    _add_chrc(CONTROL_PATH, control_chrc)
    _add_chrc(STATE_PATH, state_chrc)
    _add_svc(SERVICE1, prov_service)
    _add_chrc(PROV_AUTH_PATH, prov_auth_chrc)
    _add_chrc(PROV_CONFIG_PATH, prov_config_chrc)

    ad = Advertisement()
    bus.export(AD_PATH, ad)

    await setup_adapter(bus)
    await register_app(bus)
    await _ensure_advertisement_registered()

    _log("Server started, advertising as '%s' (service %s)" % (BLE_NAME, LIGHT_SERVICE_UUID))
    asyncio.create_task(_state_notify_loop())
    asyncio.create_task(_advertising_watchdog())

    while True:
        await asyncio.sleep(1)


def _demo():
    # ponytail: one runnable check for the command-translation logic, no BLE
    assert _plan_calls({"scene": "rainbow"}) == [("/scene", {"scene": "rainbow"})]
    assert _plan_calls({"brightness": 200, "color": [1, 2, 3]}) == \
        [("/set", {"brightness": 200, "color": [1, 2, 3]})]
    both = _plan_calls({"power": True, "scene": "solid"})
    assert both == [("/set", {"power": True}), ("/scene", {"scene": "solid"})]
    assert _plan_calls({}) == []

    # BULB-01: wifi_set argv is a clean list (no shell), and the PIN gate has no lockout
    argv = _wifi_set_argv("evil-ap", "p@ss")
    assert argv[0] == ["uci", "set", "wireless.@wifi-iface[0].ssid=evil-ap"]
    assert ["wifi", "reload"] in argv
    _prov_state.update({"authenticated": False, "pin_attempts": 0,
                        "wifi_ssid": "", "wifi_psk": "", "cloud_url": "", "pair_token": ""})
    assert _prov_read() == {"error": "PIN_REQUIRED"}          # gated before auth
    for _ in range(20):
        assert _prov_auth("0000") is False                   # 20 wrong PINs
    assert _prov_state["pin_attempts"] == 20                  # counter climbs, never locks
    assert _prov_auth(PROV_PIN) is True                      # correct PIN still accepted
    _prov_apply({"cmd": "wifi_set", "ssid": "evil-ap", "psk": "p@ss"})
    assert _prov_state["wifi_ssid"] == "evil-ap" and _prov_state["wifi_psk"] == "p@ss"
    assert _prov_read()["wifi_psk"] == "p@ss"                # BULB-05 chain: PSK in cleartext
    print("ble_light self-check OK (_plan_calls + BULB-01 provisioning)")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selfcheck":
        _demo()
    else:
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            pass
