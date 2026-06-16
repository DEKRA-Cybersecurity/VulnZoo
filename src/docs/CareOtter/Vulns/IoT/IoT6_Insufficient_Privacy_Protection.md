---
id: IoT:I6
title: "Insufficient Privacy Protection"
category: IoT
status: DONE
severity: Medium
owasp: "IoT I6 — Insufficient Privacy Protection"
cwe: "CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) / CWE-497 (Exposure of Sensitive System Information to an Unauthorized Control Sphere)"
source_docs:
  - "CareOtter_IoT.md §IoT:I3 §3.1 + §3.2 (migrated and re-classified)"
affected_components:
  - "labs/careotter/files/opt/medical-sensor/ble_server.py"
verified_date: ""
---

# IoT:I6 — Insufficient Privacy Protection

> **Status:** DONE
> **OWASP:** IoT I6 — Insufficient Privacy Protection
> **CWE:** CWE-200 / CWE-497
> **Severity:** Medium

---

## Why It Matters

The CareOtter bedside monitor advertises continuously over BLE and answers GATT reads from any device in range, with no pairing and no authentication. OWASP IoT I6 is about a device or its ecosystem disclosing information that should stay private. Before an attacker sends a single write, this monitor already hands a passive listener two things it should never broadcast: the address of the backend that holds the patient's clinical data, and a precise fingerprint of its own software stack.

Neither leak is patient PII on its own, but both are disclosed without the patient's knowledge or consent to anyone within Bluetooth range of the home, and both are pure reconnaissance that shortens every other attack on the BLE surface (the unauthenticated threshold write in [[IoT7_Insecure_Data_Transfer_and_Storage]] and the hidden provisioning backdoor in [[IoT2_Insecure_Network_Services]] §2.4).

> These two cases were originally written as part of `CareOtter_IoT.md` §IoT:I3. They are re-filed here under I6 because the defect is the device disclosing information over its own interface, not an insecure interface *outside* the device.

---

## 6.1 — BLE ManufacturerData leaks the Cloud API address (passive, no connection)

The BLE advertising payload (Company ID `0x08D4`) encodes the Cloud API IP and port plus the device WiFi IP in a 10-byte binary field that any passive scanner reads without pairing or even connecting:

```
Bytes [0:4]  → Cloud API IPv4
Bytes [4:6]  → Cloud API port
Bytes [6:10] → Device WiFi IPv4
```

Using nRF Connect or any BLE sniffer, an attacker in Bluetooth range discovers the management API endpoint before performing any active attack:

```
nRF Connect → CareOtter_HR → RAW AD → Manufacturer Specific (0x08D4)
→ c0 a8 01 62 13 8a c0 a8 02 01
→ API: 192.168.1.98:5002  Device: 192.168.2.1
```

The broadcast is passive-readable, so there is no log on the device and nothing for the patient to notice. It reveals where the patient's vitals are sent (the backend) and that the monitor is reachable on the home WiFi at a known address — the map an attacker needs before touching anything.

**Maps to:** CWE-200 (Exposure of Sensitive Information). Originally `CareOtter_IoT.md` §3.1.

---

## 6.2 — Device Information GATT characteristics leak the software stack

The standard Device Information service exposes manufacturer and model characteristics that disclose the internal implementation to any connected client:

- **Manufacturer Name (`0x2A29`)** returns the Python version and the OpenWRT platform string.
- **Model Number (`0x2A24`)** returns `MAX30102-SIM`, revealing that the device is running the sensor in **simulation mode**.

This lets an attacker fingerprint the exact software stack and target known vulnerabilities, and the `-SIM` suffix confirms the unit is a lab or simulated build rather than production hardware — useful triage for an attacker deciding how the device will behave under attack.

**Maps to:** CWE-200 / CWE-497 (Exposure of Sensitive System Information). Originally `CareOtter_IoT.md` §3.2.

---

## How It Should Be

- **Do not broadcast backend topology.** The advertising payload should carry only what pairing and connection setup require, never the Cloud API address or the device's own IP. A provisioned device knows its backend internally and has no reason to announce it to the neighbourhood.
- **Minimise GATT metadata.** The Device Information service should expose a stable, non-revealing model string and must not leak interpreter versions, platform strings, or a `-SIM` build marker.
- **Gate reads behind pairing.** Even non-sensitive characteristics should require an encrypted, paired connection so that casual enumeration from range is not free.
- **Treat infrastructure detail as sensitive.** Backend addresses and stack fingerprints carry reconnaissance value — apply the same data-minimisation to them as to patient data.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| BLE advertising | Strip the Cloud API IP/port and the device IP from ManufacturerData | Stop passive backend disclosure (CWE-200) |
| BLE GATT | Return a non-revealing Model/Manufacturer string, drop the `-SIM` marker | Stop stack fingerprinting (CWE-497) |
| Access | Require LE Secure Connections + pairing before any characteristic read | Remove free enumeration from range |
| Data governance | Classify backend addresses and build metadata as sensitive | Apply data-minimisation consistently |

---

## Verification Checklist

- [ ] **§6.1**: a passive BLE sniff (nRF Connect RAW AD, or `btmon`) on `CareOtter_HR` shows Manufacturer Specific data `0x08D4` decoding to the Cloud API IP:port and the device IP, captured without connecting or pairing.
- [ ] **§6.2**: after `connect`, reading `0x2A29` returns a Python/OpenWRT string and `0x2A24` returns `MAX30102-SIM`.
- [ ] Neither read produces an entry in the device log (the disclosure is silent).

---

## References

- Migrated and re-classified from `docs/CareOtter/IoT/CareOtter_IoT.md` §IoT:I3 (§3.1 ManufacturerData leak, §3.2 Device Information leak).
- `labs/careotter/files/opt/medical-sensor/ble_server.py` — the BLE advertisement payload and the Device Information characteristics.
- Related BLE-surface cases: [[IoT7_Insecure_Data_Transfer_and_Storage]] (§3.3 CSCP threshold forging), [[IoT2_Insecure_Network_Services]] §2.4 (hidden provisioning backdoor).
