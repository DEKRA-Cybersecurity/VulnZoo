---
id: IoT:I3
title: "Insecure Ecosystem Interfaces"
category: IoT
status: DONE
severity: High
owasp: "IoT I3 — Insecure Ecosystem Interfaces"
cwe: "CWE-345 (Insufficient Verification of Data Authenticity) / CWE-290 (Authentication Bypass by Spoofing) / CWE-294 (Authentication Bypass by Capture-replay) / CWE-319 (Cleartext Transmission of Sensitive Information)"
source_docs:
  - "CareOtter_API.md (Cloud API endpoints + Push Architecture)"
  - "CareOtter_IoT.md § Push Architecture & §IoT:I3 note"
  - "Vulns/API/API2,API5,API8,API9 + Vulns/IoT/IoT2 §2.4 (cross-referenced ecosystem cases)"
  - "CareOtter_App.md + Vulns/Mobile/M5_Insecure_Communication.md (mobile interface: rogue-device MITM → §A.7)"
affected_components:
  - "cloud_api/careotter/api_server/app.py — device_push_vitals / device_push_alerts"
  - "cloud_api/careotter/api_server/services/database_service.py — canonical_hash / adopt_mac_for_signature / EXPECTED_DEVICE_SIGNATURE"
  - "cloud_api/careotter/api_server/config.py — plaintext HTTP (no TLS)"
  - "labs/careotter/files/opt/medical-sensor/cloud_uploader.py — the device push client"
verified_date: ""
---

# IoT:I3 — Insecure Ecosystem Interfaces

> **Status:** DONE
> **OWASP:** IoT I3 — Insecure Ecosystem Interfaces
> **CWE:** CWE-345 / CWE-290 / CWE-294 / CWE-319
> **Severity:** High

---

## Why It Matters

OWASP IoT I3 covers the insecure web, backend API, cloud, or mobile interfaces in the ecosystem *outside* of the device that allow compromise of the device or its related components. The distinguishing test against I2 is location: I2 is a service running on the device itself, I3 is an interface that lives elsewhere in the ecosystem. For CareOtter the honest I3 surface is the Cloud API (`:5002`, Flask in Docker), its web UI and admin panel, the nginx edge in front of them, and the companion Android app — the mobile interface I3 explicitly names. None of it runs on the Raspberry Pi, and all of it can reach back to compromise the device, the patient's data, or the clinical dashboard.

One scoping note. OWASP IoT I3 and the OWASP API Security Top 10 describe the same cloud surface from two taxonomies, so almost every CareOtter `API-*` finding is simultaneously an I3 instance. This page does not re-file them. It is a lens that cross-references the cases whose ecosystem-interface flaw specifically reaches the device or the patient record, and it fully owns the one case that has no `API-*` home: forged device telemetry pushed into the cloud ingest endpoint (§3.1).

> The BLE-surface cases that used to be filed under `CareOtter_IoT.md` §IoT:I3 are *not* re-documented here. They were re-classified to on-device buckets because they live on the device's own radio: [[IoT6_Insufficient_Privacy_Protection]] (passive BLE leaks), [[IoT7_Insecure_Data_Transfer_and_Storage]] (CSCP threshold forging) and [[IoT2_Insecure_Network_Services]] §2.4 (hidden provisioning backdoor). The split is by which *end* of the BLE link the defect lives on. The device's GATT server is on-device, but the companion app's GATT *client* runs on the phone, unambiguously outside the device, so client-side flaws are the mobile interface I3 names (see §A.7). Device end is I2/I6/I7, mobile end is I3.

---

## The ecosystem-interface surface

| Interface | Where it runs | I3 failure | Home |
|-----------|---------------|------------|------|
| Cloud API control plane (`/api/config/thresholds`) | Docker `:5002` | Broken function-level authz forwards a patient command to the device | cross-ref → §A.1 |
| Cloud device-registration plane (`/admin/device/register`, `/api/devices/register-by-hash`) | Docker `:5002` | Trusts a fleet-wide factory signature, replayable to the real cloud | cross-ref → §A.2 |
| Cloud read plane + `/hint` + `/api/health` + `/api/network` | Docker `:5002` | Discloses device secrets and topology over the web interface | cross-ref → §A.3 |
| nginx reverse-proxy edge | Docker `:80` | ACL bypass exposes admin/debug/init endpoints externally | cross-ref → §A.4 |
| Cloud auth (JWT) | Docker `:5002` | Weak signing key forges admin tokens | cross-ref → §A.5 |
| Forgotten beta vhost (`beta.api.careotter.lab`) | Docker `:5002` | Missing rate-limit on password-reset OTP enables takeover | cross-ref → §A.6 |
| Companion mobile app (BLE GATT client) | Android phone | Authenticates the device by advertised name only — no pairing or MAC pinning — enabling rogue-device MITM | cross-ref → §A.7 |
| **Cloud device-ingest plane (`/api/device/vitals`, `/api/device/alerts`)** | **Docker `:5002`** | **Spoofable device authentication accepts forged telemetry** | **owned → §3.1** |

---

## A. Already-documented ecosystem-interface failures (cross-references)

These are implemented and written up under their primary OWASP-API home. They appear here because each is an interface outside the device whose failure reaches the device or its related components, which is exactly the I3 definition. The full reproduction steps live in the linked docs and are not duplicated.

### A.1 — Cloud-forwarded device control (BFLA threshold proxy)

`POST /api/config/thresholds` carries the wrong decorator (`@token_required` instead of `@admin_required`), so a low-privilege patient JWT reaches an admin-only function and the cloud proxies lethal thresholds to the device over IGP `0x08`. A backend-API authorization flaw on an interface outside the device becomes a device action. Primary home: [[API5_Broken_Function_Level_Authorization]] and [[IoT2_Insecure_Network_Services]] §2.2 (the device-side trust half).

### A.2 — Factory-signature replay to the real cloud (Chain F)

`/admin/device/register` and `/api/devices/register-by-hash` trust a hardcoded, fleet-wide 12-hex device signature. An attacker who captures it (over the BLE `cloud_set` redirect, off the device label, or by sniffing the plaintext push) replays it to the genuine Cloud API to register a rogue device or overwrite admin credentials. The registration interface is the I3 surface. Primary home: [[IoT2_Insecure_Network_Services]] §2.4 (Chain F) and `CareOtter_API.md` (`/admin/device/register`).

### A.3 — Device-secret disclosure over the cloud web interface

The Cloud API leaks device-related secrets through its web interface: `GET /api/network` returns the WiFi PSK in the `raw` field when `VULNERABLE=1`, `/hint` discloses the provisioning state (already tagged OWASP IoT I3 / CWE-200 in `CareOtter_API.md`), and `/api/health` exposes the device IP and MAC. The ecosystem interface discloses what should stay on the device, compromising a related component (the network). Primary home: `CareOtter_API.md` (Vulnerability Surface, High #5 and #6).

### A.4 — nginx edge ACL bypass

A trailing-slash discrepancy between the nginx exact-match deny and the slash-insensitive Flask app lets an external, unauthenticated client reach `db-debug`, `initialize_iot` and `admin` endpoints, from which device configuration can be pushed. The web edge in front of the ecosystem lacks correct authorization. Primary home: [[API8_Security_Misconfiguration]].

### A.5 — Weak JWT signing key

`JWT_SECRET = 'careotter_jwt_2026'` is a guessable, hardcoded signing key, so an attacker forges an admin token and drives every cloud-to-device admin command. Weak cryptography on the ecosystem interface yields device control. Primary home: [[API2_Broken_Authentication]].

### A.6 — Forgotten beta vhost OTP brute-force

`beta.api.careotter.lab` serves the password-reset OTP without the production vhost's rate limit, and the app has no attempt cap, so the 6-digit code is brute-forced to take over a patient account and reach that account's device data and control. A forgotten ecosystem interface is itself the I3 defect. Primary home: [[API9_Improper_Inventory_Management]].

### A.7 — Mobile interface authenticates the device by advertised name only (rogue-device MITM)

The companion Android app is the mobile interface I3 explicitly names, and its BLE client trusts the wrong thing. `BleMonitorClient.startScan()` auto-connects to the first peripheral advertising the name `CareOtter_HR`, with no pairing, no MAC pinning, and no check of the service UUIDs or manufacturer data (`CareOtter_App.md` VULN #1 / M4). An attacker who broadcasts the same name with a stronger signal becomes the peer the app talks to. A lack of authentication on an interface outside the device is the textbook I3 failure mode, and this is the cleanest instance of it in the lab — the app is unambiguously off-device.

On its own this yields a man-in-the-middle over the patient's vitals (a related component, captured in cleartext because the link is unencrypted) and device impersonation toward the app, where the rogue peripheral feeds fabricated BPM/SpO2 so the screen and the local alert banner show whatever the attacker chooses. It does not by itself compromise the bedside monitor. Reaching the genuine device additionally requires the fleet-wide CSCP key, which is statically extractable from the same APK and is already owned end to end by [[IoT7_Insecure_Data_Transfer_and_Storage]] (its §7.1 leads with the APK static-recon step and the `careotter-key-16` recovery, and its checklist verifies the key is recoverable from both the firmware and the APK). So the mobile interface contributes the missing-peer-authentication half here, and the APK key-leak half to IoT7. Primary home: [[M5_Insecure_Communication]] (Mobile M5 — Insecure Communication), which consolidates the rogue-device MITM with the missing-pairing (M3) and untrusted-name (M4) facets detailed in `CareOtter_App.md`.

> **Secondary / weaker I3 fit (considered, left in their API or Mobile home).** API7 SSRF (`/api/diagnostics` whitelist bypass → loopback admin → delete user) and API1 BOLA (`/api/caregiver/patient/<username>/vitals` cross-user read) are ecosystem-interface flaws too, but they compromise cloud users and patient data rather than the device, so they read more as pure-API findings than as I3 device-compromise. They stay under [[API7_Server_Side_Request_Forgery]] and [[API1_Broken_Object_Level_Authorization]]. On the mobile side, the app-local defects in `CareOtter_App.md` — the plaintext vitals log on `/sdcard` (M9, which overlaps I6 privacy more than I3), the hidden diagnostic panel (M8), the hardcoded default threshold *values* (M1), and the `allowBackup` / `FLAG_SECURE` gaps — never reach the device and stay under their Mobile M-IDs. The AdminActivity IGP auth-state race documented in that file is the device-side global-auth flaw (`CareOtter_IoT.md` §IoT:I7.2) in the separate `careotter_admin` app, not a defect of this BLE app's interface. All are listed here only for completeness.

---

## 3.1 — Forged device telemetry ingest (spoofable device authentication)

**Status:** DONE

In the push architecture the bedside monitor is the initiator: `cloud_uploader.py` on the Pi POSTs vitals and alerts to the Cloud API every ~10 s. The cloud ingest endpoints `POST /api/device/vitals` and `POST /api/device/alerts` are the interface that accepts that data. Their authentication is two request headers, `X-Device-MAC` and `X-Device-Hash`, and the only check is that the hash matches the stored factory signature for that MAC:

```python
# app.py — device_push_vitals()  (device_push_alerts is identical)
mac       = request.headers.get('X-Device-MAC', '').upper()
auth_hash = request.headers.get('X-Device-Hash', '')
data      = request.get_json(force=True, silent=True) or {}
...
candidate = DatabaseService.canonical_hash(auth_hash)
device    = db.get_device_by_mac(mac)
if not device:
    if db.adopt_mac_for_signature(auth_hash, mac):   # see escalation below
        device = db.get_device_by_mac(mac)
stored = (device or {}).get('auth_hash') or ''
if not device or not hmac.compare_digest(stored, candidate):
    return jsonify({'error': 'Invalid device credentials'}), 403

data['timestamp'] = time.time()        # cloud clock overwrites the Pi's
db.store_vitals(data, device_mac=mac)

global DEVICE_MAC                       # attacker-controlled header sets a process global
DEVICE_MAC = mac
```

The `hmac.compare_digest` is constant-time, so this is not a timing or a missing-auth bug. The defect is the credential model itself: the thing being verified is a static, low-entropy device signature, presented in a plaintext header, with no per-message signature, nonce, or session, on a channel with no transport encryption. Anyone who learns one valid `(MAC, signature)` pair can mint authentic-looking telemetry for that device indefinitely (CWE-345, CWE-290, CWE-294).

### Recovering a valid (MAC, signature) pair

The tightest path is on the ingest channel itself. The push runs over plaintext HTTP (the API ships no TLS, listed as "Plaintext HTTP, no TLS" in `CareOtter_API.md`), so a passive observer on the device-to-cloud path captures both headers and the body of a genuine push in one frame, then replays or forges from there (CWE-319). This folds the I3 weak-encryption clause into the same case: the interface protects a credential with no encryption and then trusts that credential as identity.

Two independent fallbacks exist if the attacker cannot sniff the link:

- The real Pi's signature is the fixed factory constant `9C0C306DEF2A` (`database_service.py::EXPECTED_DEVICE_SIGNATURE`, matched in `careservice.c` and `cloud_uploader.py`). It is the same code printed on the device label and the one the patient types into `register-by-hash`, recoverable independent of any single endpoint, including over IGP `0x10 GET_SIGNATURE`.
- On a freshly reset lab, `GET /initialize_iot` dumps the seeded demo rows including their `auth_hash` values. This is not a standing oracle: the endpoint returns `409` once the database is initialized, so it only helps before first setup.

### Forging telemetry

With a valid pair, the forged push is accepted and stored at the code-path level shown above:

```bash
# Replay/forge a vitals push for the real Pi (signature = factory constant).
# The MAC is whatever was observed on the plaintext push or from /api/health.
curl -s -X POST http://api.careotter.lab/api/device/vitals \
  -H 'Content-Type: application/json' \
  -H 'X-Device-MAC: B8:27:EB:79:53:C3' \
  -H 'X-Device-Hash: 9C0C306DEF2A' \
  -d '{"bpm": 72, "spo2": 99, "source": "simulator"}'
# {"status": "ok", "device_mac": "B8:27:EB:79:53:C3"}
```

Because the handler overwrites `data['timestamp']` with the server clock, every forged row lands inside the dashboard's "last 24 h" window and carries a current timestamp, so there is no stale-time tell that would distinguish a forgery from a live reading. The same headers against `/api/device/alerts` inject or suppress clinical alert events: a forged stream of normal vitals keeps a real bradycardia or desaturation off the clinician's screen, and a forged alert manufactures a false escalation.

### Escalation 1 — repointing the dashboard's active device

The handler assigns the attacker-controlled `X-Device-MAC` to the process-global `DEVICE_MAC`. The unauthenticated read plane uses that global as its default device:

```python
# app.py — get_vitals()  (no auth)
mac    = DEVICE_MAC
latest = db.get_latest_vitals(device_mac=mac)
```

So a single forged push repoints which device `/api/vitals` and the live dashboard serve from. If the forged push targets a different valid device row, the clinician view follows it to that device's data on the next poll. The cross-patient version of this requires a second valid `(MAC, signature)` pair, which the demo rows hand over verbatim on an uninitialized lab (see above).

### Escalation 2 — hijacking a placeholder device row

When the MAC is unknown, the handler calls `db.adopt_mac_for_signature(auth_hash, mac)` before failing. That UPDATE rewrites the device row's MAC to the attacker-supplied value, but only for rows whose MAC is still a placeholder:

```sql
UPDATE devices SET mac = ? WHERE auth_hash = ? AND mac IN ('00:00:00:00:00:00', '', '0')
```

If the real Pi's seed row still carries the placeholder `00:00:00:00:00:00` (which `initialize_iot` writes when `/health` is unreachable at seed time), an attacker who knows the fleet signature `9C0C306DEF2A` can push first with a MAC of their choosing and adopt the row, binding the device identity to an address they control. This path is closed the moment the genuine Pi pushes once, because the row then holds the real MAC and no longer matches the `WHERE` clause. It is an opportunistic race against first boot, not a standing primitive.

---

## How It Should Be

- **Authenticate the device, not a reusable secret.** Replace the static factory signature in a header with a per-device key established at provisioning and used to sign each push (HMAC over body + timestamp + MAC), so a captured frame cannot be replayed and a forged body fails verification.
- **Encrypt the ingest channel.** Terminate TLS on the cloud edge and require it for device pushes, so the credential and the telemetry are not sniffable on the path (closes CWE-319 and the capture-replay that follows).
- **Bind freshness.** Include a nonce or monotonic sequence per push and reject stale or out-of-order frames, instead of silently overwriting the timestamp with server time (which currently hides forgeries rather than detecting them).
- **Do not let an ingest header mutate global server state.** The active-device pointer must be derived from an authenticated session or an explicit operator selection, never from an attacker-controlled `X-Device-MAC` on an unauthenticated read plane.
- **Make row adoption an authenticated, one-time provisioning step.** Rewriting a device's MAC binding is an administrative action and must not be reachable from the public ingest path.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Ingest auth | Per-device signing key, HMAC each push over body+timestamp+MAC | Stop forged/replayed telemetry (CWE-345 / CWE-290 / CWE-294) |
| Transport | TLS on the device-to-cloud and client-to-cloud channels | Stop credential and data sniffing (CWE-319) |
| Anti-replay | Nonce or monotonic sequence per push, reject stale frames | Remove capture-replay and the timestamp-overwrite blind spot |
| Server state | Derive the active device from session/operator selection, not from a request header | Stop dashboard repointing by an ingest header |
| Provisioning | Gate `adopt_mac_for_signature` behind authenticated admin provisioning | Stop placeholder-row hijack from the public path |
| Cross-cutting | Apply A.1–A.6 remediations in their home docs (authz decorators, JWT secret, edge ACL, vhost inventory) | Close the ecosystem-interface paths that reach the device |

---

## Verification Checklist

- [ ] **§3.1 (forge)**: a `POST /api/device/vitals` with `X-Device-MAC` of a known device and `X-Device-Hash: 9C0C306DEF2A` returns `{"status":"ok"}` and the forged BPM/SpO2 appears on `/api/vitals` within one poll.
- [ ] **§3.1 (alerts)**: a `POST /api/device/alerts` with the same headers stores a fabricated alert event, and a sustained normal-vitals push keeps a real threshold breach off the dashboard.
- [ ] **§3.1 (no TLS)**: the push channel is plaintext HTTP — a `tcpdump`/proxy on the device-to-cloud path captures `X-Device-MAC` and `X-Device-Hash` in clear.
- [ ] **§3.1 (repoint)**: a forged push for a second valid device MAC flips `DEVICE_MAC`, and `/api/vitals` follows to that device on the next read.
- [ ] **§3.1 (adopt, conditional)**: against a Pi row still seeded with `00:00:00:00:00:00`, a push with the fleet signature and a new MAC rewrites the row's MAC, and a subsequent push from the real MAC then `403`s.
- [ ] **A cross-refs**: the linked `API-*` / IoT2 §2.4 checklists pass — each is the ecosystem-interface half of an I3 path.

---

## References

- `cloud_api/careotter/api_server/app.py` — `device_push_vitals` / `device_push_alerts` (the ingest endpoints) and `get_vitals` (the `DEVICE_MAC` read).
- `cloud_api/careotter/api_server/services/database_service.py` — `EXPECTED_DEVICE_SIGNATURE` (`9C0C306DEF2A`), `canonical_hash`, `adopt_mac_for_signature`.
- `cloud_api/careotter/api_server/config.py` — plaintext HTTP, no TLS termination.
- `labs/careotter/files/opt/medical-sensor/cloud_uploader.py` — the legitimate device push client whose headers are forged.
- `docs/CareOtter/API/CareOtter_API.md` — Push Architecture, the ingest contract, and the Vulnerability Surface table (the A cases).
- `docs/CareOtter/IoT/CareOtter_IoT.md` — § Push Architecture & Cron Hardening, and the §IoT:I3 re-classification note.
- Cross-referenced A cases: [[API5_Broken_Function_Level_Authorization]], [[API8_Security_Misconfiguration]], [[API2_Broken_Authentication]], [[API9_Improper_Inventory_Management]], [[IoT2_Insecure_Network_Services]] §2.4, with [[API7_Server_Side_Request_Forgery]] and [[API1_Broken_Object_Level_Authorization]] as secondary fits.
