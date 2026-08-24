---
id: ROUTCOON-CRA-ASSESSOR-KEY
title: RoutCoon CRA Assessor Gap Key (training answer key)
category: Training
status: DONE
standard: prEN 40000-1-2
audience: trainer / assessor only
version: 1
date: 2026-08-21
---

# RoutCoon CRA Assessor Gap Key

> **This document is NOT part of the manufacturer dossier. It is the trainer and assessor answer key. It lists the intentional discrepancies between what the RoutCoon CRA documentation claims and what the product actually does. Do not ship it with the dossier and do not give it to trainees before the exercise. The manufacturer documents (RC-*) are written in character and contain no such annotations by design.**

## 1. Purpose and use

The RoutCoon dossier follows the intermediate framing: a plausible, internally consistent manufacturer submission whose claims diverge from the live product. The assessor's task is to verify each claim against the running device and the source overlay and to find the divergences. This key is the reference set of those divergences so the exercise can be graded.

Three kinds of gap are seeded:

- **Claimed-but-absent control.** The dossier asserts a control the product does not have. Found by testing the claim.
- **Weakly-accepted risk.** The risk report acknowledges a real risk but accepts it on a thin justification. Found by challenging the acceptance rationale in RC-RMR-001 section 6.4.5.
- **Silent omission.** A real, testable weakness that does not appear anywhere in the dossier. Found only by testing the product, not by reading the paperwork.

Evidence paths are relative to `src/labs/routcoon/`. Catalogue references point to the RoutCoon vulnerability docs under `src/docs/RoutCoon/`.

## 2. Table A. Claimed-but-absent controls

| # | Dossier claim | Location | Product reality | Evidence | Catalogue |
|---|---------------|----------|-----------------|----------|-----------|
| A-01 | Web administration is served over TLS | RC-SAD-004 s.4 (control), RC-SRS-003 SR-06 | Admin served over plain HTTP on port 80, no TLS | uhttpd on :80, no TLS listener | IoT7 |
| A-02 | All administrative interfaces require an authenticated session before any privileged operation | RC-SAD-004 s.4/s.5, SR-01, SR-14 | Privileged LuCI handlers run with `sysauth=false`, and `api/v1/*` endpoints are unauthenticated | `files/usr/lib/lua/luci/dispatcher.lua`, `.../controller/network_tools.lua` | API5 |
| A-03 | The default administration password must be changed on first use | RC-SAD-004 s.4/s.6, SR-02 | Credentials are hardcoded and fixed, no first-use change is enforced | `files/usr/lib/vulnzoo-hooks/profile-init.d/11-add-users.sh` | IoT1 |
| A-04 | Authentication enforces rate limiting and lockout, session tokens use a secure random source | RC-SAD-004 s.4, SR-03, SR-04 | No rate limiting or lockout, weak session token from `sys.uniqueid(16)` | `.../dispatcher.lua`, `.../model/cbi/admin_system/admin.lua` | API2 |
| A-05 | Password change requires the current password | RC-SAD-004 s.4, SR-05 | Password can be changed without supplying the old password | `.../model/cbi/admin_system/admin.lua` | API2 |
| A-06 | Firmware and packages are verified for authenticity before install, network-staged artifacts are not auto-executed | RC-SAD-004 s.4, SR-15, SR-16 | Package signature verification disabled, and a root cron auto-executes files staged over anonymous FTP | `files/etc/opkg.conf:5` (`option check_signature 0`), `files/etc/crontabs/root:1` (`*/3 ... auto-updater.sh`), `files/opt/oem-updates/scripts/auto-updater.sh` | IoT4 |
| A-07 | UPnP, SNMP and anonymous file sharing are disabled by default | RC-SAD-004 s.4/s.6, SR-08, SR-10, SR-11, SR-19 | All three are enabled: UPnP `secure_mode 0`, SNMP `rocommunity public` / `rwcommunity private`, anonymous SMB share | `files/etc/config/upnpd:5`, `files/etc/snmp/snmpd.conf:1-2`, `files/etc/samba/samba.conf` | IoT2, IoT6 |
| A-08 | The SMB share is read-only by default and requires authentication for write access | RC-SAD-004 s.4, SR-09 | `[public]` share is world-writable with `guest ok = yes` and `force user = root` | `files/etc/samba/samba.conf` | IoT2 |
| A-09 | The wireless network has no shared default passphrase in operation | RC-SAD-004 s.4, SR-07 | Ships and runs with a shared default WPA2 passphrase `password123` | `files/usr/lib/vulnzoo-hooks/profile-init.d/88-routcoon-wifi-ap.sh:20` | IoT1 |
| A-10 | Network tool endpoints validate input against an allowlist and reject local and file schemes | RC-SAD-004 s.4/s.5, SR-12 | SSRF: `api/v1/check` reads `file://`, `api/v1/status` fetches an attacker-controlled `internal_url` | `.../controller/network_tools.lua` | API7 |
| A-11 | Diagnostic functions do not invoke a shell with user input | RC-SAD-004 s.4/s.5, SR-13 | OS command injection in the ping/diagnostic handler | `.../controller/admin/network.lua` (`diag_ping`) | API8 |
| A-12 | Production units ship with debug interfaces disabled | RC-SAD-004 s.4/s.6, SR-20 | No secure boot, unencrypted microSD root filesystem, exposed UART console | hardware, documented under IoT10 | IoT10 |
| A-13 | No diagnostic, debug or maintenance interfaces are exposed on production firmware, no undocumented administrative interfaces | RC-SAD-004 s.5/s.6, SR-19 | See all silent omissions in Table C, most directly the hidden root telnet | `files/usr/lib/vulnzoo-hooks/profile-init.d/50-ttylogin.sh:28` | IoT2, API9 |

## 3. Table B. Weakly-accepted risks

These risks are disclosed in RC-RMR-001 but accepted on a justification an assessor should reject.

| Threat | Accepted justification (RC-RMR-001 s.6.4.5) | Why the justification fails |
|--------|---------------------------------------------|-----------------------------|
| T-01 Hardcoded credentials | "The user changes them on first use" | The product does not enforce a change, one account is a system account, and the WiFi PSK is a fixed shared secret. The mitigation is not actually available to the user. |
| T-02 Cleartext admin HTTP | "Administration is only from the trusted wired LAN" | Administration is reachable over the WiFi segment as well, all services bind on all interfaces, and there is no control enforcing LAN-only administration. |
| T-07 No firmware update authenticity | "Updates are infrequent and delivered over the local network" | Authenticity is a state-of-the-art baseline for the CRA, signature verification is explicitly disabled, and the local delivery path is itself anonymous and writable. |
| T-14 No device management controls | "State of the art for the segment" | No logging, monitoring, or lockout is below the CRA baseline for this product class, and it directly enables the accepted authentication risks. |
| T-15 Insufficient physical hardening | "Physical access is outside the operational threat model" | The device is a consumer product with an unencrypted removable microSD and an exposed UART, a foreseeable exposure that the acceptance dismisses without analysis. |

## 4. Table C. Silent omissions

Real, testable weaknesses that appear nowhere in the dossier. The assessor finds these only by testing the product. Each should have appeared in the RC-RMR-001 threat register and been reflected in RC-SAD-004.

| # | Finding | Evidence | Catalogue | Where it should have appeared |
|---|---------|----------|-----------|-------------------------------|
| C-01 | Hidden Telnet on port 5515 giving an unauthenticated root shell | `files/usr/lib/vulnzoo-hooks/profile-init.d/50-ttylogin.sh:28` (`telnetd -p 5515 -l /bin/sh`) | IoT2 | RMR threat register, SAD s.5 attack surface |
| C-02 | IoTGoat `webcmd` root console | `.../controller/iotgoat/iotgoat.lua` | API8 | RMR threat register, SAD s.5 |
| C-03 | Unauthenticated SSH public-key injection via a spoofable forwarded client IP | `.../controller/support/remote.lua` | IoT5 | RMR threat register, SAD s.4 authentication |
| C-04 | Leftover debug and support endpoints, including a `?debug=1` environment dump | `.../dispatcher.lua`, `.../controller/support/`, `.../controller/iotgoat/` | API9 | RMR threat register, SAD s.6 inventory of interfaces |
| C-05 | Ecosystem interface disclosure through response-size differences | `.../dispatcher.lua` | IoT3 | RMR threat register |
| C-06 | Restricted shell bypass via `awk` | `rshell.c`, the `openwrtuser` account | IoT9 | RMR threat register, SAD s.4 |

## 5. Table D. False verification verdicts

RC-VVR-008 section 4 records a Pass verdict for every requirement SR-01 to SR-20. None of the Fail verdicts below were raised. This table is the reconciliation of the claimed verdicts against the actual product behaviour, cross-referenced to Table A.

| Requirement | RC-VVR-008 verdict | Actual result | Ref |
|-------------|--------------------|---------------|-----|
| SR-01 Authentication on admin interfaces | Pass | Fail: API and hidden telnet bypass authentication | A-02, A-13 |
| SR-02 First-use credential change | Pass | Fail: no first-use change is enforced | A-03 |
| SR-03 Rate limiting and lockout | Pass | Fail: no rate limiting or lockout | A-04 |
| SR-04 Strong session tokens | Pass | Fail: weak session token | A-04 |
| SR-05 Current password on change | Pass | Fail: password change without the old password | A-05 |
| SR-06 Administration over TLS | Pass | Fail: plain HTTP, no TLS | A-01 |
| SR-07 Wireless, no shared default | Pass | Partial: WPA2 present but a shared default passphrase is in use | A-09 |
| SR-08 Attack-surface minimisation | Pass | Fail: UPnP, SNMP, and anonymous SMB are all enabled | A-07 |
| SR-09 SMB read-only by default | Pass | Fail: the share is world-writable | A-08 |
| SR-10 UPnP disabled by default | Pass | Fail: UPnP enabled with secure_mode 0 | A-07 |
| SR-11 SNMP disabled by default | Pass | Fail: SNMP enabled with default communities | A-07 |
| SR-12 Tool input allowlist | Pass | Fail: SSRF present | A-10 |
| SR-13 Safe diagnostic execution | Pass | Fail: command injection present | A-11 |
| SR-14 Function-level authorisation | Pass | Fail: broken function-level authorisation | A-02 |
| SR-15 Update authenticity | Pass | Fail: signature verification disabled | A-06 |
| SR-16 No auto-execution of staged artifacts | Pass | Fail: root cron auto-executes staged files | A-06 |
| SR-17 Data minimisation | Pass | Fail: SNMP discloses network and personal records | A-07 |
| SR-18 Security logging | Pass | Weak: no security-relevant logging or monitoring | Table B, T-14 |
| SR-19 Secure defaults, no undocumented interfaces | Pass | Fail: anonymous services and hidden interfaces present | A-07, A-13, Table C |
| SR-20 Storage and debug hardening | Pass | Fail: unencrypted storage, exposed UART | A-12 |

## 6. Cross-reference to the checklist

The gaps above are what an assessor records against the prEN 40000-1-2 checklist rows. Table A undermines the 7.4 architecture claims (row 12) and the 7.6 verification claims (row 19, RC-VVR-008). Table B undermines the 6.4.5 evaluation and 6.5 treatment (rows 6 and 7). Table C undermines the 6.4.3 threat identification completeness (row 4) and the 7.5b/7.5c component-and-interface inventory (rows 14 and 15). RC-VVR-008 is the document where an honest verification would surface Table A and Table C, so it is the primary place to look for the divergence between claimed and tested behaviour.
