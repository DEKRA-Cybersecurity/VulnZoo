---
id: RC-CBL-006
title: RoutCoon Component List
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.5b
cra_annex: Annex VII
covers_checklist_rows: [14]
requirement_ids: []
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
supersedes: none
---

# RC-CBL-006 Component List

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-CBL-006 |
| Title | RoutCoon Component List |
| Version | 1.0 |
| Date | 2026-08-21 |
| Product | RoutCoon Home/Office WiFi Router |
| Manufacturer | RoutCoon Networks (fictional) |
| Standard clause | prEN 40000-1-2, 7.5b (Component List) |
| Related deliverables | RC-SBOM-007 (SBOM), RC-TPD-012 (third-party due diligence) |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose

This document is the maintained list of all components integrated into the RoutCoon product, including third-party software components and hardware components, as required by prEN 40000-1-2 clause 7.5b. It is the human-readable companion to the machine-readable software bill of materials RC-SBOM-007. Third-party component due diligence and support-period assessment are recorded separately in RC-TPD-012.

## 2. Scope and method

The software component inventory is derived from the RoutCoon build configuration at `labs/routcoon/.config` (312 selected packages on the OpenWrt 24.10.3 image feed) and confirmed against the running image banner. This document lists the top-level and security-relevant components. The complete package-level manifest, including transitive dependencies, is maintained in RC-SBOM-007 in CycloneDX format.

Component versions that are pinned or observable on the running image are stated. Where a version is resolved from the OpenWrt 24.10.3 package feed at build time and is not independently pinned, the version column records the feed baseline and the entry is confirmed against the built image before release.

## 3. Platform baseline

| Component | Version | Type | Supplier / origin | License (indicative) | Notes |
|-----------|---------|------|-------------------|----------------------|-------|
| OpenWrt | 24.10.3 (r28739-d9340319c6) | Operating system | OpenWrt project (FOSS) | GPL-2.0-only | Base firmware distribution |
| Linux kernel | 6.6 (6.6.x LTS) | Operating system kernel | kernel.org (FOSS) | GPL-2.0-only | armv7l, bcm27xx / bcm2709 |
| BusyBox | 1.36.1 | Userland utilities | BusyBox project (FOSS) | GPL-2.0-only | Provides telnetd, ftpd, tcpsvd, core utilities |

Base heritage: the RoutCoon software configuration derives from and extends the OWASP IoTGoat project. This provenance is recorded for licensing and due-diligence traceability.

## 4. Security-relevant software components

| Component                                                                                                                                                                                         | Version                 | Type          | Supplier / origin              | License (indicative) | Purpose in product                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------- | ------------------------------ | -------------------- | ---------------------------------------- |
| uhttpd (+ mod-ubus, mod-ucode)                                                                                                                                                                    | feed 24.10.3            | Application   | OpenWrt (FOSS)                 | ISC                  | HTTP server for the web admin            |
| LuCI (luci, luci-base, luci-light, mod-admin-full, mod-network, mod-status, mod-system, lua-runtime, lib-base/ip/jsonc/nixio, theme-bootstrap, app-firewall, app-package-manager, proto-ipv6/ppp) | feed 24.10.3            | Application   | OpenWrt LuCI (FOSS)            | Apache-2.0           | Web administration UI and internal API   |
| Dropbear                                                                                                                                                                                          | feed 24.10.3            | Application   | Matt Johnston (FOSS)           | MIT                  | SSH server (port 22)                     |
| dnsmasq                                                                                                                                                                                           | feed 24.10.3            | Application   | Simon Kelley (FOSS)            | GPL-2.0-only         | DHCP and DNS for LAN and WiFi            |
| Samba 4 (samba4-server, samba4-libs)                                                                                                                                                              | 4.18.8                  | Application   | Samba Team (FOSS)              | GPL-3.0-only         | SMB file sharing (port 445)              |
| miniupnpd (nftables)                                                                                                                                                                              | feed 24.10.3            | Application   | miniupnp project (FOSS)        | BSD-3-Clause         | UPnP IGD service                         |
| wpad-basic-mbedtls                                                                                                                                                                                | feed 24.10.3            | Application   | hostap / OpenWrt (FOSS)        | BSD-3-Clause         | WiFi AP authenticator and supplicant     |
| hostapd-common                                                                                                                                                                                    | feed 24.10.3            | Application   | hostap (FOSS)                  | BSD-3-Clause         | Shared hostapd configuration and helpers |
| net-snmp (snmpd)                                                                                                                                                                                  | feed 24.10.3 (declared) | Application   | Net-SNMP project (FOSS)        | Net-SNMP (BSD-like)  | SNMP agent, v1/v2c. See note 6.1         |
| libopenssl                                                                                                                                                                                        | feed 24.10.3            | Library       | OpenSSL project (FOSS)         | Apache-2.0           | TLS/crypto primitives                    |
| libustream-mbedtls                                                                                                                                                                                | feed 24.10.3            | Library       | OpenWrt / Mbed TLS (FOSS)      | Apache-2.0           | TLS stream layer                         |
| Mbed TLS (via wpad/ustream)                                                                                                                                                                       | feed 24.10.3            | Library       | Trusted Firmware (FOSS)        | Apache-2.0           | TLS backend for WiFi and ustream         |
| curl                                                                                                                                                                                              | feed 24.10.3            | Application   | curl project (FOSS)            | curl (MIT-style)     | HTTP client, used by device tooling      |
| wget-ssl                                                                                                                                                                                          | feed 24.10.3            | Application   | GNU (FOSS)                     | GPL-3.0-only         | HTTP(S) client                           |
| kmod-brcmfmac                                                                                                                                                                                     | feed 24.10.3            | Kernel module | Linux / Broadcom (FOSS driver) | GPL-2.0-only         | Broadcom WiFi driver                     |
| wireless-regdb                                                                                                                                                                                    | feed 24.10.3            | Data          | wireless-regdb (FOSS)          | ISC-style            | Wireless regulatory database             |

Application-level custom code integrated into the product (not third-party): `rshell.c` restricted login shell and the custom LuCI controllers (`network_tools.lua`, `support/remote.lua`, `iotgoat/iotgoat.lua`, modified `dispatcher.lua`). These are first-party components and are covered by RC-SAD-004 and RC-VVR-008 rather than by third-party due diligence.

## 5. Hardware components

| Component | Identifier | Type | Supplier / origin | Notes |
|-----------|-----------|------|-------------------|-------|
| Application processor | Broadcom BCM2837 (Pi 3B/3B+) | Hardware (SoC) | Raspberry Pi / Broadcom | ARM Cortex-A7 class target (bcm27xx/bcm2709 build) |
| Onboard WiFi | Broadcom BCM43430 / BCM43455 | Hardware (radio) | Broadcom | Driven by kmod-brcmfmac, firmware from wireless-regdb nvram |
| Storage | microSD card | Hardware (removable media) | commodity | Unencrypted root filesystem. See RC-RMR-001 |
| Debug interface | UART header | Hardware (interface) | Raspberry Pi | Exposed serial console. See RC-RMR-001 |

## 6. Notes

### 6.1 SNMP component status

net-snmp (snmpd) is listed as a shipped RoutCoon component because it is part of the documented product behaviour: the service configuration (`files/etc/snmp/snmpd.conf`), the provisioning hook (`80-routcoon-services.sh`), and the device documentation all treat SNMP v1/v2c with default communities as a running service. The corresponding packages are currently not selected in `labs/routcoon/.config`, so the SNMP entry is marked declared. Its version is confirmed against the running image before release, and this status is reconciled in RC-SBOM-007 and RC-TPD-012.

### 6.2 Version resolution

Versions marked "feed 24.10.3" are resolved from the OpenWrt 24.10.3 package feed at image build time. RC-SBOM-007 records the concrete versions observed on the built image. Where the two differ, the SBOM value is authoritative.

### 6.3 Maintenance

This list is maintained as a living document. It is reviewed and updated on each product change, dependency update, or feed baseline change, in line with RC-SCP-002 and the monitoring intervals in RC-VMP-010.
