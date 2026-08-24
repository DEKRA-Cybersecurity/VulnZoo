---
id: RC-SAD-004
title: RoutCoon Cybersecurity Architecture and Design
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.4
cra_annex: Annex VII
covers_checklist_rows: [12]
requirement_ids: [CLA-03-RQ-01, CLA-03-RQ-02]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
---

# RC-SAD-004 Cybersecurity Architecture and Design

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-SAD-004 |
| Title | RoutCoon Cybersecurity Architecture and Design |
| Version | 1.0 |
| Date | 2026-08-21 |
| Product | RoutCoon Home/Office WiFi Router, firmware 1.0 |
| Standard clause | prEN 40000-1-2, 7.4 (CLA-03) |
| Related deliverables | RC-SRS-003, RC-RMR-001, RC-VVR-008, RC-TPD-012 |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose

This document specifies the cybersecurity architecture and design of RoutCoon as required by prEN 40000-1-2 clause 7.4. It records the trust boundaries, the selected cybersecurity controls that fulfil the requirements in RC-SRS-003 (CLA-03-RQ-01), the secure interface design, the secure-by-default configuration, and how cybersecurity is maintained through component integration (CLA-03-RQ-02).

## 2. Architecture overview

RoutCoon runs OpenWrt 24.10.3 on a single-board platform with one physical network interface. The interface carries the wired LAN, and an onboard radio provides the wireless LAN. The administration plane consists of the web UI and internal API (uhttpd and LuCI) and the SSH service (Dropbear). The network services are the DHCP and DNS server (dnsmasq), the file share (Samba), the UPnP IGD service (miniupnpd), and the SNMP agent (net-snmp). Packet filtering is provided by the firewall (nftables via luci-app-firewall). Component versions and origins are in RC-CBL-006 and RC-SBOM-007.

## 3. Trust boundaries

| Boundary | Description | Controls at the boundary |
|----------|-------------|--------------------------|
| Wired LAN | 192.168.2.0/24, device at 192.168.2.1 | Firewall input policy, authenticated administration |
| Wireless LAN | 192.168.3.0/24, device at 192.168.3.1 | WPA2 link-layer encryption, firewall, authenticated administration |
| Management plane | Web UI, API, SSH | Session authentication and authorisation |
| Physical device | Board, storage, debug headers | Production configuration with debug interfaces disabled |

There is no RDPS and no remote management plane. The product does not expose a distinct WAN interface.

## 4. Selected cybersecurity controls (CLA-03-RQ-01)

The controls below are selected to fulfil the requirements in RC-SRS-003. Each control references the requirement it satisfies.

| Control | Design | Fulfils |
|---------|--------|---------|
| Administration authentication | The web UI, API, and SSH require an authenticated session before any privileged operation | SR-01, SR-14 |
| First-use credential change | Setup forces a change of the default administration password before the interface is usable | SR-02 |
| Authentication hardening | The login path applies rate limiting and temporary lockout, and session tokens use a cryptographically secure random source | SR-03, SR-04 |
| Credential change protection | Password changes require the current password | SR-05 |
| Administration transport encryption | The web administration interface is served over TLS | SR-06 |
| Wireless protection | The radio uses WPA2 with a passphrase set by the user during setup, with no shared default passphrase in operation | SR-07 |
| Attack-surface minimisation | Only services required for the intended purpose are enabled by default, and UPnP, SNMP, and anonymous file sharing are disabled by default | SR-08, SR-10, SR-11, SR-19 |
| File-share protection | The SMB share is read-only by default and requires authentication for write access | SR-09 |
| Input validation on tools | Network tool endpoints validate input against an allowlist and reject local and file URL schemes | SR-12 |
| Safe diagnostic execution | Diagnostic functions use safe argument passing and do not invoke a shell with user input | SR-13 |
| Update authenticity | Firmware images and packages are verified for authenticity and integrity before installation, and network-staged artifacts are not executed without verification | SR-15, SR-16 |
| Data minimisation | DHCP and DNS records are retained only as needed for operation and are not exposed without authentication | SR-17 |
| Security logging | Security-relevant events are recorded in an administrator-visible log | SR-18 |
| Storage and debug hardening | Production units ship with debug interfaces disabled and consider confidentiality of stored secrets | SR-20 |

## 5. Secure interface design

Authentication is enforced at every administrative interface before any state-changing or information-disclosing operation. Input received from the network is validated at the interface boundary, with allowlisting for tool and diagnostic endpoints. The attack surface is minimised by shipping only the services required for the intended purpose and by binding management interfaces to the administrative context. There are no diagnostic, debug, or maintenance interfaces exposed on production firmware.

## 6. Secure-by-default configuration (CLA-03-RQ-01)

The product ships with a secure default configuration. Administration requires authentication and the default password must be changed on first use. Transport encryption is enabled for administration. UPnP, SNMP, and anonymous file sharing are disabled by default. The wireless network requires the user to set a passphrase during setup. No anonymous network services and no undocumented administrative interfaces are present in the default configuration.

## 7. Component integration security (CLA-03-RQ-02)

Cybersecurity is maintained through component integration. Each third-party component listed in RC-CBL-006 is integrated in line with its intended purpose and secure configuration guidance, and its due diligence is recorded in RC-TPD-012. Integrated components do not weaken the trust boundaries in section 3. There is no RDPS to consider in the integration design. Where a component provides a security function (for example wpad for wireless encryption or the firewall for network access control), its configuration is derived from the requirements in RC-SRS-003.
