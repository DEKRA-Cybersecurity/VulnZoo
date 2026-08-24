---
id: RC-RMR-001
title: RoutCoon Product Cybersecurity Risk Management Report
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 6 (6.2-6.7)
cra_annex: Annex VII
covers_checklist_rows: [1, 2, 3, 4, 5, 6, 7, 8, 9]
requirement_ids: [RMA-01-RQ-01, RMA-01-RQ-02, RMA-02-RQ-01, RMA-03-RQ-01, RMA-04-RQ-01, RMA-05-RQ-01, RMA-05-RQ-02, RMA-05-RQ-03, RMA-06-RQ-01, RMA-06-RQ-02, RMA-06-RQ-03, RMA-06-RQ-04, RMA-07-RQ-01, RMA-07-RQ-02, RMA-07-RQ-03, RMA-08-RQ-01, RMA-08-RQ-02, RMA-08-RQ-03, RMA-09-RQ-01, RMA-09-RQ-02, RMA-09-RQ-03]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
---

# RC-RMR-001 Product Cybersecurity Risk Management Report

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-RMR-001 |
| Title | RoutCoon Product Cybersecurity Risk Management Report |
| Version | 1.0 |
| Date | 2026-08-21 |
| Product | RoutCoon Home/Office WiFi Router, firmware 1.0 on OpenWrt 24.10.3 |
| Manufacturer | RoutCoon Networks (fictional) |
| Standard clause | prEN 40000-1-2, Clause 6 (6.2 to 6.7) |
| Related deliverables | RC-CBL-006, RC-SBOM-007, RC-SRS-003, RC-SAD-004, RC-VMP-010, RC-UM-013 |
| Owner | Product Security |
| Approver | Head of Engineering |

## 1. Purpose and scope

This report documents the product cybersecurity risk management activities for the RoutCoon router as required by prEN 40000-1-2 Clause 6. It covers the product context (6.2), risk acceptance criteria (6.3), the risk assessment of assets, threats, analysis and evaluation (6.4), risk treatment (6.5), risk communication (6.6), and risk review (6.7). Each normative requirement identifier is cited in the section that satisfies it so the report can be traced by requirement ID.

The assessment scope is the RoutCoon device firmware and its integrated components as listed in RC-CBL-006 and RC-SBOM-007. Cybersecurity requirements derived from this report are specified in RC-SRS-003 and realised in the architecture RC-SAD-004.

## 2. Risk methodology

Risk is estimated as a function of likelihood and impact. Likelihood and impact are each rated Low, Medium or High. The resulting risk level is read from the matrix below.

| Likelihood \ Impact | Low | Medium | High |
|---------------------|-----|--------|------|
| Low | Low | Low | Medium |
| Medium | Low | Medium | High |
| High | Medium | High | Critical |

Likelihood considers attacker position (physical, WiFi-adjacent, wired-LAN, remote/WAN), the skill required, and whether a known exploit or public technique exists. Impact considers the cybersecurity properties affected (confidentiality, integrity, availability, authenticity) and the consequence for the user and their network.

## 6.2 Product context (RMA-01-RQ-01, RMA-01-RQ-02)

### 6.2.1 Intended purpose and reasonably foreseeable use (IPRFU)

RoutCoon is a home and small-office WiFi router. Its intended purpose is to provide wired and wireless local network connectivity, DHCP and DNS services, and a web-based administration interface for a non-expert owner. Reasonably foreseeable use includes deployment on a residential LAN, sharing files over the local network, and occasional remote administration from within the same LAN. Reasonably foreseeable misuse includes leaving default credentials unchanged, exposing the administration interface to an untrusted network segment, and connecting the device directly to a public network.

### 6.2.2 Product functions

Routing and switching, wireless access point (2.4 GHz, WPA2-PSK), DHCP and DNS (dnsmasq), a web administration UI and internal API (uhttpd and LuCI), SSH administration (Dropbear), SMB file sharing (Samba), UPnP IGD (miniupnpd), and an SNMP management agent (net-snmp). Component versions and origins are in RC-CBL-006.

### 6.2.3 Operational environment

The device operates on a trusted residential or small-office LAN behind an upstream ISP gateway. It has a single physical network interface, so it does not present a distinct WAN interface. The wired LAN is 192.168.2.0/24 with the device at 192.168.2.1, and the wireless LAN is 192.168.3.0/24 with the device at 192.168.3.1. Administration is expected from within these segments.

### 6.2.4 Architecture overview

The security-relevant architecture, trust boundaries, and control placement are specified in RC-SAD-004. In summary, the trust boundaries are the wired LAN, the wireless LAN, and the physical device boundary. All network services bind on all interfaces. There is no separate management VLAN.

### 6.2.5 User description

The primary user is a non-expert home or small-office administrator with limited security knowledge. The user is expected to perform first-time setup, change default credentials, and apply firmware updates when notified. Mitigation measures that depend on user action must be within this user's capability (see 6.4.5).

### 6.2.6 Distribution of security functions

Security functions are distributed as follows. Authentication and session management are handled by LuCI and Dropbear. Network access control is handled by the firewall (nftables via luci-app-firewall). Confidentiality of wireless traffic is handled by wpad (WPA2). Firmware and package handling is performed by the OpenWrt sysupgrade and opkg mechanisms and the OEM update channel described in RC-SDD-009.

### 6.2.7 Remote data processing solution (RDPS) (RMA-01-RQ-02)

RoutCoon has no RDPS in the meaning of the standard. All processing essential to the product's function is performed on the device. The OEM firmware update channel referenced in RC-SDD-009 is an out-of-band distribution channel and does not perform remote processing of user data on behalf of the product. RMA-01-RQ-02 is therefore satisfied by recording that no RDPS is present and none was considered in the product context.

## 6.3 Risk acceptance criteria (RMA-02-RQ-01)

The risk acceptance criteria are defined and justified for the product context above, considering the following factors.

- **Regulatory factors.** The product is in scope of the EU Cyber Resilience Act. Relevant essential requirements include protection against unauthorised access, confidentiality and integrity of data, minimisation of attack surface, and secure default configuration. Data minimisation under the GDPR is considered for any personal data the device processes (DHCP leases, DNS query records).
- **Supply chain considerations.** The product is built on OpenWrt 24.10.3 and FOSS components (RC-CBL-006). Component maintenance and support periods are assessed in RC-TPD-012.
- **Nature of known risks.** The product exposes several network services on a trusted LAN. Known risks are assessed on the assumption that the LAN is trusted and that the wireless network is protected by a user-set passphrase.
- **State of the art.** Current good practice for consumer routers includes transport encryption for administration, signed firmware updates, credential-change enforcement on first use, and rate limiting of authentication.

Acceptance rule: a residual risk is acceptable if its risk level is Low, or if it is Medium and the exposure is limited to the trusted wired LAN and the user can apply a documented mitigation within their capability. Risks rated High or Critical are not acceptable and require treatment (6.5).

## 6.4 Risk assessment

### 6.4.2 Asset identification (RMA-03-RQ-01)

The product cybersecurity assets and the properties to be protected are identified from the product context.

| Asset | Confidentiality | Integrity | Availability | Authenticity |
|-------|:---:|:---:|:---:|:---:|
| Administrator credentials and session tokens | x | x | | x |
| Device firmware and installed packages | | x | | x |
| Device configuration (UCI) | x | x | x | |
| Wireless passphrase (WPA2 PSK) | x | | | |
| User network traffic in transit | x | x | | |
| DHCP lease and DNS query records (personal data) | x | | | |
| SMB shared files | x | x | x | |
| Device availability and management plane | | | x | |

### 6.4.3 Threat identification (RMA-04-RQ-01)

Threats are identified from the product context and from relevant known vulnerabilities of the integrated components and configuration. Each threat records the targeted asset, the compromised property, and the cause. The threat register below is the manufacturer's identified set. Threat identifiers are mapped to the product's internal security findings catalogue where applicable.

| Threat | Targeted asset | Compromised property | Cause | Ref (CWE) |
|--------|----------------|----------------------|-------|-----------|
| T-01 Hardcoded and weak account credentials | Admin credentials, WiFi PSK | Confidentiality, Authenticity | Factory-set accounts and a shared default WPA2 passphrase | CWE-521, CWE-798 |
| T-02 Cleartext administration over HTTP | Admin credentials, session tokens | Confidentiality | Web admin served over plain HTTP without TLS | CWE-319 |
| T-03 Anonymous writable FTP | Firmware staging area | Integrity | BusyBox ftpd allows anonymous write to the update staging directory | CWE-306 |
| T-04 SNMP default communities | Network topology, ARP and DNS records | Confidentiality | SNMP v1/v2c with default community strings | CWE-306, CWE-200 |
| T-05 UPnP with secure mode disabled | Firewall ruleset | Integrity, Availability | miniupnpd configured with secure_mode disabled | CWE-284 |
| T-06 Anonymous world-writable SMB share | SMB shared files | Confidentiality, Integrity | Samba public share writable by anonymous users | CWE-732 |
| T-07 No firmware update authenticity | Device firmware | Integrity, Authenticity | Package signature verification disabled, no firmware signing | CWE-347 |
| T-08 Unauthenticated update processing | Device firmware | Integrity | Update artifacts staged over the network are processed automatically | CWE-494 |
| T-09 Weak wireless protection | Wireless passphrase, user traffic | Confidentiality | Shared default WPA2 PSK, no per-user credentials | CWE-521 |
| T-10 Server-side request forgery in tools | Device configuration, internal resources | Confidentiality | Network tools endpoint fetches attacker-controlled URLs | CWE-918 |
| T-11 OS command injection in diagnostics | Device integrity | Integrity | Ping/diagnostic handler passes input to a shell | CWE-78 |
| T-12 Broken authentication controls | Admin credentials, sessions | Confidentiality, Integrity | No rate limiting, weak session token generation, password change without old password | CWE-307, CWE-620 |
| T-13 Broken function-level authorisation | Privileged operations | Integrity | Privileged handlers reachable without an authenticated session | CWE-862 |
| T-14 Absence of device management controls | Management plane, availability | Availability | No security monitoring, no account lockout, no update tracking | CWE-778 |
| T-15 Insufficient physical hardening | All device assets | Confidentiality, Integrity, Availability | No secure boot, unencrypted storage, exposed debug interface | CWE-1263 |

### 6.4.4 Risk analysis (RMA-05-RQ-01, RMA-05-RQ-02, RMA-05-RQ-03)

For each threat, the likelihood of occurrence (RMA-05-RQ-01), the impact (RMA-05-RQ-02), and the incident scenario (RMA-05-RQ-03) are documented.

| Threat | Likelihood | Impact | Risk | Incident scenario |
|--------|-----------|--------|------|-------------------|
| T-01 | High | High | Critical | An attacker on the LAN or WiFi authenticates with a known factory credential and takes administrative control |
| T-02 | Medium | High | High | An attacker on the same LAN segment captures administrator credentials from unencrypted HTTP traffic |
| T-03 | Medium | Medium | Medium | An attacker on the LAN uploads a file to the update staging area anonymously |
| T-04 | Medium | Medium | Medium | An attacker queries SNMP with the default community and enumerates the network and connected clients |
| T-05 | Low | Medium | Low | A LAN client manipulates the firewall via UPnP port mapping requests |
| T-06 | Medium | Medium | Medium | An attacker on the LAN reads or plants files in the anonymous SMB share |
| T-07 | Medium | High | High | A tampered firmware or package image is installed because authenticity is not verified |
| T-08 | Medium | High | High | An update artifact placed on the device is processed and executed automatically |
| T-09 | Medium | Medium | Medium | An attacker within radio range recovers the shared passphrase and decrypts wireless traffic |
| T-10 | Medium | Medium | Medium | An attacker causes the device to read internal files or reach internal network resources |
| T-11 | Medium | High | High | An attacker injects operating-system commands through the diagnostic function |
| T-12 | High | High | Critical | An attacker brute forces or forges a session and gains administrative access |
| T-13 | High | High | Critical | An attacker invokes privileged functions without authenticating |
| T-14 | High | Medium | High | An intrusion proceeds undetected because there is no monitoring or lockout |
| T-15 | Low | High | Medium | An attacker with physical access extracts secrets from storage or the debug interface |

### 6.4.5 Risk evaluation and acceptance (RMA-06-RQ-01, RMA-06-RQ-02, RMA-06-RQ-03, RMA-06-RQ-04)

Each risk is evaluated against the acceptance criteria of 6.3 (RMA-06-RQ-01). Where a risk is accepted, the justification is recorded (RMA-06-RQ-04), and where the mitigation depends on the user, the manufacturer confirms it is within the capability of the intended user (RMA-06-RQ-03).

| Threat | Risk     | Decision                | Justification (RMA-06-RQ-04)                                                                                                                               |
| ------ | -------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-01   | Critical | Accept with user action | Default credentials are documented in the user manual and the user is expected to change them on first use, which is within user capability (RMA-06-RQ-03) |
| T-02   | High     | Accept                  | Administration is expected only from the trusted wired LAN, so cleartext exposure is considered limited                                                    |
| T-03   | Medium   | Accept                  | The staging area is local to the LAN and the update process validates artifacts before use                                                                 |
| T-04   | Medium   | Accept                  | SNMP exposes only network status and the LAN is trusted                                                                                                    |
| T-05   | Low      | Accept                  | The device has no WAN interface, so port mappings have limited effect                                                                                      |
| T-06   | Medium   | Treat                   | The anonymous writable share exceeds acceptable exposure for user data                                                                                     |
| T-07   | High     | Accept                  | Firmware updates are infrequent and delivered over the local network, so the residual risk is considered tolerable                                         |
| T-08   | High     | Treat                   | Automatic processing of network-staged artifacts requires additional control                                                                               |
| T-09   | Medium   | Accept with user action | The user is expected to set a strong wireless passphrase, which is within user capability                                                                  |
| T-10   | Medium   | Treat                   | Internal resource access through the tools endpoint requires input restriction                                                                             |
| T-11   | High     | Treat                   | Command injection in diagnostics is not acceptable and requires input handling                                                                             |
| T-12   | Critical | Treat                   | Authentication weaknesses are not acceptable and require rate limiting and stronger tokens                                                                 |
| T-13   | Critical | Treat                   | Missing authorisation on privileged functions is not acceptable                                                                                            |
| T-14   | High     | Accept                  | Consumer devices of this class commonly lack monitoring, considered state of the art for the segment                                                       |
| T-15   | Medium   | Accept                  | Physical access to the device is considered outside the operational threat model                                                                           |

Residual accepted risks: T-01, T-02, T-03, T-04, T-05, T-07, T-09, T-14, T-15. These are recorded as the manufacturer's accepted residual risk position (RMA-06-RQ-02). Risks marked Treat are carried to 6.5.

## 6.5 Risk treatment (RMA-07-RQ-01, RMA-07-RQ-02, RMA-07-RQ-03)

For each risk not meeting the acceptance criteria, a treatment decision and rationale are documented (RMA-07-RQ-01, RMA-07-RQ-02), and the risk is re-evaluated after treatment (RMA-07-RQ-03).

| Threat | Treatment decision | Rationale | Re-evaluated risk |
|--------|--------------------|-----------|-------------------|
| T-06 | Restrict the SMB public share to read-only and require authentication for write access | Removes anonymous write while retaining the file-sharing function | Low |
| T-08 | Require the update process to validate an artifact signature before processing and remove automatic execution of staged files | Prevents processing of unauthenticated artifacts | Medium |
| T-10 | Restrict the tools endpoint to an allowlist of schemes and hosts and reject local and file schemes | Removes the internal-resource access path | Low |
| T-11 | Replace shell invocation in the diagnostic handler with a safe argument-array call and validate input | Removes the command injection sink | Low |
| T-12 | Add authentication rate limiting and account lockout, use a cryptographically strong session token, and require the current password on change | Restores authentication assurance | Medium |
| T-13 | Enforce an authenticated and authorised session on all privileged handlers | Restores function-level authorisation | Low |

The treatments above are the planned target state recorded in the requirements specification RC-SRS-003. The verification of their implementation is reported in RC-VVR-008.

## 6.6 Risk communication (RMA-08-RQ-01, RMA-08-RQ-02, RMA-08-RQ-03)

Relevant residual risks and the conditions of use are communicated to users in clear, non-technical language in RC-UM-013 (RMA-08-RQ-01), taking accessibility into account through simple language and a printable format (RMA-08-RQ-02). The communication includes (RMA-08-RQ-03): the circumstances and reasonably foreseeable misuse that lead to significant risk (unchanged default credentials, administration from untrusted networks, direct exposure to a public network), and the recommended mitigation measures for the user (change the default administrator and wireless credentials on first use, administer only from the trusted LAN, keep firmware updated, and do not place the device directly on a public network).

## 6.7 Risk review (RMA-09-RQ-01, RMA-09-RQ-02, RMA-09-RQ-03)

Risk management activities are reviewed at planned intervals and on trigger events (RMA-09-RQ-01, RMA-09-RQ-02). The planned interval and the triggers, and the justification for the interval, are defined in RC-VMP-010. Triggers include a product modification that may affect cybersecurity, a change in the product context, a newly disclosed vulnerability in an integrated component, a severe cybersecurity incident, and component obsolescence. Where a review shows an impact, the affected Clause 6 documentation in this report is updated (RMA-09-RQ-03), and the change is recorded in the document control block and in the RC-VMP-010 issue register.

## Appendix A. Consolidated risk register

| Threat | Asset | Property | Likelihood | Impact | Risk | Decision | Residual |
|--------|-------|----------|-----------|--------|------|----------|----------|
| T-01 | Admin credentials, WiFi PSK | C, Au | High | High | Critical | Accept (user action) | Critical |
| T-02 | Admin credentials | C | Medium | High | High | Accept | High |
| T-03 | Firmware staging | I | Medium | Medium | Medium | Accept | Medium |
| T-04 | Network records | C | Medium | Medium | Medium | Accept | Medium |
| T-05 | Firewall ruleset | I, A | Low | Medium | Low | Accept | Low |
| T-06 | SMB files | C, I | Medium | Medium | Medium | Treat | Low |
| T-07 | Firmware | I, Au | Medium | High | High | Accept | High |
| T-08 | Firmware | I | Medium | High | High | Treat | Medium |
| T-09 | WiFi PSK, traffic | C | Medium | Medium | Medium | Accept (user action) | Medium |
| T-10 | Configuration | C | Medium | Medium | Medium | Treat | Low |
| T-11 | Device integrity | I | Medium | High | High | Treat | Low |
| T-12 | Sessions | C, I | High | High | Critical | Treat | Medium |
| T-13 | Privileged ops | I | High | High | Critical | Treat | Low |
| T-14 | Management plane | A | High | Medium | High | Accept | High |
| T-15 | All assets | C, I, A | Low | High | Medium | Accept | Medium |
