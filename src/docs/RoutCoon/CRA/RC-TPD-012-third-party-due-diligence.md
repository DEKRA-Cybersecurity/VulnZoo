---
id: RC-TPD-012
title: RoutCoon Third-Party Component Due Diligence and Integration
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.10 and 7.5f
cra_annex: Annex VII
covers_checklist_rows: [18, 28]
requirement_ids: [CLA-10-RQ-01, CLA-10-RQ-02, CLA-10-RQ-03, CLA-10-RQ-04, CLA-10-RQ-05]
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Engineering
approver: RoutCoon Networks - Head of Engineering
---

# RC-TPD-012 Third-Party Component Due Diligence and Integration

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-TPD-012 |
| Title | RoutCoon Third-Party Component Due Diligence and Integration |
| Version | 1.0 |
| Date | 2026-08-21 |
| Standard clause | prEN 40000-1-2, 7.10 (CLA-10) and 7.5f |
| Related deliverables | RC-CBL-006, RC-SBOM-007, RC-RMR-001, RC-VVR-008, RC-VMP-010 |
| Owner | Engineering |
| Approver | Head of Engineering |

## 1. Purpose

This document records the due diligence performed for the third-party components integrated into RoutCoon, as required by prEN 40000-1-2 clause 7.10, and confirms their integration in line with their intended purpose and user instructions as required by clause 7.5f.

## 2. Due diligence method (CLA-10-RQ-01, CLA-10-RQ-02, CLA-10-RQ-03, CLA-10-RQ-04)

Due diligence is performed during selection and prior to integration (CLA-10-RQ-01). For each component the assessment covers: alignment of the component's intended purpose with its use in the product, compliance with legal and cybersecurity requirements, the absence of known exploitable vulnerabilities at the time of selection, and the component's support period. For free and open-source software (FOSS) the assessment also considers active maintenance, the presence of a vulnerability disclosure process, and cybersecurity-by-design indicators (CLA-10-RQ-02, CLA-10-RQ-03, CLA-10-RQ-04).

## 3. Component due diligence record

All components are FOSS from the OpenWrt 24.10.3 feed unless noted. Versions and full inventory are in RC-CBL-006 and RC-SBOM-007.

| Component | Purpose alignment | Support / maintenance | Disclosure process | Known exploitable vulns at selection |
|-----------|-------------------|-----------------------|--------------------|--------------------------------------|
| OpenWrt (base) | Router firmware platform | Active project, maintained release branch 24.10 | OpenWrt security advisories | None known at selection |
| Linux kernel 6.6 | OS kernel | Active LTS branch | kernel.org and distro advisories | None known at selection |
| BusyBox 1.36.1 | Userland utilities | Active | Project mailing list | None known at selection |
| uhttpd / LuCI | Web server and admin UI | Active, OpenWrt maintained | OpenWrt advisories | None known at selection |
| Dropbear | SSH server | Active | Upstream advisories | None known at selection |
| dnsmasq | DHCP and DNS | Active | Upstream advisories | None known at selection |
| Samba 4.18.8 | SMB file sharing | Active, supported branch | Samba security releases | None known at selection |
| miniupnpd | UPnP IGD | Active | Upstream advisories | None known at selection |
| wpad / hostapd | WiFi authenticator | Active | hostap advisories | None known at selection |
| net-snmp | SNMP agent | Active | Upstream advisories | None known at selection |
| OpenSSL / Mbed TLS | TLS and crypto | Active, supported branches | OpenSSL and Mbed TLS advisories | None known at selection |
| curl / wget | HTTP clients | Active | Upstream advisories | None known at selection |
| brcmfmac / wireless-regdb | WiFi driver and regulatory data | Maintained with the kernel | kernel advisories | None known at selection |

## 4. Integration confirmation (7.5f)

Each integrated third-party component is used in line with its intended purpose and its configuration follows the component's secure-configuration guidance and user instructions, as realised in RC-SAD-004 and RC-SRS-003. The integration does not repurpose any component outside its documented intended use.

## 5. Inclusion in ongoing activities (CLA-10-RQ-05)

Each component is included in the product risk assessment (RC-RMR-001), the verification and validation (RC-VVR-008), and the ongoing monitoring (RC-VMP-010). Third-party components are monitored over their lifecycle to identify and address vulnerabilities relevant to the product, in line with clause 7.8 and the intervals defined in RC-VMP-010 (CLA-10-RQ-05).
