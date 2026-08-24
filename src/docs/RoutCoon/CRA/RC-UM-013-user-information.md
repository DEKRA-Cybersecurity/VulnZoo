---
id: RC-UM-013
title: RoutCoon Information and Instructions to the User (CRA Annex II)
category: Compliance
status: DONE
standard: prEN 40000-1-2 clause 7.5e
cra_annex: Annex II
covers_checklist_rows: [17]
requirement_ids: []
version: 1.0
date: 2026-08-21
owner: RoutCoon Networks - Product Security
approver: RoutCoon Networks - Head of Engineering
---

# RoutCoon Router - User Information and Instructions

## Document control

| Field | Value |
|-------|-------|
| Document ID | RC-UM-013 |
| Standard clause | prEN 40000-1-2, 7.5e (CRA Annex II) |
| Related deliverables | RC-RMR-001 (6.6), RC-DEC-011, RC-VMP-010, RC-TD-000 |
| Owner | Product Security |
| Approver | Head of Engineering |

> This document is the user-facing information and instructions required by CRA Annex II. It is written in clear, non-technical language and is provided with the product in a printable and screen-reader-friendly format.

## 1. Manufacturer and product

- **Manufacturer.** RoutCoon Networks (fictional).
- **Contact and security reports.** contact@routcoon-oem.local
- **Product.** RoutCoon Home/Office WiFi Router.
- **Firmware version.** 1.0 (based on OpenWrt 24.10.3).
- **Declaration of conformity.** The EU Declaration of Conformity is provided with the product and is referenced in the technical documentation RC-TD-000.

## 2. What the product is for

RoutCoon connects your home or small office to the internet and to each other, over a network cable and over WiFi. It hands out local network addresses, resolves names, offers file sharing on your local network, and provides a web page for you to manage it. Use it on your own local network behind your internet provider's connection. Do not connect it directly to the public internet.

## 3. Set it up securely (do this first)

These steps protect your network. Please do them before you start using the device.

1. **Change the administrator password.** Open the management page at http://192.168.2.1 and set a new, strong administrator password. Do not keep the factory password.
2. **Set your WiFi password.** Choose your own strong WiFi passphrase. Do not keep the factory WiFi passphrase.
3. **Manage only from your own network.** Use the management page and remote access only from your trusted wired or WiFi network, never from an untrusted network.
4. **Turn off what you do not use.** If you do not need file sharing, UPnP, or SNMP, leave them off.

## 4. Keeping the product updated

Security updates are provided by the manufacturer for the support period below. When an update is available you are notified on the management page and through the security advisory channel. Install updates promptly. Updates are the main way the product stays protected against newly discovered issues.

## 5. Risks to be aware of and how to reduce them

This section explains the circumstances that can put your network at risk and what you can do about them. It corresponds to the risk communication in RC-RMR-001 section 6.6.

| Situation | Why it matters | What to do |
|-----------|----------------|------------|
| Keeping the factory administrator or WiFi password | Anyone who knows the factory password can take control | Change both passwords during setup (section 3) |
| Managing the device from an untrusted network | Your management traffic could be seen or altered | Manage only from your own trusted network |
| Connecting the device directly to the public internet | It exposes local services to anyone | Keep the device behind your internet provider's connection |
| Not installing updates | Known issues stay unfixed | Install updates when notified (section 4) |
| Leaving unused services on | More ways in than you need | Turn off file sharing, UPnP, and SNMP if unused |

## 6. Support period

The manufacturer provides security updates for RoutCoon until the end-of-support date **2031-08-21** (five years from release). Before that date you will be informed of the end-of-support and of any final security update. After that date the product no longer receives security updates and you should plan to replace it.

## 7. Decommissioning and disposal

When you stop using the device, remove your data and secrets before you dispose of it or pass it on. Full guidance is in RC-DEC-011.

1. **Save anything you want to keep.** Export your configuration first if you need it.
2. **Erase your data.** Perform a factory reset to clear the configuration, passwords, WiFi passphrase, address leases, and logs.
3. **Remove it from your network.** Disconnect it and remove its entries from your other devices.
4. **Dispose of it safely.** The storage card is not encrypted, so remove or securely erase the microSD card before disposal or resale.

## 8. Reporting a security problem

If you find a security problem with RoutCoon, please contact contact@routcoon-oem.local. Reports are handled by the product security team as described in RC-VMP-010.
