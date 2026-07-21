---
id: IoT:I5
title: "Use of Insecure or Outdated Components"
category: IoT
status: PENDING
severity: Medium
owasp: "IoT I5 - Use of Insecure or Outdated Components"
cwe: "CWE-1104 (Use of Unmaintained Third-Party Components) / CWE-1035 (Using Components with Known Vulnerabilities)"
source_docs:
  - "src/docs/OctoBot/OPENWRT_INTEGRATION.md §7 (IoT:I5)"
  - "stages/01_spec/output/octobot-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "labs/octobot/files/usr/lib/vulnzoo-hooks/profile-init.d/15-octobot-python-deps.sh"
verified_date: ""
---

## Why It Matters

An IoT field gateway often runs a frozen software stack for years: an old web server, an outdated TLS library, a stale Python framework. Each carries published CVEs an attacker can look up from a version banner. The intended lab vector is a deliberately pinned, outdated component set (old Dropbear / uHTTPd / Flask / jQuery, stale OpenWRT) that `nmap -sV` fingerprints and maps to known exploits.

rcise in a session and that one showed something pretty clear goi## Implementation Status

NOT YET IMPLEMENTED. The Stage 02 dependency hook `15-octobot-python-deps.sh` installs current package versions, so no outdated component is pinned today. The Stage 02 manifest tagged this item to that hook, but the hook does not yet pin vulnerable versions. Implementing I5 requires a follow-up Stage 02 pass that pins specific old versions (and documents the chosen CVEs), so this doc is `PENDING` until that lands.

## Root Cause (intended)

The deps hook would pin known-vulnerable releases instead of latest, for example an old Flask with a documented CVE or a stale uHTTPd, and OpenWRT itself would not be updated. The version then leaks through service banners.

## Steps to Reproduce (once implemented)

```bash
# Fingerprint service versions
nmap -sV 192.168.2.1
# Cross-reference each detected version against a CVE database
```

## Expected Result

`nmap -sV` reports component versions with published CVEs that are exploitable against the running services.

## How It Should Be

Track a software bill of materials, monitor advisories for every shipped component, and apply security updates. Pin versions to current patched releases, not to vulnerable ones.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| SBOM | Inventory every component + version | Know the attack surface |
| Patch | Track advisories, update on release | Close known CVEs |
| Build | Pin to current patched versions | Avoid shipping stale code |

## Verification Checklist

- [ ] (blocked) Pinned outdated versions present in the deps hook
- [ ] (blocked) `nmap -sV` reports a version with a known CVE
