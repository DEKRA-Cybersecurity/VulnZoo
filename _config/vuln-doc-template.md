# Vulnerability Doc Template (Layer 3 — product)

> Template for `stages/03_document`. Copy this structure to
> `src/docs/<Device>/Vulns/<Category>/<VULN-ID>.md`. Keep prose in **English**.
> Mirrors the existing CareOtter `Vulns/` docs.

```markdown
---
id: <API1:2023 | IoT:I1 | M9 | IGP-01 | BLE-07>
title: "<Descriptive title>"
category: <API | IoT | Mobile>
status: <DONE | PENDING | IN PROGRESS>
severity: <Critical | High | Medium | Low>
owasp: "<full OWASP entry, e.g. API1:2023 — Broken Object Level Authorization>"
cwe: "<CWE-XXX (Name) / CWE-YYY (Name)>"
source_docs:
  - "<reference, e.g. CareOtter_Test_Suite.md §API-01>"
affected_components:
  - "<real src/ path, e.g. cloud_api/careotter/api_server/app.py>"
verified_date: "<YYYY-MM-DD>"
---

## Why It Matters
<High-level impact in the device's domain.>

## Root Cause
<Technical analysis with code snippets; mark the missing check.>

## Steps to Reproduce
1. <curl / tool commands, screenshots, expected output>

## Expected Result
<Explicit success criteria: status codes, exposed data.>

## How It Should Be
<Minimal fix + architectural improvement.>

## Controls to Implement
| Layer | Measure | Objective |
|-------|---------|-----------|

## Verification Checklist
- [ ] <pass/fail criteria>
```
