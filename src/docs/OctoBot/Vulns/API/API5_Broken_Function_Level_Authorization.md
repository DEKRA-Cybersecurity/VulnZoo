---
id: API5:2023
title: "Broken Function Level Authorization"
category: API
status: IN PROGRESS
severity: High
owasp: "API5:2023 Broken Function Level Authorization"
cwe: "CWE-285 (Improper Authorization)"
source_docs:
  - "stages/01_spec/output/octobot-firmware-endpoints-spec.md"
  - "stages/02_implement/output/manifest.md"
affected_components:
  - "cloud_api/octobot/app.py"
verified_date: ""
---

## Why It Matters

The OctoBot cloud API exposes the same firmware-management capability through two route versions. `/api/v2/firmware` is gated by the operator session cookie, but `/api/v0/firmware` is an older, downgraded path that performs no authentication at all. An attacker who discovers the v0 route can download the current firmware image and upload a replacement image to the Pi without ever logging in. This is a function-level authorization failure: the sensitive operation is reachable through an unprotected entry point that bypasses the access control applied to its newer equivalent.

The Android login panel and web UI only reference `/api/v2/firmware/version`, so they do not directly expose the v0 path. However, the visible `/api/v2/` versioning scheme invites route enumeration; an attacker who fuzzes lower versions quickly discovers `/api/v0/firmware` and the unauthenticated downgrade.

Because the uploaded file overwrites `/opt/octobot/firmware/robot_arm.hex` on the Pi, the v1 route becomes a remote firmware replacement primitive. When combined with the lack of signature verification documented in [IoT:I4](../IoT/IoT4_Lack_of_Secure_Update_Mechanism.md), the attacker can move straight from discovering the legacy route to replacing the actuator firmware image. The cloud PUT stages that image on the Pi over SSH, it does not flash the Arduino itself, so the malicious build runs on the next flash (a gateway `/update` or a reboot with hardware). See [IoT:I4](../IoT/IoT4_Lack_of_Secure_Update_Mechanism.md) for the full staging.

## Root Cause

```python
# cloud_api/octobot/app.py
@app.route('/api/v0/firmware', methods=['GET', 'PUT'])
def firmware_v0():
    # [IoT:I4] [API5:2023] Intentionally downgraded endpoint: no session check.
    if request.method == 'GET':
        ...
        return send_from_directory(...)

    if 'file' not in request.files:
        return jsonify(error='no file provided'), 400
    return FirmwareService.save_and_push(request.files['file'], 'v1'), 200


@app.route('/api/v2/firmware', methods=['GET', 'PUT'])
@login_required
def firmware_v2():
    ...
```

The v0 handler is not decorated with `@login_required`. It reuses the same `FirmwareService.save_and_push` helper as v2, so the only difference between the two routes is the missing authorization check. The application relies on URL path versioning for security rather than a central authorization decision that covers every function that can modify the firmware store.

## Steps to Reproduce

```bash
# 1. Confirm that v2 rejects an unauthenticated upload.
curl -s -w '%{http_code}' -X PUT -F 'file=@evil.hex' http://localhost:5002/api/v2/firmware
# -> 401 {"error": "authentication required"}

# 2. Call the v0 route with the same payload and no cookie.
curl -s -X PUT -F 'file=@evil.hex' http://localhost:5002/api/v0/firmware
# -> {"version": "v1", "filename": "robot_arm.hex", "path": "/app/firmware/robot_arm.hex", "pushed": true}

# 3. Download the current firmware without credentials.
curl -s http://localhost:5002/api/v0/firmware -o current.hex
# -> binary firmware image
```

The v1 route succeeds without a session cookie, while the equivalent v2 route requires one. Both routes operate on the same firmware file and push to the same Pi path.

## Expected Result

`PUT /api/v0/firmware` accepts and stores an arbitrary file without authentication and pushes it to the Pi. `GET /api/v0/firmware` returns the current firmware image without authentication. `PUT /api/v2/firmware` performs the same operations only when a valid session cookie is present.

## How It Should Be

Remove the unauthenticated v0 route, or re-implement it as a redirect or strict deprecation response. Enforce a single, consistent authorization check for every function that can read or modify firmware. Authorization should be based on the user's role and the sensitivity of the operation, not on the API version string in the URL.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Access control | Central function-level authorization policy | Apply the same rule to v0 and v2 |
| Route hygiene | Disable or remove deprecated v0 endpoints | Remove the unauthenticated bypass |
| Logging | Log firmware read/write with actor and outcome | Enable detection of unauthorized function use |
| Test coverage | Automated tests that verify v1 and v2 have identical auth requirements | Prevent auth drift between versions |

## Verification Checklist

- [ ] `PUT /api/v0/firmware` without a cookie returns the same success response as an authenticated v2 call
- [ ] `GET /api/v0/firmware` without a cookie returns the firmware image
- [ ] `PUT /api/v2/firmware` without a cookie returns 401
- [ ] `GET /api/v2/firmware` without a cookie returns 401
- [ ] The v0 and v2 routes use the same underlying `FirmwareService.save_and_push` helper

## Related Vulnerabilities

- [IoT:I4 — Lack of Secure Update Mechanism](../IoT/IoT4_Lack_of_Secure_Update_Mechanism.md): the unauthenticated v0 route is the access vector that lets an attacker replace the Pi firmware image.
- [IoT:I1 — Weak, Guessable, or Hardcoded Passwords](../IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md): `GET /api/v0/firmware` allows anyone to download the compiled firmware and extract the hardcoded actuator password `OctoSuperBot2026` with `strings`.
- [M8 — Security Misconfiguration](../Mobile/M8_Security_Misconfiguration.md): the Android login panel discloses the `/api/v0/` route namespace before authentication by calling `GET /api/v0/firmware/version`.
