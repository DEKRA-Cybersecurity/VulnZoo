---
id: M8
title: "Security Misconfiguration (Pre-Login API Surface Disclosure)"
category: Mobile
status: IN PROGRESS
severity: Medium
owasp: "OWASP Mobile Top 10: M8 — Security Misconfiguration"
cwe: "CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) / CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer)"
source_docs:
  - "src/docs/OctoBot/Vulns/API/API5_Broken_Function_Level_Authorization.md"
  - "src/docs/OctoBot/Vulns/IoT/IoT4_Lack_of_Secure_Update_Mechanism.md"
affected_components:
  - "vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/LoginActivity.java"
  - "vulnzoo_apps/octobot_app/app/src/main/res/layout/activity_login.xml"
  - "cloud_api/octobot/app.py"
verified_date: ""
---

## Why It Matters

The OctoBot Android login panel only references the `/api/v2/` firmware endpoints, but it still discloses the API's versioning surface before the user has authenticated. The connection-test section issues `GET /api/v2/firmware/version` as soon as the operator presses "Test Connection" (and once on startup from the saved server). That request confirms to anyone observing traffic that the cloud exposes versioned firmware routes and that the current version is `v2`.

An attacker who sees `/api/v2/` can enumerate earlier versions. Because the server still leaves the deprecated `/api/v0/firmware` and `/api/v0/firmware/version` endpoints enabled and unauthenticated, a simple fuzz of `/api/v0/firmware` returns the full firmware image. From there the attacker extracts the hardcoded actuator password ([IoT:I1](../IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md)) or replaces the firmware ([IoT:I4](../IoT/IoT4_Lack_of_Secure_Update_Mechanism.md)).

The mobile side contributes to the misconfiguration by issuing a pre-authentication call that advertises the API's route structure and versioning scheme, while the server side contributes by keeping the unauthenticated downgrade endpoints live.

## Root Cause

`LoginActivity.java` exposes the cloud API structure through a connection-test section on the login screen. The panel has separate IP and Port fields, a "Detect WiFi" button, and a "Test Connection" button. Pressing "Test Connection" builds the server string, saves it, and then calls `/api/v2/firmware/version` to populate the firmware version label:

```java
// vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/LoginActivity.java
btnTestConnection.setOnClickListener(v -> testConnection());
...
private void testConnection() {
    final String server = getServerString();
    getSharedPreferences(PREFS, MODE_PRIVATE).edit()
            .putString(KEY_SERVER, server)
            .apply();

    exec.execute(() -> {
        ...
        HttpURLConnection c = (HttpURLConnection)
                new URL("http://" + server + "/api/v2/firmware/version").openConnection();
        c.setRequestMethod("GET");
        ...
    });
}
```

![[m8_firmware_fetched.png|525]]

The same fetch is issued once on startup from the saved/default server. The app never references `/api/v0/`, but the cloud controller still exposes it:

```python
# cloud_api/octobot/app.py
@app.route('/api/v0/firmware', methods=['GET', 'PUT'])
def firmware_v0():
    # [IoT:I4] [API5:2023] Intentionally downgraded endpoint: no session check.
    ...
```

Because the deprecated route is still reachable, version enumeration is enough to turn the mobile-side route disclosure into a firmware download or replacement primitive.

## Steps to Reproduce

### 1. Observe the pre-login v2 request

Proxy the OctoBot Android app (e.g., Burp Suite or `mitmproxy`) or capture device traffic, then open the login panel and press **Test Connection**. Before any credentials are entered you will see:

```http
GET /api/v2/firmware/version HTTP/1.1
Host: 192.168.2.2:5002
```

![[m8_firmware_version.png]]

Response:

```json
{"version": "v1.0.0"}
```

![[m8_firmware_version_response.png]]
### 2. Enumerate the deprecated v0 endpoint

The `/api/v2/` path confirms the API uses URL versioning. Fuzz lower versions to find the unauthenticated downgrade:

```bash
for v in v0 v1; do
  curl -s -o /dev/null -w "%{http_code}" http://192.168.2.2:5002/api/$v/firmware
done
# v0 -> 200
# v1 -> 404
```

![[m8_endpoint_fuzzing.png]]
## Expected Result

The Android login panel uses only `/api/v2/firmware/version`, but its pre-login request reveals that the cloud API exposes versioned firmware routes. An attacker who enumerates lower versions discovers `/api/v0/firmware`, which returns the firmware image without authentication, and `/api/v0/firmware/version`, which returns the version without authentication.

## How It Should Be

The login panel should not make any pre-authentication API calls to endpoints that expose internal versioning or firmware metadata. Version information is useful only after the operator has authenticated, so it should be fetched inside `ControlActivity` (the post-login screen).

On the server side, deprecated routes such as `/api/v0/firmware` and `/api/v0/firmware/version` should be removed or require the same session authorization as `/api/v2/firmware`. If a legacy endpoint must remain temporarily, it should return a strict deprecation response rather than the full firmware image.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Mobile UI | Remove the pre-login connection test's API call from `LoginActivity` | Stop disclosing the API versioning surface before authentication |
| Mobile UI | Move version display to `ControlActivity` | Show firmware version only after login |
| API route hygiene | Remove or disable `/api/v0/firmware` and `/api/v0/firmware/version` | Eliminate the unauthenticated downgrade |
| API auth | Apply `@login_required` to all non-login firmware endpoints | Prevent anonymous firmware read/write |
| API design | Return generic 404 for unknown versions instead of distinguishing missing routes from forbidden ones | Slow route enumeration |
| Testing | Proxy test the login flow and assert zero non-login API calls; fuzz API versions and assert v0 is unreachable | Catch disclosure and downgrade regressions |

## Verification Checklist

- [ ] Opening the Android login panel and pressing **Test Connection** triggers no API calls except the user-initiated `POST /login`
- [ ] `GET /api/v0/firmware` without a session cookie returns 401 or 404 (or the route is removed)
- [ ] `GET /api/v0/firmware/version` without a session cookie returns 401 or 404 (or the route is removed)
- [ ] `GET /api/v2/firmware/version` requires a session cookie or is only reachable from the authenticated control panel
- [ ] The firmware version is still visible to authenticated users inside the control panel
- [ ] Traffic analysis of the login flow does not reveal the API versioning scheme

## Related Vulnerabilities

- [API5:2023 — Broken Function Level Authorization](../API/API5_Broken_Function_Level_Authorization.md): `/api/v0/firmware` exposes the same firmware-management functions as v2 without session validation.
- [IoT:I4 — Lack of Secure Update Mechanism](../IoT/IoT4_Lack_of_Secure_Update_Mechanism.md): `PUT /api/v0/firmware` replaces the Pi firmware image without signature or version verification.
- [IoT:I1 — Weak, Guessable, or Hardcoded Passwords](../IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md): `GET /api/v0/firmware` lets anyone download the compiled firmware and recover the hardcoded actuator password `OctoSuperBot2026`.
