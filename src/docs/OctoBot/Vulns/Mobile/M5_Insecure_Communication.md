---
id: M5
title: "Insecure Communication (Cleartext HTTP Credentials and Session Cookie)"
category: Mobile
status: IN PROGRESS
severity: High
owasp: "OWASP Mobile Top 10: M5 — Insecure Communication"
cwe: "CWE-319 (Cleartext Transmission of Sensitive Information)"
source_docs:
  - "src/docs/OctoBot/Vulns/IoT/IoT7_Insecure_Data_Transfer_and_Storage.md"
  - "src/docs/OctoBot/Vulns/Mobile/M9_Insecure_Data_Storage.md"
affected_components:
  - "vulnzoo_apps/octobot_app/app/src/main/AndroidManifest.xml"
  - "vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/LoginActivity.java"
  - "vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/ControlActivity.java"
verified_date: ""
---

## Why It Matters

The OctoBot Android app talks to the cloud controller entirely over plain HTTP. The operator credentials are submitted in a cleartext `POST /login`, and the Flask session cookie returned by that login is then replayed in the `Cookie` header on every `/api/*` request. Any attacker on the flat lab LAN who can sniff traffic (the same segment the app and the cloud share) captures both the operator password and a live session cookie, and can immediately drive the robot arm through the authenticated `/api/servo` and `/api/command` endpoints. This is the mobile-side counterpart of the device cleartext exposure in [IoT:I7](../IoT/IoT7_Insecure_Data_Transfer_and_Storage.md).

## Root Cause

The manifest opts the whole app into cleartext traffic:

```xml
<!-- vulnzoo_apps/octobot_app/app/src/main/AndroidManifest.xml -->
android:usesCleartextTraffic="true"
```

Both activities build `http://` URLs with no TLS. The login posts the credentials in the form body:

```java
// vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/LoginActivity.java
URL url = new URL("http://" + server + "/login");
...
String body = "username=" + URLEncoder.encode(user, "UTF-8")
            + "&password=" + URLEncoder.encode(pass, "UTF-8");
```

The control panel then attaches the captured session cookie to every request, still over `http://`:

```java
// vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/ControlActivity.java
HttpURLConnection c = (HttpURLConnection) new URL("http://" + server + path).openConnection();
...
if (cookie != null && !cookie.isEmpty()) c.setRequestProperty("Cookie", cookie);
```

There is no certificate pinning and no HTTPS option. Everything the app sends and receives is readable on the wire.

## Steps to Reproduce

1. Put an interception proxy or a passive sniffer on the LAN between the phone and the cloud host (for example `mitmproxy` in transparent mode, or `tcpdump`/Wireshark on the shared segment).

```bash
sudo tcpdump -i any -A 'tcp port 5002'
```

2. In the app, enter the server and log in with the operator account. In the captured traffic the credentials appear in cleartext:

```http
POST /login HTTP/1.1
Host: 192.168.2.2:5002
Content-Type: application/x-www-form-urlencoded

username=operator&password=octobot
```

3. The login response sets the session cookie, and every subsequent control request replays it, all readable:

```http
GET /api/state HTTP/1.1
Host: 192.168.2.2:5002
Cookie: session=eyJ1c2VyIjoib3BlcmF0b3IifQ...
```

4. Replay the captured cookie from any host to drive the arm with no login:

```bash
curl -s -X POST http://192.168.2.2:5002/api/servo/1 \
     -H 'Content-Type: application/json' -H 'Cookie: session=<captured>' \
     -d '{"angle":90}'
```

## Expected Result

A passive capture of the login flow yields the operator username and password in cleartext, plus the session cookie, and the replayed cookie authorizes servo and command requests against the cloud API without any further authentication.

## How It Should Be

Serve the cloud API over TLS and remove `usesCleartextTraffic`, so the app only ever connects over HTTPS. Add certificate pinning to the client so a rogue proxy cannot transparently intercept. Mark the session cookie `Secure` and `HttpOnly` so it is never transmitted in cleartext.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Transport | HTTPS-only, drop `usesCleartextTraffic` | End cleartext credentials and cookies on the wire |
| Client | Certificate pinning | Prevent transparent proxy interception |
| Cookie | `Secure` + `HttpOnly` flags | Keep the session token off cleartext channels |

## Verification Checklist

- [ ] `AndroidManifest.xml` sets `usesCleartextTraffic="true"`
- [ ] The login `POST /login` body shows the operator credentials in a cleartext capture
- [ ] The `Cookie: session=...` header is visible in cleartext on `/api/*` requests
- [ ] A replayed captured cookie authorizes `/api/servo` / `/api/command` with no login

## Related Vulnerabilities

- [IoT:I7 — Insecure Data Transfer and Storage](../IoT/IoT7_Insecure_Data_Transfer_and_Storage.md): the device side is cleartext on every channel too, so the whole path is unencrypted end to end.
- [M9 — Insecure Data Storage](M9_Insecure_Data_Storage.md): the same session cookie is also stored at rest in plaintext, so it can be recovered off-device as well as on the wire.
- [API10:2023 — Login Input SQL Injection](../API/API10_Unsafe_Consumption_of_APIs.md): an attacker who cannot sniff can still obtain a session by bypassing the login filter.
