# BulbBee Android app (BULB-APP)

Companion controller for the BulbBee smart light. It is a BLE client of the device's Lighting Control service (`0xFF30`, characteristics Control `0xFF31` / State `0xFF32`) and provisioning service (`0xFF40`, Auth `0xFF41` / Config `0xFF42`).

## Structure

A single-activity, fragment-based app with a bottom-nav shell:

- `MainActivity` - navigation host (bottom nav + `NavController`) and the session gate (BULB-U1): login is the start destination, and the app is entered only on an active cloud session.
- `ble/BleController` - the GATT transport (scan, connect with no bonding, one-at-a-time op queue).
- `ble/BleRepository` - single owner of the transport, exposes connection / state / provisioning as `LiveData`.
- `ui/LightViewModel` - activity-scoped view model shared by every fragment.
- `ui/` fragments - `LoginFragment` (the mandatory sign-in barrier, BULB-U1, the start destination), `LightFragment` (orb + wheel + brightness bar + temperature ramp + presets driving `0xFF31`, over a state overlay that shows Connecting / Offline / a "Vincular device" prompt, and Forget device + Sign out in the header, BULB-U2/U3/U4), `ScenesFragment` (the four firmware scenes), `SetupFragment` (the link panel, BULB-U4: it connects over BLE and provisions WiFi + cloud server IP + a claim), `RoutinesFragment` (empty-state placeholder, no backing). The standalone Scan screen was retired (BULB-U5), its BLE scan is now the Light probe and its provisioning is the Setup link panel.
- `ui/` custom views - `BulbOrbView`, `ColorWheelView`, `BrightnessBarView`, `TempRampView` (the redesigned control surface).
- `cloud/` remote transport (BULB-R4) - `CloudClient` (dependency-free REST client of the BulbBee cloud API) and `CloudRepository` (singleton mirroring `BleRepository`). BULB-R6: a cloud sign-in (user + password) on the login screen controls a registered bulb over the cloud with Bluetooth off, and onboarding passes a cloud claim token via `pair_set` so the bulb binds to the account.
- `local/` direct-LAN transport (BULB-R5) - `LocalClient` (AES-CCM `:6668`, BouncyCastle) and `LocalRepository`. `LightViewModel` routes every control call to the active transport, so the UI stays transport-agnostic. Since BULB-U2 the control screen auto-selects BLE proximity then Cloud (Decision U-1), so the LAN `:6668` plane stays a built capability and an analysis/attack surface (`ui/TransportSelector` keeps the LAN-inclusive selector), not part of the conventional auto decision.

Wheel / brightness / temperature drags are throttled to ~20 Hz in `LightFragment`, so a drag does not flood the bulb with Control writes (BULB-07 is a scene-payload DoS finding).

## Connection lifecycle (BULB-U1..U5)

Login is the mandatory first screen (BULB-U1): the app needs the signed-in user before any control, and it persists the session (the bearer, base URL and user, in plaintext prefs) so the login screen is skipped while a stored session is usable, until Sign out (on the control screen) clears it. A client-side Forget device (also on the control screen) drops the app's memory of the provisioned device (the stored serial + per-user list) so the screen returns to the "Vincular device" state, leaving the cloud binding untouched. After login the control screen picks the channel automatically (BULB-U2, Decision U-1): if the peripheral answers a BLE scan it connects over BLE in the background, otherwise it uses the cloud for the account's bound bulb (resolved by the real device serial captured over BLE, `cloud_device_id`, not the first or seeded bulb the account owns), with the identical control UX. If the BLE link drops while it is the active transport (Bluetooth turned off, out of range), `LightViewModel` watches `BleRepository.connected()` and fails over to the cloud on its own, no re-login needed. A bound bulb that neither BLE nor the cloud reports live shows "Offline device" (BULB-U3, driven by the cloud `online` / `last_seen` field), and an account with no bound bulb shows a large "Vincular device" button that opens the Setup link panel and binds the bulb over BLE (BULB-U4). The LAN `:6668` plane stays available for analysis but is out of the automatic choice.

## Intentional vulnerabilities (training)

- **M1 / CWE-798**: the factory pairing PIN `8080` is hardcoded in `ui/SetupFragment.java` (prefilled on the setup screen), extractable from the APK and identical on every unit (client side of BULB-01).
- **M9 / CWE-312**: the home WiFi PSK and cloud token are stored in plaintext `SharedPreferences` and logged to Logcat in `SetupFragment.storeCredentials` (client side of BULB-05).
- **Cloud leg (M9 / insecure transport)**: the remote transport (`cloud/`) drives the bulb over plain HTTP and stores the bearer JWT in the same plaintext `SharedPreferences` (`cloud_jwt`) and Logcat (client side of BULB-CLD / BULB-R4).
- **Local plane (proximity = control)**: `local/LocalClient` embeds the static firmware key `bulbbee-local-16` (BULB-P03), so any app on the bulb's LAN drives it over AES-CCM `:6668` with no per-device key and no owner check (BULB-P06 carried into the app, BULB-R5).
- **Persisted session (M9, BULB-U1)**: the cloud bearer, base URL and user are saved in the same plaintext `SharedPreferences` and auto-resumed on launch, so a long-lived token in the clear survives restarts and re-authenticates with no re-login (an extension of the M9 cloud-leg storage, not a new finding).

The redesign only changed what the setup screen says and asks for, not where the secret ends up.

## Status

The BLE plumbing, the light control (Control `0xFF31`, State notify `0xFF32`) and the WiFi provisioning (Auth `0xFF41`, Config `0xFF42`) are implemented. On-device BLE control needs an Android device with the BulbBee peripheral in range. Wave 7 (BULB-U1..U5: login-first + persistent session + the automatic BLE-proximity-then-Cloud channel + the Offline and "Vincular device" states + Sign out) builds cleanly (`assembleDebug`); the full runtime flow needs a device with the peripheral in range and the cloud stack up.

Build:

```sh
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ./gradlew :app:assembleDebug
```

Dependencies: AndroidX Navigation, Lifecycle (ViewModel/LiveData), RecyclerView, ConstraintLayout, Material 3 and BouncyCastle (`bcprov-jdk18on`, for the AES-CCM `:6668` local plane) (see `gradle/libs.versions.toml`). Produces `app/build/outputs/apk/debug/app-debug.apk`; the M1/M9 findings are verifiable in the APK (`unzip -p ... classes.dex | strings | grep 8080`).

Finding doc: [`../../docs/BulbBee/Vulns/Mobile/BULB-APP-hardcoded-pin-and-plaintext-storage.md`](../../docs/BulbBee/).
