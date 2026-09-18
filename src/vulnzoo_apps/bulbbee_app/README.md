# BulbBee Android app (BULB-APP)

Companion controller for the BulbBee smart light. It is a BLE client of the device's Lighting Control service (`0xFF30`, characteristics Control `0xFF31` / State `0xFF32`) and provisioning service (`0xFF40`, Auth `0xFF41` / Config `0xFF42`).

## Structure

A single-activity, fragment-based app with a bottom-nav shell:

- `MainActivity` - navigation host (bottom nav + `NavController`), no business logic.
- `ble/BleController` - the GATT transport (scan, connect with no bonding, one-at-a-time op queue).
- `ble/BleRepository` - single owner of the transport, exposes connection / state / provisioning as `LiveData`.
- `ui/LightViewModel` - activity-scoped view model shared by every fragment.
- `ui/` fragments - `ScanFragment` (pair), `LightFragment` (orb + wheel + brightness bar + temperature ramp + presets, driving `0xFF31`), `ScenesFragment` (the four firmware scenes), `SetupFragment` (WiFi onboarding), `RoutinesFragment` (empty-state placeholder, no backing).
- `ui/` custom views - `BulbOrbView`, `ColorWheelView`, `BrightnessBarView`, `TempRampView` (the redesigned control surface).

Wheel / brightness / temperature drags are throttled to ~20 Hz in `LightFragment`, so a drag does not flood the bulb with Control writes (BULB-07 is a scene-payload DoS finding).

## Intentional vulnerabilities (training)

- **M1 / CWE-798**: the factory pairing PIN `8080` is hardcoded in `ui/SetupFragment.java` (prefilled on the setup screen), extractable from the APK and identical on every unit (client side of BULB-01).
- **M9 / CWE-312**: the home WiFi PSK and cloud token are stored in plaintext `SharedPreferences` and logged to Logcat in `SetupFragment.storeCredentials` (client side of BULB-05).

The redesign only changed what the setup screen says and asks for, not where the secret ends up.

## Status

The BLE plumbing, the light control (Control `0xFF31`, State notify `0xFF32`) and the WiFi provisioning (Auth `0xFF41`, Config `0xFF42`) are implemented. On-device BLE control needs an Android device with the BulbBee peripheral in range.

Build:

```sh
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ./gradlew :app:assembleDebug
```

Dependencies: AndroidX Navigation, Lifecycle (ViewModel/LiveData), RecyclerView, ConstraintLayout and Material 3 (see `gradle/libs.versions.toml`). Produces `app/build/outputs/apk/debug/app-debug.apk`; the M1/M9 findings are verifiable in the APK (`unzip -p ... classes.dex | strings | grep 8080`).

Finding doc: [`../../docs/BulbBee/Vulns/Mobile/BULB-APP-hardcoded-pin-and-plaintext-storage.md`](../../docs/BulbBee/).
