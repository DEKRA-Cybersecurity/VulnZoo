# BulbBee Android app (BULB-APP)

Minimal companion controller for the BulbBee smart light. It is a BLE client of the device's Lighting Control service (`0xFF30`, characteristics Control `0xFF31` / State `0xFF32`) and provisioning service (`0xFF40`, Auth `0xFF41` / Config `0xFF42`).

**Intentional vulnerabilities (training):**

- **M1 / CWE-798**: the factory pairing PIN `8080` is hardcoded in `MainActivity.java`, extractable from the APK and identical on every unit (client side of BULB-01).
- **M9 / CWE-312**: the home WiFi PSK and cloud token are stored in plaintext `SharedPreferences` and logged to Logcat (client side of BULB-05).

**Status:** source skeleton. The security findings are static (verified by inspection). Building an APK needs the standard Android scaffold (gradle wrapper, `gradle/libs.versions.toml` version catalog, resources), model it on `../careotter_app/`. The build (`gradlew assembleDebug`) and on-device BLE control are the remaining steps and need the Android toolchain and a device.

Finding doc: [`../../docs/BulbBee/Vulns/Mobile/BULB-APP-hardcoded-pin-and-plaintext-storage.md`](../../docs/BulbBee/).
