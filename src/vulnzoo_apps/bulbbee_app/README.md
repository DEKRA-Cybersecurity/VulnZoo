# BulbBee Android app (BULB-APP)

Minimal companion controller for the BulbBee smart light. It is a BLE client of the device's Lighting Control service (`0xFF30`, characteristics Control `0xFF31` / State `0xFF32`) and provisioning service (`0xFF40`, Auth `0xFF41` / Config `0xFF42`).

**Intentional vulnerabilities (training):**

- **M1 / CWE-798**: the factory pairing PIN `8080` is hardcoded in `MainActivity.java`, extractable from the APK and identical on every unit (client side of BULB-01).
- **M9 / CWE-312**: the home WiFi PSK and cloud token are stored in plaintext `SharedPreferences` and logged to Logcat (client side of BULB-05).

**Status:** builds. `./gradlew :app:assembleDebug` (AGP 9.2.1, Gradle 9.4.1, JDK 21) produces `app/build/outputs/apk/debug/app-debug.apk`. The M1/M9 findings are verified by inspection and present in the APK (`unzip -p ... classes.dex | strings | grep 8080`). On-device BLE control needs an Android device with the BulbBee peripheral in range.

Build:

```sh
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ./gradlew :app:assembleDebug
```

Finding doc: [`../../docs/BulbBee/Vulns/Mobile/BULB-APP-hardcoded-pin-and-plaintext-storage.md`](../../docs/BulbBee/).
