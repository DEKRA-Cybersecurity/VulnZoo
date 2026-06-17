---
id: M6
title: "Inadequate Privacy Controls"
category: Mobile
status: DONE
severity: Medium
owasp: "Mobile M6 - Inadequate Privacy Controls"
cwe: "CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor) / CWE-313 (Cleartext Storage of Sensitive Information) / CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"
source_docs:
  - "CareOtter_App.md (patient monitoring app, BLE + Cloud API client)"
  - "Vulns/Mobile/M5_Insecure_Communication.md (cleartext transport facet reused by the upload)"
affected_components:
  - "vulnzoo_apps/careotter_app/app/src/main/AndroidManifest.xml - ACCESS_FINE_LOCATION false justification, BLUETOOTH_SCAN neverForLocation"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/MainActivity.java - requestPermissions rationale dialog, getLastKnownLocation, postReadingWithLocation"
  - "cloud_api/careotter/api_server/app.py - POST /api/vitals/readings (submit_vitals_reading)"
  - "cloud_api/careotter/api_server/services/database_service.py - vitals_readings latitude/longitude, store_vitals"
verified_date: ""
---

# M6 - Inadequate Privacy Controls

> **Status:** DONE
> **OWASP:** Mobile M6 - Inadequate Privacy Controls
> **CWE:** CWE-359 / CWE-313 / CWE-200
> **Severity:** Medium

---

## Why It Matters

The CareOtter patient app handles Protected Health Information (PHI): a patient's heart rate and blood-oxygen readings, tied to their account. OWASP Mobile M6 is about what an app does with personal data beyond the headline function: whether it collects more than it needs, whether it is honest with the user about why, and whether it protects what it gathers. CareOtter fails all three. It collects the phone's precise GPS on every reading, it justifies the location permission with a reason that is provably false, and it ships those coordinates to the cloud bundled with the PHI where they are stored verbatim.

Location is not needed to monitor a heart rate over Bluetooth. The app asks for it anyway, tells the user it is "required for BLE device scanning", and then uses it for something else entirely. That gap between stated purpose and actual use is the defining shape of an inadequate privacy control. The harm is concrete: anyone who can read the readings table (for example through the M4 SQL injection on the sibling GET endpoint, see more on [[M4_Insufficient_Input_Output_Validation]]) recovers not just a patient's vitals but a timestamped trail of exactly where that patient was each time a reading was taken.

---

## OWASP Classification

| Category | Role |
|---|---|
| **M6 - Inadequate Privacy Controls** | Primary - the app over-collects precise geolocation, misrepresents why it needs the permission, bundles the location with PHI, and the backend persists it with no masking or consent gate |
| **M5 - Insecure Communication** | Contributing - the upload rides the same cleartext HTTP channel (`usesCleartextTraffic="true"`), so the over-collected coordinates are also exposed in transit. Owned by [[M5_Insecure_Communication]] |
| **M4 - Insufficient Input/Output Validation** | Contributing - the same `vitals_readings` rows (now including lat/lon) are exfiltrated through the UNION SQL injection on `GET /api/vitals/readings`. Owned by [[M4_Insufficient_Input_Output_Validation]] |

**Why M6 over M5.** M5 is about the channel being interceptable. The defect here exists even on a perfectly encrypted channel: the app should not be collecting precise location for a BLE heart-rate monitor at all, and it should not be lying to the user about the reason. That is a data-minimization and transparency failure, which is M6's defined scope. Cleartext transport is a real but secondary aggravator and is documented under M5.

---

## 6.1 - The location permission is justified by a false reason (dark pattern)

On Android 12 and above, a Bluetooth LE scan does not require location permission as long as the app declares that it does not derive location from BLE. CareOtter makes exactly that declaration, then turns around and asks for precise location anyway, citing the scan as the reason.

The manifest declares `BLUETOOTH_SCAN` with `neverForLocation`, which is the app asserting on the record that it does not need location for scanning:

```xml
<!-- AndroidManifest.xml -->
<uses-permission android:name="android.permission.BLUETOOTH_SCAN"
    android:usesPermissionFlags="neverForLocation" tools:targetApi="s" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<!-- VULNERABILITY M6 ... justified to the user as "required for BLE device
     scanning" - a false rationale ... actually used to capture precise GPS -->
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

At runtime the app presents a rationale dialog whose text repeats the false reason before the system prompt appears:

```java
// MainActivity.requestPermissions()  - dark pattern, not a real privacy control
new androidx.appcompat.app.AlertDialog.Builder(this)
        .setTitle(R.string.location_rationale_title)        // "Location needed to find your device"
        .setMessage(R.string.location_rationale_message)    // "...to discover and connect to your CareOtter device..."
        .setCancelable(false)
        .setPositiveButton(R.string.location_rationale_accept, (d, w) -> doRequestPermissions())  // Accept -> request location
        .setNegativeButton(R.string.location_rationale_cancel, (d, w) -> redirectToLogin())        // Cancel -> back to login
        .show();
```

![[m6_location_needed.png]]

The dialog is a dark pattern, not a consent control. It cannot be dismissed (`setCancelable(false)`), and its only choices are Accept, which proceeds to the location request, or Cancel, which clears the stored session and ejects the user back to the login screen. The app is therefore unusable without granting location, which is grant-or-leave coercion rather than a genuine choice. Once the permission is present, denying the OS prompt afterward does not change what the app collects. The stated purpose ("find your device") and the real purpose (GPS capture for upload) do not match, which is the transparency failure at the heart of M6.

---

## 6.2 - Precise GPS is over-collected and bundled with PHI

Every BLE vitals notification triggers a location read and an upload. The coordinates come from `getLastKnownLocation` at full precision - no rounding, no coarsening to city level, no truncation of decimal places:

```java
// MainActivity.getLastKnownLocation()
LocationManager lm = (LocationManager) getSystemService(LOCATION_SERVICE);
Location loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
if (loc == null) loc = lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
return new double[]{ loc.getLatitude(), loc.getLongitude() };   // full precision
```

The reading and the location are then serialized into one request body and POSTed together, so the patient's vitals and their exact position travel and land as a single record:

```java
// MainActivity.postReadingWithLocation()
JSONObject body = new JSONObject();
body.put("device_mac", mac);
if (bpm  > 0) body.put("bpm", bpm);
if (spo2 > 0) body.put("spo2", spo2);
if (loc != null) { body.put("lat", loc[0]); body.put("lon", loc[1]); }   // PHI + precise location, one payload
// POST apiUrl + "/api/vitals/readings"  (Bearer token, Content-Type application/json)
```

Location is not used by any feature of the app. It is displayed nowhere, it gates nothing, and it is irrelevant to BLE monitoring. It is collected solely because the permission was obtained, which is the textbook definition of over-collection.

> As soon as the patient connects to the device, the app starts communicating its position.

![[m4_post_readings_position_leaked.png]]

![[m4_db_position_columns.png]]

---

## 6.3 - The backend persists the coordinates verbatim

The cloud endpoint that receives the upload writes the coordinates straight into the `vitals_readings` row. There is no masking, no precision reduction, and no check that the patient ever consented to location collection:

```python
# app.py
@app.route('/api/vitals/readings', methods=['POST'])
@token_required
def submit_vitals_reading():
    data = request.get_json(force=True, silent=True) or {}
    device_mac = (data.get('device_mac') or '').upper()
    ...
    db.store_vitals(data, device_mac=device_mac)   # stores lat/lon as-is
```

```python
# database_service.store_vitals()  - lat/lon persisted exactly as received
INSERT INTO vitals_readings
(device_mac, timestamp, bpm, spo2, source, latitude, longitude)
VALUES (?, ?, ?, ?, ?, ?, ?)
# ... float(data.get('lat')) ... float(data.get('lon'))
```

The `vitals_readings` table now carries `latitude REAL` and `longitude REAL` columns alongside the clinical fields. Because the location is co-located with PHI in the same table, every path that reads vitals also reads the patient's movements - including the M4 UNION SQL injection on the GET form of this very route.

---

## Attack flow - location trail recovery

1. **Install and grant.** The patient installs the app, sees "Location needed to find your device", and grants location, believing it is for Bluetooth.
2. **Silent collection.** From then on, every reading taken while monitoring uploads the phone's precise GPS with the vitals. The patient is monitored at home, at work, at a clinic - each session pins a coordinate.
3. **Exfiltration.** An attacker who reaches the readings table - for example via the M4 UNION SQL injection on `GET /api/vitals/readings` (see [[M4_Insufficient_Input_Output_Validation]]) - now selects `latitude, longitude, timestamp` and reconstructs a timestamped location history for the victim, on top of the vitals.
4. **Impact.** A heart-rate dataset that the patient expected to stay clinical becomes a surveillance log of where they live, work, and seek care.

> This unusual behaviour can be detected, firstly by questioning whether the app really needs to access the mobile device’s location and why (normally, the medical device’s location would already be known). And secondly, by analysing the data packets sent by the mobile phone via the app to the cloud.

![[m6_capture_position_leak.png]]

---

## Reproduction - hands-on

Backend (server side, no app required):

```bash
# Bring the API up
cd src/cloud_api/careotter && ./cloudctl.sh --vulnerable restart

# Confirm the new columns exist (inside the api container)
docker compose exec careotter-api sqlite3 /app/data/careotter.db ".schema vitals_readings"
#   -> latitude REAL, longitude REAL present

# Submit a reading with precise coordinates, authenticated as a patient
TOKEN=<patient_jwt>
curl -s -X POST http://localhost:5002/api/vitals/readings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"device_mac":"AA:BB:CC:DD:EE:FF","bpm":180,"spo2":95,"lat":40.4168,"lon":-3.7038}'
#   -> {"status":"ok","device_mac":"AA:BB:CC:DD:EE:FF"}

# Read it back - coordinates stored unmasked
docker compose exec careotter-api sqlite3 /app/data/careotter.db \
  "SELECT bpm,spo2,latitude,longitude FROM vitals_readings ORDER BY id DESC LIMIT 1;"
#   -> 180|95|40.4168|-3.7038
```

App side:

1. `cd src/vulnzoo_apps/careotter_app && ./gradlew assembleDebug` and install on a device or emulator with a location fix set.
2. Log in as a patient and open the monitor. The misleading location dialog appears on first launch.
3. Grant location, connect to the `CareOtter_HR` device, and let a few readings arrive.
4. `adb logcat -s MainActivity` shows `reading upload http 200 gps=<lat>,<lon>`, and the backend `SELECT` above returns the device-supplied coordinates.

---

## Verification Checklist

- [ ] `vitals_readings` has `latitude` and `longitude` columns after startup (fresh DB and migrated DB).
- [ ] `POST /api/vitals/readings` with a valid patient token persists the exact lat/lon (no rounding or masking).
- [ ] The app shows the misleading "find your device" rationale before requesting `ACCESS_FINE_LOCATION`.
- [ ] `BLUETOOTH_SCAN` declares `neverForLocation` (static proof the scan does not need location).
- [ ] Readings uploaded after granting location carry non-null coordinates; denying location still uploads the reading with null coordinates (collection is not consent-gated).
- [ ] The M4 UNION SQL injection on `GET /api/vitals/readings` still works (vuln preserved), and can now also dump `latitude`/`longitude`.

---

## Remediation

For reference only - do not apply in the lab.

- Remove `ACCESS_FINE_LOCATION`/`ACCESS_COARSE_LOCATION`. A BLE heart-rate monitor does not need them on Android 12+ once `BLUETOOTH_SCAN` is `neverForLocation`.
- Stop collecting location entirely (data minimization). If a feature genuinely needs it, ask with an honest rationale, make consent revocable, and gate collection on it.
- Never co-locate location with PHI by default. If stored at all, coarsen to the minimum useful precision and protect it as sensitive data.
- Drop the `latitude`/`longitude` columns from `vitals_readings` and reject those fields server-side.
