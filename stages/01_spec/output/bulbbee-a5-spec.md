# BULB-A5 - Secret store (simulated flash) (spec)

Target: `BULB-A5` (Phase 3, secure baseline).

## Why it matters

The rootfs files that simulate the bulb's flash, so an attacker can attempt recovery: the session secret, the local key, and the owner binding. A5 defines where each secret lives and its intended protection, which the storage weaknesses (BULB-02 PSK, BULB-03 local key, BULB-04 token, BULB-05 owner binding) later violate.

## Design (ponytail: one source of truth)

- **Single root secret:** the per-device secret at `/opt/bulbbee/.session_secret` (0600, created by `session_token`) is the one stored high-value secret. The session token (BULB-A3) and the LAN/TCP local key (BULB-A4) both DERIVE from it in secure mode, so there is no second key file to leak or drift. The layout documents this derivation rather than storing redundant keys.
- **Net-new: owner binding store.** `/opt/bulbbee/secrets/owner.json` records the account the device is bound to (owner id + bound-at). Robust (secure): binding is write-once and the device enforces it (`check_owner` requires a match). Default (vulnerable, the BULB-05 substrate): the device does not enforce, any client is accepted, binding lives only in the app.
- **Store directory:** `/opt/bulbbee/secrets/` created 0700 (simulated flash region).
- **Layout map:** a `LAYOUT` constant naming every secret, its path, mode, and intended protection, so the eval and the Phase-4 findings can point at it.

## Components

- New device module `secret_store.py`: `ensure_store`, `LAYOUT`, `bind_owner`/`owner`/`check_owner`. Non-invasive, no rewire of the working provisioning path (the default `check_owner` returns True, so behavior is unchanged until a plane opts in).

## Acceptance criteria

1. `LAYOUT` names the session secret, local key (derived), provisioning cache, and owner binding, each with a path and a restrictive mode (<= 0o600 for files, 0o700 for the dir).
2. `bind_owner` is write-once: a second `bind_owner` with a different id keeps the first binding.
3. `check_owner(claim, secure=True)` requires the claim to equal the bound owner; `check_owner(claim, secure=False)` always returns True (the BULB-05 substrate).
4. `ensure_store` creates `/opt/bulbbee/secrets/` at 0700.
5. `py_compile` clean; `--selfcheck` passes.
