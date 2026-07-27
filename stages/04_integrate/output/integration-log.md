# Integration Log - canary (phase 0 functional bring-up)

Date: 2026-07-06
Pipeline: 01_spec -> 02_implement -> 03_document -> 04_integrate (this stage)

## Promoted code (Stage 02 -> src/)

| Artifact | Destination |
|----------|-------------|
| CGW service | `src/labs/canary/files/opt/canary/someip_gateway.py` |
| BCM service | `src/labs/canary/files/opt/canary/bcm_ecu.py` |
| UCI config | `src/labs/canary/files/etc/config/canary` |
| Init scripts | `src/labs/canary/files/etc/init.d/canary-gateway`, `canary-bcm` |
| Hooks | `src/labs/canary/files/usr/lib/vulnzoo-hooks/profile-init.d/{05,15,50,70}-canary-*.sh` |
| Reference client | `src/labs/canary/tools/someip_client.py` (not packaged) |
| Self-check | `src/labs/canary/tools/test_canary.py` (not packaged) |
| Lab contract | `src/labs/canary/CONTEXT.md` |

Executable bits set on hooks, init scripts, and `*.py`.

## Promoted docs (Stage 03 -> src/)

| Artifact | Destination |
|----------|-------------|
| Landing page | `src/docs/Canary/Canary.md` |
| Vulnerability roadmap | `src/docs/Canary/Vulns/README.md` |

## Repackaged overlay

`src/labs/vulnzoo/files/usr/lib/vulnzoo-devices/canary.tar.gz` rebuilt from `src/labs/canary/files` with `--exclude='__pycache__' --exclude='*.pyc' --exclude='*.md'`. Contents verified: `opt etc usr` only, no bytecode, no docs, no `tools/`.

## Registration (MWP discoverability)

| File | Change |
|------|--------|
| `shared/glossary.md` | added `canary` -> `Canary/` (Automotive), + ports 30509/udp SOME/IP and CAN |
| `src/AGENTS.md` | workspace map labs list, device -> doc-folder table, `AUTO-##` custom ID |
| `_config/promotion-map.md` | device -> paths row for `canary` |
| `_config/conventions.md` | `AUTO-##` added to the custom identifier scheme |
| `src/docs/PROJECT_OVERVIEW.md` | canary port rows |

## Base-image changes (build-time, not runtime overlay)

- `src/labs/vulnzoo/.config`: `kmod-can`, `kmod-can-mcp251x`, `kmod-can-raw`, `kmod-can-vcan`, `libsocketcan`, and `ip-full` enabled on disk. `ip-full` was added during this stage because busybox `ip` (even with `FEATURE_IP_LINK`) cannot run `ip link add type vcan` or `ip link set ... type can bitrate`, which the `50-canary-services.sh` bring-up needs. Without it even the simulation path fails and both services crash-loop. Still uncommitted, must be committed for a reproducible image build. `canutils` intentionally left unset (Model A).
- Device-tree overlays (`spi=on`, `mcp2515-can0/can1`) for the base-image boot config: NOT applied as a file. The bcm27xx boot config path and whether an overlay `config.txt` merges or replaces the image default were not confirmed here, so this remains a build-time step to resolve rather than a fabricated file that could clobber the image default. Recorded in the spec section 8.1.

## Verification

- `python3 src/labs/canary/tools/test_canary.py` -> `OK` (SOME/IP header and CAN frame round-trip, including Request ID echo).
- Live SetLock -> CAN -> state-file chain: not runnable in the authoring environment (no root for `modprobe vcan`). Commands to run it on the Pi or a root host are in `src/labs/canary/CONTEXT.md` and `Canary.md`.
- Device Manager loads any `<device>.tar.gz` generically (`cgi-bin/device-manager.sh` builds the tarball path from the device name), so `canary` needs no per-device backend entry. Only the WIP UI card gates click-to-load.

## Remaining before the lab is user-loadable and DONE

1. Commit the base-image `.config` change (and the pre-existing uncommitted CAN edits).
2. Resolve the bcm27xx `config.txt` overlay step (`spi=on` + `mcp2515-can0/can1`). `ip-full` is resolved (enabled in `.config`). A `make defconfig` / menuconfig pass at build reconciles `ip-full` dependencies.
3. On-Pi verification (load via Device Manager or SSH, run hooks, exercise the chain with real modules + a PC USB-CAN adapter).
4. UI: the `data-device="canary"` card in `devices.html` is intentionally WIP ("Soon", disabled). Enable it and add a `canary.html` page (model on `octobot.html`) once on-Pi verified.
5. Vulnerability roadmap (`AUTO-01`..`AUTO-05` + connected-car) stays `PENDING` until later phases.

## Stage cleanup

`stages/{01_spec,02_implement,03_document}/output/` cleaned after promotion, per project convention. This integration log is the durable record.

---

# Integration Log - canary (Jeep kill chain, AUTO-01/05/02)

Date: 2026-07-08
Pipeline: 01_spec -> 02_implement -> 03_document -> 04_integrate (this stage)
Spec: `stages/01_spec/output/canary-jeepchain-spec.md` (cleaned after this promotion).

## Promoted code (Stage 02 -> src/)

| Artifact | Destination | Change |
|----------|-------------|--------|
| CGW service | `src/labs/canary/files/opt/canary/someip_gateway.py` | token gate on SetLock, exposed mgmt `UpdateFirmware` (`:30510`, no auth, unsigned in vulnerable mode), `gw_policy` read, `RelayFrame` gated by `allow_raw`, `CANARY_MODE` |
| Init script | `src/labs/canary/files/etc/init.d/canary-gateway` | pass `CANARY_MODE`/`MGMT_PORT`/`SETLOCK_TOKEN`/`FW_KEY` env |
| UCI config | `src/labs/canary/files/etc/config/canary` | `mgmt_port`, `setlock_token`, `fw_key` |
| Firewall hook | `src/labs/canary/files/usr/lib/vulnzoo-hooks/profile-init.d/70-canary-firewall.sh` | open UDP `30510` |
| Reference client | `src/labs/canary/tools/someip_client.py` (not packaged) | token argument |
| Attacker tool | `src/labs/canary/tools/reflash_gw.py` (new, not packaged) | unsigned reflash + arbitrary CAN inject |
| Self-check | `src/labs/canary/tools/test_canary.py` (not packaged) | Jeep-chain gateway logic |

## Promoted doc (Stage 03 -> src/)

| Artifact | Destination |
|----------|-------------|
| Chain finding | `src/docs/Canary/Vulns/Automotive/AUTO-Jeep-Kill-Chain.md` |

## Doc sync (Layer 3 <-> Layer 4)

| File | Change |
|------|--------|
| `src/docs/Canary/Vulns/README.md` | AUTO-01/05/02 rows to IN PROGRESS, chain note links the doc, status and legend updated, CWEs kept distinct |
| `src/docs/Canary/Canary.md` | status blockquote, Status and certification framing reflect the chain, SetLock token note, `someip_client` examples carry the token |
| `src/docs/Canary/LAB_SETUP.md` | Part 5 `someip_client` lock/unlock examples carry the token |

## Repackaged overlay

`src/labs/vulnzoo/files/usr/lib/vulnzoo-devices/canary.tar.gz` rebuilt (`opt etc usr`, excludes bytecode/docs/tools). Confirmed the changed overlay files are inside: `someip_gateway.py`, `canary-gateway`, `config/canary`, `70-canary-firewall.sh`.

## Verification (authoring env)

- `python3 src/labs/canary/tools/test_canary.py` -> `OK` (token gate, invariant, unsigned-accept in vulnerable, signed-verify in secure).
- Socket-level integration harness (CAN socket monkeypatched, no `vcan` needed): a tokenless SetLock and a pre-reflash RelayFrame emit no CAN (the invariant), a tokened SetLock emits `LOCK_CMD`, unsigned firmware is accepted, and the post-reflash RelayFrame injects arbitrary ids and unlocks with no token. All pass.
- Method id note: `RelayFrame` is `0x0003` (spec Section 7.3 said `0x0002`, which collided with `GetLockState`).

## Deployment and on-Pi verification

Deployment done by the user, then verified from the PC against the Pi on 2026-07-08. On-Pi verification passed in simulation (`vcan0`, one CAN module still defective): a tokenless SetLock is rejected with no actuation, a pre-reflash RelayFrame is refused and puts nothing on the bus (the invariant), the unsigned firmware is accepted, the post-reflash RelayFrame unlocks with no token, and an unrelated id `0x7DF` is relayed (no whitelist). The shipped `someip_client.py` and `reflash_gw.py` produce the same. Status flipped to DONE across the finding doc, the `Vulns/README.md` rows, and `Canary.md`. The physical-bus `candump` on real modules is pending the CAN module replacement, the chain itself is bus-agnostic (it drives the gateway, not the transport).

## Deferred (unchanged)

- Exact R155 Annex 5 clause numbers: mapped by named category, not invented. Pin against the regulation text.
- Secure-mode internal-only binding realism, the AGL pivot, and token theft from AGL: the AGL-live phase.

## Stage cleanup

`stages/{01_spec,02_implement,03_document}/output/` cleaned after this promotion, per project convention. This log is the durable record.

---

# Enhancement - canary dynamic-analysis surface (2026-07-08)

Direct edit to `src/` (not a new stages run), to enable a realistic dynamic-analysis path for the Jeep chain walkthrough, per the advisor review.

## Changes

| File | Change |
|------|--------|
| `src/labs/canary/files/opt/canary/someip_gateway.py` | standard SOME/IP return codes (E_UNKNOWN_SERVICE / E_UNKNOWN_METHOD / E_MALFORMED_MESSAGE / E_NOT_OK) so a black-box tester can enumerate; a SOME/IP-SD FindService responder (offers 0x1401) gated by `sd_enabled` |
| `src/labs/canary/files/etc/config/canary` | `sd_enabled '1'`, `sd_port '30490'` |
| `src/labs/canary/files/etc/init.d/canary-gateway` | pass `CANARY_SD_ENABLED` / `CANARY_SD_PORT` env |
| `src/labs/canary/files/usr/lib/vulnzoo-hooks/profile-init.d/70-canary-firewall.sh` | open UDP 30490 (SD) |
| `src/labs/canary/agl/carctl`, `agl/lock-ui/` (new, on AGL) | the car's central-locking control on the AGL head unit (CLI + IVI web UI), whose use produces the legitimate traffic to sniff (replaced an earlier PC-side generator, `head_unit_sim.py`, which was retired as artificial) |
| `src/labs/canary/tools/test_canary.py` | assert the SD OfferService is well-formed |

## Doc falsification pass (Layer 3 <-> Layer 4)

The change made two committed claims false, corrected in the same edit:
- "the reflash is the only path to actuation" -> split: arbitrary CAN (any other ECU) still needs the reflash, but lock actuation also falls to sniff-and-replay of the cleartext SetLock token (OWASP I7). Fixed in the finding doc invariant and `Vulns/README.md`.
- walkthrough Phase 2 "others -> no response" and Phase 3 "RelayFrame is the method the sweep missed" -> with the error codes the sweep now maps the surface and reveals RelayFrame exists (E_MALFORMED). Phase 2 rewritten with the dynamic path (sniff, SD FindService, active enumeration), Phase 3 wording fixed.
- `Vulns/README.md` OWASP I7 row and AUTO-02 row updated for the sniffable token / SOME/IP replay. `CONTEXT.md` synced (SD port, error codes, the AGL head-unit control).

## Verification

- `python3 src/labs/canary/tools/test_canary.py` -> `OK`.
- Socket integration harness (CAN monkeypatched): error codes correct on both ports (unknown service 0x02, unknown method 0x03, RelayFrame short 0x09, tokenless SetLock 0x01), the invariant holds (no CAN before reflash), SD FindService returns an OfferService advertising 0x1401, reflash + post-reflash inject still work. All pass.
- Repackaged `canary.tar.gz` (SD + error-code markers confirmed inside).
- On-Pi verification (2026-07-08, simulation / vcan0): full attack chain passed from the PC. SD FindService returns the OfferService for 0x1401, the error-code sweep enumerates the methods (SetLock E_NOT_OK, GetLockState RESPONSE, RelayFrame E_MALFORMED, unknown E_UNKNOWN_METHOD), a legit SetLock captured with tcpdump on the wire exposes the token in cleartext (I7), the tokenless SetLock is rejected, the invariant holds (no CAN before the reflash), the unsigned firmware is accepted, and the post-reflash RelayFrame unlocks with no token and relays an arbitrary id. All pass. Physical-bus candump pending the CAN module.

---

# OWL-D1 - Fix dead doc routing docs/IP Camera -> docs/OwlCam (2026-07-27)

Target from `stages/TARGET.md` (OWL-D1). Divide-and-conquer pass: `01_spec -> 04_integrate` (02/03 N/A, no vuln code).

## Problem

The owlcam Layer 3 folder is `src/docs/OwlCam/`, but Layer 0, both Layer 2 `CONTEXT.md` files, and the factory registration files routed to a non-existent `docs/IP Camera/`. The whole owlcam doc chain was dead.

## Changes (path references only: `docs/IP Camera` -> `docs/OwlCam`)

| File | Change |
|------|--------|
| `src/AGENTS.md` | device->folder map row: link text + percent-encoded URL (`docs/IP%20Camera/`) |
| `src/labs/owlcam/CONTEXT.md` | Inputs table Layer 3 rows + References section |
| `src/cloud_api/CONTEXT.md` | doc references + "understand cloud vulnerabilities" routing row |
| `src/cloud_api/owlcam/CONTEXT.md` | Layer 3 input row + References |
| `shared/glossary.md` | device->doc-folder map cell `` `IP Camera/` `` -> `` `OwlCam/` `` |
| `_config/promotion-map.md` | device->product paths Docs cell |

Prose descriptions of the device type ("IP Camera Vulnerable Profile", "IP Camera Surveillance Lab", the `(IP camera)` label, "IP camera surveillance", the mermaid CAM label) left intact, they are not paths.

## Verification

`grep -rnE "docs/IP Camera|docs/IP%20Camera"` over the repo returns only the OWL-D1 backlog/spec descriptions, no live routing reference remains. All five target files exist under `docs/OwlCam/`.

## Stage cleanup

`stages/01_spec/output/owl-d1-spec.md` cleaned after promotion, per convention. This log is the durable record.

---

# OWL-D2 - YAML frontmatter on OwlCam vuln docs (2026-07-27)

Target from `stages/TARGET.md` (OWL-D2). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code).

## Change

Added a collection-level YAML frontmatter block (the 8 convention fields plus a compact per-finding status list) to each aggregate vuln doc. The OwlCam docs aggregate many findings per file, so the frontmatter is per-file, not per-finding. A per-finding split (CANary style) is a larger refactor, out of OWL-D2 scope.

| File | id | status |
|------|----|--------|
| `IoT (Camera)/Vulnerabilities.md` | OWLCAM-IOT | IN PROGRESS |
| `API/Vulnerabilities.md` | OWLCAM-API | IN PROGRESS |
| `Mobile/Vulnerabilities.md` | OWLCAM-MOBILE | DONE |

Not touched (not vuln findings): `README.md`, `Mobile/ARCHITECTURE_SSE_C2.md`, `Mobile/C2-HTTP-SSE-Migration.md`.

## Verification

All 3 files begin with `---` at byte 0, the YAML parses (`yaml.safe_load`) with keys `id/title/category/status/severity/owasp/cwe/affected_components/findings`, and the original H1 heading follows. The API file's pre-existing leading blank line was dropped so the frontmatter is byte 0.

## Stage cleanup

`stages/01_spec/output/owl-d2-spec.md` cleaned after promotion. This log is the durable record.

---

# OWL-D3 - Standardize status badges (2026-07-27)

Target from `stages/TARGET.md` (OWL-D3). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code).

## Change

Normalized the non-standard inline status badges in `docs/OwlCam/API/Vulnerabilities.md` to the canonical `DONE` / `IN PROGRESS` / `PENDING` (AGENTS.md convention). IoT and Mobile docs already used only standard badges.

| Old badge | Finding | New |
|-----------|---------|-----|
| `NOT DONE` | API3 mass-assignment | `PENDING` |
| `NOT DEVELOPED` (x3) | API4, API6, API7 | `PENDING` |
| `NOT DEVELOPED YET` | API4 demo | `PENDING` |
| `ATTACK DOCUMENTATION PENDING` | API5 | `DONE` (badge was stale, section carries a full demo with 5 screenshots) |
| `PENDING REVIEW` | API8 Attack Vector #2 (system logs) | `IN PROGRESS` |

Left as-is: `> **CSRF is not included in the OWASP API Top 10...**` (explanatory note, not a status badge).

## Frontmatter reconciliation

`API8` in the D2 `findings` list moved `DONE -> IN PROGRESS`: the primary finding (user enumeration) is DONE but Attack Vector #2 is IN PROGRESS, so the body badges and the frontmatter now agree across all ten API findings.

## Verification

`grep -E "NOT DEVELOPED|NOT DONE|PENDING REVIEW|DOCUMENTATION PENDING"` over the OwlCam docs returns nothing. All 14 body badges are `DONE` / `IN PROGRESS` / `PENDING`.

## Stage cleanup

`stages/01_spec/output/owl-d3-spec.md` cleaned after promotion. This log is the durable record.

---

# OWL-D4 - Fix broken Obsidian wikilinks (2026-07-27)

Target from `stages/TARGET.md` (OWL-D4). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code).

## Change

15 broken links fixed across the 3 vuln docs (each old string asserted to match exactly once):

- Legacy note names `X - Vulnerabilities and features` -> path-qualified `<folder>/Vulnerabilities`. The three docs share the basename `Vulnerabilities.md`, so the folder path disambiguates the wikilink.
- Self-references that were written as cross-file links -> same-file `[[#Heading|alias]]` (API7, API1 in the API doc, M9 in Mobile, IoT4 in IoT).
- Same-file anchor drift matched to the real heading text (API3, Attack Vector #2, API8 were missing the `:` / `#`).
- Junk links: two `app://obsidian.md/index.html` (`admin_access.js` -> italic, the API3 markdown link -> a wikilink), one `vscode-file://` (`limit` -> a code span), and an empty-anchor Mobile link -> `[[Mobile/Vulnerabilities|Mobile vulnerabilities]]`.

Left as-is (already valid same-file anchors): `[[#3. Insecure JWT]]`, `[[#1. Userinfo leak]]`.

## Verification

`grep -E "Vulnerabilities and features|app://obsidian|vscode-file://"` over the OwlCam docs returns nothing. Every wikilink resolves to a real file (path-qualified for cross-file) or a same-file heading, and each referenced heading exists.

## Stage cleanup

`stages/01_spec/output/owl-d4-spec.md` cleaned after promotion. This log is the durable record.

---

# OWL-D5 - README onboarding polish (2026-07-27)

Target from `stages/TARGET.md` (OWL-D5). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code).

## Change (`docs/OwlCam/README.md`)

- Added a "Hosts, ports and credentials" map table so the reader knows which host to use from where (device `192.168.2.1`, Docker host `192.168.2.2`, emulator alias `10.0.2.2`, API port `5000`).
- Made the vague device credential explicit: `root` / `12345678` (verified live this session, `admin` is denied).
- Fixed setup paths: `cd cloud_api` -> `cd cloud_api/owlcam` (two occurrences), `cd vulnzoo_app` -> `cd vulnzoo_apps/owlcam_app`, `com.example.vulnzooapp/.MainActivity` -> `com.example.owlcamapp/.MainActivity`.
- Mermaid SSH node `admin:12345678` -> `root:12345678` for internal consistency with the map.

## Flagged (out of D5 scope, later C-family target)

- `IoT (Camera)/Vulnerabilities.md` still states the SSH default is `admin:12345678` and that testing it grants device access. The real OS login is `root` / `12345678` (`admin` SSH is denied). Doc<->code drift.
- `Mobile/Vulnerabilities.md` M9 uses `com.example.vulnzoo` for the shared_prefs path. Real applicationId is `com.example.owlcamapp`. Doc<->code drift.

## Verification

`grep` confirms the README no longer carries `admin:12345678`, a bare `cd cloud_api`, `vulnzooapp`, or the "default credentials or those you have configured" line. The corrected paths, package, and credentials are present, and `root` / `12345678` SSH was verified against the live Pi.

## Stage cleanup

`stages/01_spec/output/owl-d5-spec.md` cleaned after promotion. This log is the durable record.

---

# OWL-C1 - Document the strong undocumented API endpoints (2026-07-27)

Target from `stages/TARGET.md` (OWL-C1). Pass: `01_spec -> 04_integrate` (02 N/A, the endpoints already exist, this was a documentation gap).

## Change

Added the section `# Exposed Debug and Administrative Endpoints (additional findings)` to `docs/OwlCam/API/Vulnerabilities.md`, documenting six previously-undocumented findings, each with its OWASP 2023 category, CWE, a `curl` repro and the expected result. All confirmed by reading `cloud_api/owlcam/api_server/app.py`.

1. `POST /firmware/trigger_update` - unauthenticated OS command injection RCE via `shell=True` f-string (API8, CWE-78, Critical).
2. `POST /firmware/upload` - unauthenticated arbitrary upload + path traversal on the client filename (API8, CWE-434/CWE-22, High).
3. `GET /api/v1/debug/sessions?admin_id=` - weak-auth dump of all sessions including `_id`, the session token, enabling hijack (API9/API2, High).
4. `GET /sessions` - unauthenticated session metadata enumeration (API9, CWE-200, Medium).
5. `GET /camerasdb/delete` + `/restart` - unauthenticated destructive DB wipe over GET, also CSRF-able (API8/API5, High).
6. `POST /api/debug/decode_token` - unauthenticated JWT decode with signature verification off (API9, CWE-489, Low-Medium).

The frontmatter `findings` list was extended with these six endpoint findings (now 16 total). Badges are `IN PROGRESS`: documented from source review, not reproduced against the live lab (the containers are OOM-exited and the destructive / RCE findings must not be run against a working deployment).

## Correction to the earlier review

`/sessions` projects out `_id`, so it does NOT leak the session token. The token leak is `/api/v1/debug/sessions`, which serializes and returns `_id`. Documented accordingly.

## Verification

Frontmatter parses (`yaml.safe_load`, 16 findings), the section has 6 H2 findings with OWASP/CWE tags and `IN PROGRESS` badges, and no prose line carries a semicolon. All endpoint behaviors were confirmed against `app.py` (`UPLOAD_FOLDER=/vulnzoo/firmware`, `subprocess.Popen(..., shell=True)`, `find({}, {"_id": 0})` vs `find({})`, `drop_database`).

## Stage cleanup

`stages/01_spec/output/owl-c1-spec.md` cleaned after promotion. This log is the durable record.

---

# OWL-C3 - Fix OwlCam doc<->code drifts (2026-07-27)

Target from `stages/TARGET.md` (OWL-C3), broadened from API-only to all OwlCam doc<->code drifts (it absorbs the IoT1 and M9 drifts flagged during OWL-D5). 01_spec done inline (verified every drift against `app.py` and the JS/manifest). Pass: `01_spec -> 04_integrate`. This one carries a small `02_implement` code change.

## Doc fixes (docs match the code now)

| File | Drift | Fix |
|------|-------|-----|
| `API/Vulnerabilities.md` | `/admin/v2/userinfo` typo | `/api/v2/userinfo` |
| `API/Vulnerabilities.md` | `/profile-change_password` | `/profile/change_password` (real route) |
| `API/Vulnerabilities.md` | `/admin/assign-role` (x8, non-existent) | `/admin/roles` (real role-change route) |
| `API/Vulnerabilities.md` | CSRF claim "does not validate the origin" (x2) | corrected: the endpoint enforces a weak `Referer` substring check (any `/admin` in the header), bypassed by an attacker URL whose path contains `/admin` |
| `API/Vulnerabilities.md` | XSS payload reads `localStorage.getItem('jwt')` | `('auth')`, the real key (`login.js` `setItem('auth', ...)`) |
| `Mobile/Vulnerabilities.md` | shared_prefs path `com.example.vulnzoo` | `com.example.owlcamapp` (real applicationId) |
| `IoT (Camera)/Vulnerabilities.md` | SSH default `admin:12345678`, "testing confirms access" | keeps the Aviosys vendor default as context, states the lab OpenWRT login is `root:12345678` (verified live, `admin` is denied) |

## Code change (`app.py`, 02_implement)

The documented `/snapshot` session-only bypass (`session.status == 'active'`) never fired because no session document set `status`. Added `'status': 'active'` to all four session-creation sites (init admin session, the `/admin` flow, `/api/v1/login`, `/api/v2/login`), so the documented bypass is now reproducible and completes the chain from the OWL-C1 `/api/v1/debug/sessions` token leak to `/snapshot?session=<id>`.

## Verification

`grep` confirms no drifted string remains in the docs, the corrected routes/keys/credential are present, `app.py` carries four `'status': 'active'` and parses (`ast.parse` OK). The code change is static-verified only, live reproduction needs a `docker compose up --build` (the API/mongo containers are OOM-exited) and is pending.

## Stage cleanup

01_spec for OWL-C3 was performed inline (drift verification), no throwaway spec file. This log is the durable record.

---

# OWL-F3 - Fix C2 doc path/network drift and port narrative (2026-07-27)

Target from `stages/TARGET.md` (OWL-F3), last item of wave 1. 01_spec done inline (verified the real path, network name and port against the tree and the live `c2-server` container). Pass: `01_spec -> 04_integrate` (02 N/A, docs only).

## Change

| File | Drift | Fix |
|------|-------|-----|
| `Mobile/ARCHITECTURE_SSE_C2.md` | `cd cloud_api/c2_server`, README ref `cloud_api/c2_server/README.md` | `cloud_api/owlcam/c2_server` (the README exists there) |
| `Mobile/ARCHITECTURE_SSE_C2.md` | `docker network inspect cloud_api_c2_net` | `owlcam_c2_net` (real network, confirmed on the running container) |
| `Mobile/C2-HTTP-SSE-Migration.md` | `cd cloud_api/c2_server`, `docker network inspect cloud_api_c2_net` | `cloud_api/owlcam/c2_server`, `owlcam_c2_net` |
| `Mobile/Vulnerabilities.md` (M6) | "over standard HTTP ports" | "over HTTP on port 4999" |
| `Mobile/Vulnerabilities.md` (M6) | "(ports 80/443) bypasses firewall rules that would flag anomalous TCP connections on non-standard ports" (false and self-contradictory, 4999 is itself non-standard) | "(HTTP on port 4999) blends with the application's own API traffic and survives HTTP-aware egress filtering, where a raw TCP or WebSocket C2 protocol would stand out to a firewall" |

The port narrative now agrees across M6: the C2 is HTTP on 4999. The client-side ephemeral-port "connection laundering" section (about the mobile's source ports) is accurate and left as is.

## Verification

`grep` confirms no `cloud_api/c2_server`, `cloud_api_c2_net`, `ports 80/443` or "over standard HTTP ports" remain. The real network name `owlcam_c2_net` was read from the live `c2-server` container, and `cloud_api/owlcam/c2_server/README.md` exists.

## Stage cleanup

01_spec was performed inline. This log is the durable record. Wave 1 (D1-D5, C1, C3, F3) is complete.

---

# OWL-B1 - Fix IoT4 firmware crypto parity and finish the chain (2026-07-27)

Target from `stages/TARGET.md` (OWL-B1, wave 2). 01_spec done inline. The chain turned out to be broken three ways, not one:

1. **Crypto parity**: the device decrypted with legacy `EVP_BytesToKey` (`-aes-256-cbc -k`), while the doc/attacker encrypted with `-pbkdf2`. KDF mismatch, so every update failed with `bad decrypt` (confirmed with OpenSSL 3.0.17).
2. **Signature check on the encrypted file**: the device grep'd the ENCRYPTED download for a plaintext signature string, which encryption destroys, so the check could never pass on a properly-encrypted firmware.
3. **Corrupted reference blob**: the shipped `firmware-v1.0.3` had 61 `U+FFFD` sequences (mangled by a UTF-8 pass), un-decryptable with any recipe.

## Code (02_implement)

- `labs/owlcam/files/etc/init.d/update-firmware`: decrypt with `-pbkdf2` (matches the attacker recipe) and move the signature `grep` to AFTER decryption (grep `/tmp/update.sh`) so the trivially-forgeable check actually functions. The hardcoded HMAC secret, encryption key and trivial signature are preserved (the intentional weaknesses).
- Regenerated `cloud_api/owlcam/api_server/firmware/firmware-v1.0.3`: a legit emulated-update script carrying the signature comment, encrypted with `-pbkdf2`/`supersecret` (240 B, clean binary, 0 U+FFFD).
- Added `cloud_api/owlcam/api_server/firmware/.gitattributes` marking the blob `binary` to prevent the UTF-8 re-corruption.

## Doc (03_document)

- `IoT (Camera)/Vulnerabilities.md`: updated the device-script snippet (decrypt then grep, `-pbkdf2`), fixed the inspect command (`-pbkdf2 -k`), added an end-to-end reproduction + expected result, flipped the IoT4 badge and frontmatter `IN PROGRESS -> DONE`.

## Verification

- Crypto round-trip verified locally and DEVICE-SIDE on the live Pi (OpenSSL 3.0.17): `firmware-v1.0.3` and an equivalent `firmware-v1.0.4` decrypt, pass the signature grep and execute (the emulated update wrote `/etc/owlcam_firmware_version=1.0.3`, a malware payload would append a dropbear key). Negative control: the old legacy recipe on a pbkdf2 blob returns `bad decrypt`.
- The new `update-firmware` was deployed to the live Pi (md5 matches source), test artifacts cleaned.

## Deployment / pending

- `owlcam.tar.gz` needs a rebuild for fresh flashes (the user manages the tar.gz, not repackaged here). The live Pi already has the fixed script.
- The API image needs `docker compose up --build` to serve the regenerated `firmware-v1.0.3` and to exercise the full API-mediated walkthrough (upload via `/api/status` PUT, trigger via `/firmware/trigger_update`). The device-side chain is verified, the HTTP transport is pending the API being up (currently OOM-exited).

---

# OWL-B2 - Make the alg:none JWT bypass functional (2026-07-27)

Target from `stages/TARGET.md` (OWL-B2, wave 2). 01_spec inline. Decision: the `none` algorithm is an intended, classic JWT attack, so make it work rather than remove it.

## Root cause

`config.py` sets `JWT_ALLOW_NONE_ALGORITHM=True` and `jwt_service.decode_token` lists `'none'` in the algorithms, but it calls `jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=[...])` with the non-empty secret. PyJWT 2.13 rejects an `alg:none` token when a key is supplied (`InvalidKeyError: When alg = "none", key value must be None`), so the advertised bypass never fired.

## Code (02_implement)

`services/jwt_service.py`: when `JWT_ALLOW_NONE_ALGORITHM` and the token header declares `alg=none`, decode with `options={'verify_signature': False}` instead of the keyed decode. HS256 tokens still go through the keyed path (signature enforced).

## Doc (03_document)

`API/Vulnerabilities.md`: corrected the false claim "the server does not bypass signature validation" (it does, via `none`), and added a "Bypass: the `none` algorithm" subsection under API2 with the forge-an-admin-token repro.

## Verification

Isolation test (PyJWT 2.13): a forged `alg:none` token decodes to its payload, a normal HS256 token still decodes via the keyed path, and an HS256 token signed with the wrong secret is still rejected (`InvalidSignatureError`). `jwt_service.py` parses (`ast.parse`). Live end-to-end against the running API is pending `docker compose up --build` (the API/mongo containers are OOM-exited), so the doc badge is `IN PROGRESS`.

## Deployment / pending

The API image needs `docker compose up --build` to serve the fixed validator (same rebuild that OWL-C3 and OWL-B1 need).

---

# OWL-A1 - Re-scope the streaming surface: HTTP MJPEG :9090 canonical, RTSP re-scoped (2026-07-27)

Target from `stages/TARGET.md` (OWL-A1, wave 3). 01_spec inline.

## Decision (01_spec)

The RTSP `:8554-:8556` surface serves scrambled frames (v4l2rtspserver ships the loopback MJPEG as JPEG-over-RTP, RFC 2435, stripping the Huffman/quantization tables). The two candidate transports that render were: H264-over-RTSP, or declaring the HTTP MJPEG on `:9090` canonical. Checked the Pi live: it ships **no H264/H265 encoder** (only `rtph264pay/depay` payloaders and libav audio encoders, `libx264` is not built into libav), so H264-over-RTSP is not achievable on this build without adding packages. Decision: **HTTP MJPEG `http://192.168.2.1:9090/video` is the canonical decodable stream** (the cloud API already polls it), and RTSP is re-scoped to the raw unauthenticated insecure-services surface (feeds OWL-A2), documented as payload-mangled.

## Code (02_implement)

Found a packaging bug: `etc/init.d/camera-http` and the hook `usr/lib/vulnzoo-hooks/profile-init.d/23-camera-http.sh` were tracked `100644` (non-executable) while every sibling init script/hook is `100755`. On a fresh flash the hook cannot run and `/etc/init.d/camera-http start` fails with `Permission denied`, so the A0 bridge never auto-started. Fixed both to `100755` (`git update-index --chmod=+x`, staged). No streaming-config change was needed, the bridge itself already serves the intact frame.

## Doc (03_document)

- `IoT (Camera)/Vulnerabilities.md`: rewrote the IoT2 opening to name the two concrete plaintext services (HTTP MJPEG `:9090/video` and RTSP `:8554-:8556`) with an endpoint table and a no-auth `ffmpeg`/`ffplay` capture, added a note explaining the RFC 2435 RTSP corruption and why `:9090` is the reliable capture. Expanded `affected_components` to the real streaming stack (`virtual-cameras`, `camera-streamer`, `camera-http`, `camera_stream.py`). Flipped the IoT2 finding badge `PENDING -> IN PROGRESS` (endpoint documented and verified, the full sniff/replay attack is OWL-A2).
- `README.md`: fixed the architecture mermaid, added the `HTTP MJPEG :9090/video` node in the camera subgraph, repointed the API feed edge from `RTSP` to `HTTP` (the API consumes the bridge, not RTSP), added the attacker `capture MJPEG :9090` edge.
- `labs/owlcam/CONTEXT.md`: added the `:9090/video` bridge to the verification checklist and the Outputs table, marked RTSP as the raw insecure-services surface with a mangled JPEG/RTP payload.

## Verification

- Started the bridge on the live Pi and carved one frame from `http://127.0.0.1:9090/video`: valid JPEG (SOI/EOI), 640x480, 46243 bytes, **byte-identical to `/root/img_cam0.jpeg`** (md5 `fb672c7edc971ea0a0d55da296fb81fe`). This is the decodable frame the RTSP path cannot produce.
- After `chmod +x`, verified the packaged path the hook uses: `VULNZOO_DEVICE=owlcam sh .../23-camera-http.sh` -> `/etc/init.d/camera-http start` brings `:9090` up and the frame is still decodable (46243-byte valid JPEG).

## Deployment / pending

- `owlcam.tar.gz` needs a rebuild so fresh flashes ship the executable `camera-http`/hook and auto-start the bridge (the user manages the tar.gz, not repackaged here). The live Pi has the exec bits applied and the bridge running.
- OWL-A2 builds the full IoT2 attack (weak-cred RTSP discovery, plaintext sniff, replay) on top of this re-scoped surface.

---

# OWL-A2 - IoT2 real streaming attack: cleartext capture + replay (2026-07-27)

Target from `stages/TARGET.md` (OWL-A2, wave 3). 01_spec inline.

## Decision (01_spec)

Deviated from the original spec's "authenticated-but-weak RTSP" idea. After OWL-A1 established that the RTSP payload is mangled (RFC 2435) and the Pi ships no H264 encoder, cracking weak RTSP credentials to watch a scrambled stream is low value and would need an overlay change plus a re-flash. The IoT2 centerpiece is instead the cleartext transmission itself (CWE-319): the HTTP MJPEG feed on `:9090` renders and is unauthenticated, so a passive sniff recovers the live video verbatim. Unauthenticated RTSP on `:8554-:8556` is documented as the secondary open-service/enumeration target.

## Code (02_implement)

N/A. Both streaming services are insecure by design (unauthenticated, no TLS). No overlay change, so `owlcam.tar.gz` is untouched. All attacker tooling is standard (`nmap`, `nc`, `tcpdump`, `tshark`/Wireshark, `python3`) and the repro snippets live in the doc.

## Doc (03_document)

`IoT (Camera)/Vulnerabilities.md`, under IoT2:
- Recon and enumeration: `nmap` shows `:8554-:8556` (RTSP) and `:9090` (HTTP MJPEG) open with no auth, an unauthenticated `DESCRIBE` returns `200 OK` and a wrong path leaks the real `cam0` mount point.
- Passive capture (cleartext sniffing, CWE-319): `tcpdump` the `:9090` feed while a victim watches, reassemble with Wireshark "Follow TCP Stream" or `tshark --export-objects http`, carve JPEG frames on the SOI/EOI markers.
- Replay: a minimal MJPEG server re-serves the captured frame as a fake live feed, chained to the API `/snapshot` BOLA (this is the concrete path IoT3 owns).
- Flipped the IoT2 finding badge `IN PROGRESS -> DONE`.

## Verification

Live on the Pi. Captured `:9090` with `tcpdump` while a client pulled the feed, wrote a proper TCP reassembler (parses the pcap, orders server->client segments by seq, strips the HTTP header), then carved the first JPEG: **byte-identical to `/root/img_cam0.jpeg`, md5 `fb672c7edc971ea0a0d55da296fb81fe`**, so the live frame crosses the wire in cleartext and is recovered with no credentials. Unauthenticated RTSP `DESCRIBE` confirmed (no `401`, `cam0` mount point leaked in the 404 body). Replay re-serves that exact captured frame by construction, all test artifacts cleaned from `/tmp`.

## Deployment / pending

None. Doc-only target, no image rebuild. OWL-A3 (IoT3 de-stub) reuses this streaming surface plus the API access-control break.
