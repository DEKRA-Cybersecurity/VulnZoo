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

---

# OWL-A3 - IoT3 de-stub: camera stream reachable through the API BOLA (2026-07-28)

Target from `stages/TARGET.md` (OWL-A3, wave 3). 01_spec inline. This closes wave 3 (the streaming centerpiece).

## Decision (01_spec)

IoT3 (Insecure Ecosystem Interfaces) was a stub deferring to the API docs. The concrete ecosystem path it owns: the physical cameras are registered in the cloud API, and `/snapshot` authorizes by role (`admin`/`viewer`) with no per-camera ownership check, so a non-owner pulls any camera's live frame. This is the device-facing framing of the API1 BOLA, and it ties directly to the physical Pi camera ('Parking Lot', `c18a78a6ee98f183f51def10`, `http://192.168.2.1:9090/video`, the OWL-A1/A2 stream).

## Code (02_implement)

N/A. Reuses the existing API and streaming, no code change, no image rebuild.

## Doc (03_document)

`IoT (Camera)/Vulnerabilities.md`, IoT3 rewritten from one vague paragraph into a device-centric section: how `/snapshot` gates access (`session_required_html` only checks a session cookie exists, then a role-only check), the seeded camera table mapping owner to physical source (Parking Lot = the Pi), a forge-a-viewer-token repro, the verified results, cross-links to API1 (BOLA) and API2 (weak secret), and remediation. Flipped the IoT3 finding badge and the doc-level `status` to `DONE` (all four IoT findings are now DONE). Added `app.py (/snapshot)` to `affected_components`.

## Verification

Live on the running Docker stack (`vulnzoo-vulnerable` on `:5000`, `mongo` up). Read the seeded model: users admin(`admin`)/elliot(`viewer`)/john(`user`), john owns Greenhouse (`bd2218...`, active) and the Pi 'Parking Lot' (inactive). Forged an HS256 token with the known secret `supersecretkey` for each user and POSTed `/snapshot?camera=<john's Greenhouse>` with any existing `session_id` cookie:
- elliot (role `viewer`, NOT the owner) -> `HTTP 200 image/jpeg`, john's camera frame returned. BOLA confirmed.
- john (role `user`, the actual owner) -> `HTTP 403 Insufficient permissions`.
Authorization is role-based, ownership is never consulted, and the endpoint serves the physical Pi camera identically when active.

## Deployment / pending

None. Doc-only. Wave 3 (streaming centerpiece: A1, A2, A3) is complete.

---

# OWL-C2 - Implement or downgrade the prose-only API categories (2026-07-28)

Target from `stages/TARGET.md` (OWL-C2, wave 4). 01_spec inline. Containers were up, so API4 and API7 were verified live against the running stack.

## Decision (01_spec)

A code survey (not just the docs) changed the picture: two of the four categories were already implemented but undocumented, one was a hardcoded non-vuln, and one had no code at all.
- API4 (Unrestricted Resource Consumption): already real. `/api/v1/login` inserts a session on every POST before checking credentials and has no attempt cap, while `/api/v2/login` caps at three and returns `429`. Verify + DONE, no code.
- API7 (SSRF): already real. `process_support_file` decodes an uploaded HTML attachment and does `requests.get()` on every `<img src>` server-side. `/api/support/modify` only checks the multipart `Content-Type` against an image/PDF allow-list while the processor keys off the file name, so a `.html` payload with a forged `image/png` content-type triggers the fetch. Verify + DONE, no code.
- API3 (mass assignment): not real. `change_password` hardcoded `$set:{'password':...}`. Implement the sink.
- API6 (voucher/store): no store, checkout, or voucher endpoint exists anywhere in the codebase. Honest downgrade rather than build a whole business-flow subsystem for one tick.

## Code (02_implement)

`api_server/app.py`, `change_password`: instead of setting only the password, it now `$set`s every field in the JSON body except the control keys `current_password` and `new_password`. A caller can add `"role":"admin"` (or any trusted field such as an `admin_session` value) to a normal password change and have it persisted to their own user document. This is the only code change, API4 and API7 already existed.

## Doc (03_document)

`API/Vulnerabilities.md`:
- API4: fixed the `# API4:2023 - #` heading typo, flipped section + Demonstration `PENDING -> DONE`, added the verified v1-uncapped / v2-`429` repro and result.
- API7: flipped the SSRF `PENDING -> DONE`, added a "Reproduced: SSRF via the support-ticket file processor" subsection with the submit-then-modify repro, the forged-content-type detail, and the verified `processing_results` (internal hosts reached). Noted the MJPEG-stream DoS variant.
- API3: flipped `PENDING -> IN PROGRESS`, added the role-escalation repro via `change_password`, cross-linked to API1 BOLA.
- API6: kept `PENDING`, added an explicit "design proposal, not implemented in this build" banner so it is not mistaken for a live attack.
- Frontmatter findings: API4 `DONE`, API7 `DONE`, API6 `PENDING (design only, no store endpoint in this build)`, API3 stays `IN PROGRESS`.

## Verification

Live on the running Docker stack (`vulnzoo-vulnerable:5000`, `mongo`, `vulnzoo-secure`):
- API4: six `/api/v1/login` bad-cred POSTs returned `401 401 401 401 401 401` and created six new session documents with no throttling, while `/api/v2/login` returned `401 401 401 429 429 429`. Test sessions cleaned up afterward.
- API7: submitted a support ticket as john, then attached `<img src="http://mongo:27017/"><img src="http://vulnzoo-secure:5001/">` as a `.html` file with a forged `image/png` content-type. The server's `processing_results` showed `mongo:27017` reached (TCP connect then `RemoteDisconnected`) and `vulnzoo-secure:5001` returning `status 200`, both internal-only hostnames the host itself cannot resolve (`host -> mongo:27017 = 000`). Ticket and admin auto-message cleaned up afterward.
- API3: isolation-verified the update construction (`role:admin` persisted, `current_password`/`new_password` control keys excluded, benign path sets only `password`), `app.py` parses.

## Deployment / pending

Only API3 needs deployment: the API image is baked (no volume mount), so the `change_password` mass-assignment goes live on the next `docker compose up --build`. API4 and API7 are already live and verified. API6 is a documented design proposal, no build needed. If the store/voucher flow (API6) is wanted as a real vuln, it is a separate follow-up (new endpoints + a mongo collection).

---

# RC-D1 - Fix dead doc routing docs/Router -> docs/RoutCoon (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-D1, wave 1, first RoutCoon target). Divide-and-conquer pass: `01_spec -> 04_integrate` (02/03 N/A, no vuln code). Same class as OWL-D1.

## Problem

The routcoon Layer 3 folder is `src/docs/RoutCoon/`, but Layer 0 (`src/AGENTS.md`), the Layer 2 lab contract (`src/labs/routcoon/CONTEXT.md`) and the factory promotion map routed to a non-existent `docs/Router/`. No `src/docs/Router/` directory exists, so the whole routcoon Layer 2 -> Layer 3 chain was dead.

## Changes (path references only: `docs/Router/` -> `docs/RoutCoon/`)

| File | Change |
|------|--------|
| `src/AGENTS.md` | device -> doc-folder map row (link text + URL) |
| `src/labs/routcoon/CONTEXT.md` | Inputs table Layer 3 rows (x3) + References section (x3) |
| `_config/promotion-map.md` | device -> product paths, Docs folder cell (out of the target's original Layer 0 + Layer 2 scope, caught by the 01_spec grep) |

Prose naming the device type ("Router", "vulnerable OpenWRT-based router", the `(router)` label) left intact, those are not paths.

## Verification

`grep -rn "docs/Router" --include="*.md"` over the repo returns only the `stages/TARGET_ROUTCOON.md` backlog description (the target that documents the drift), no live routing reference remains. The three real targets (`README.md`, `API/Vulnerabilities.md`, `IoT (Router)/Vulnerabilities.md`) all resolve under `src/docs/RoutCoon/`.

## Stage cleanup

01_spec was performed inline (a repo-wide grep), no throwaway spec file. This log is the durable record.

---

# RC-D2 - YAML frontmatter on RoutCoon vuln docs (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-D2, wave 1). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code). Same class as OWL-D2.

## Scope decision (01_spec)

The AGENTS.md convention is that *vuln docs* carry frontmatter. Following the OWL-D2 precedent (which excluded the OwlCam README), frontmatter was added to the two aggregate vuln docs and **not** to `README.md`, which is an onboarding/intro doc, not a findings doc (its content is handled by RC-D5). So the target's initial "every doc" wording is narrowed to the two `Vulnerabilities.md` files.

## Change

Added a collection-level YAML frontmatter block (the 8 convention fields `id/title/category/status/severity/owasp/cwe/affected_components` plus a compact per-finding `findings` list) at byte 0 of each aggregate vuln doc. The RoutCoon docs aggregate many findings per file, so the frontmatter is per-file, matching the OwlCam pattern. `cwe` and `affected_components` were aligned to the real overlay code paths confirmed during the RC analysis (not the doc's prose).

| File | id | status | findings |
|------|----|--------|----------|
| `API/Vulnerabilities.md` | ROUTCOON-API | IN PROGRESS | API2/API7/API8 (all DONE) |
| `IoT (Router)/Vulnerabilities.md` | ROUTCOON-IOT | IN PROGRESS | IoT1-10: I1/I3/I4/I9 DONE, I2/I5 IN PROGRESS, I6/I7/I8/I10 PENDING (not developed) |

The per-finding statuses reflect current documentation maturity, not a live re-verification. Known content drifts (IoT1 root credential, IoT4 FTP path, IoT5 endpoint) are left for the RC-C targets, matching how OWL-D2 set statuses before OWL-C3 fixed drifts. The IN PROGRESS / PENDING (not developed) markers will be reconciled with the body badges by RC-D3.

Not touched (not a vuln findings doc): `README.md`.

## Verification

Both files begin with `---` at byte 0, the YAML parses (`yaml.safe_load`) with all 8 required keys plus `findings`, and the original H1 heading follows the block (`# Introduction`, `# IoT:I1 - Weak Guessable, or Hardcoded Passwords`). API doc: 3 findings / 3 cwe / 5 components. IoT doc: 10 findings / 10 cwe / 10 components.

## Stage cleanup

01_spec (template + OwlCam shape review, scope decision) performed inline, no throwaway spec file. This log is the durable record.

---

# RC-D3 - Standardize non-standard status badges (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-D3, wave 1). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code). Same class as OWL-D3.

## Change

Normalized the 8 non-standard inline markers in `docs/RoutCoon/IoT (Router)/Vulnerabilities.md` to the canonical `DONE` / `IN PROGRESS` / `PENDING` (AGENTS.md convention). The API doc was already clean (grep-confirmed, no markers). Each new badge reconciles with the RC-D2 frontmatter `findings` status.

| Line | Old marker | New badge | Rationale |
|------|-----------|-----------|-----------|
| Samba 2.2 | `> **ON DEVELOPMENT**` | `PENDING` | SMB config on disk but the service is not enabled in this build (matches IoT2 frontmatter note) |
| DHCP/DNS | `> **CHECK ATTACKS**` | `IN PROGRESS` | attacks described in prose, not yet reproduced |
| IoT3 | `> **VERY BASIC VULNERABILITY:** ...` | `DONE` | low-severity, editorial "relegate to mobile interface" note preserved as prose |
| IoT5 | `> **NEEDS CHECK: Overlaps with [[...IoT I3...]]**` | `IN PROGRESS` | overlap note preserved, wikilink left verbatim for RC-D4 |
| IoT6/7/8/10 | `> **NOT DEVELOPED**` (x4) | `PENDING` | not developed, matches frontmatter |

Where a marker carried real information beyond the status (the IoT3 editorial suggestion, the IoT5 overlap note), the note was rewritten as plain prose after the canonical badge rather than dropped. The IoT5 broken wikilink was intentionally left untouched (RC-D4 owns link fixes, one stage one job).

## Verification

`grep -E "ON DEVELOPMENT|NOT DEVELOPED|CHECK ATTACKS|NEEDS CHECK|VERY BASIC|NOT DONE|PENDING REVIEW"` over both docs returns nothing. All 8 body markers are now `DONE` / `IN PROGRESS` / `PENDING` blockquotes, consistent with the RC-D2 per-finding statuses.

## Stage cleanup

01_spec (marker enumeration + mapping) performed inline. This log is the durable record.

---

# RC-D4 - Fix broken Obsidian wikilinks (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-D4, wave 1). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code). Same class as OWL-D4.

## Change

12 broken text wikilinks fixed across the two vuln docs. Every one turned out to be a **self-reference**: the note name `IoT Vulnerabilities` (and the colon-less `#API8 2023`) were the file's own old identity, but the file is named `Vulnerabilities.md`, so the note-name links did not resolve and the anchors had drifted from the real heading text. All were converted to same-file `[[#Heading]]` anchors matching the exact heading text. No cross-file links exist between the two docs.

| Doc | Old link | Fixed anchor |
|-----|----------|--------------|
| API (x2) | `[[#API8 2023 Security Misconfiguration]]` | `[[#API8:2023 Security Misconfiguration]]` |
| IoT | `[[IoT Vulnerabilities#IoT I1 - Weak Guessable, or Hardcoded Passwords]]` | `[[#IoT:I1 - Weak Guessable, or Hardcoded Passwords]]` |
| IoT | `[[IoT Vulnerabilities#IoT7 Insecure Data Transfer and Storage]]` | `[[#IoT:I7 - Insecure Data Transfer and Storage]]` |
| IoT | `[[IoT Vulnerabilities#IoT5 Using Insecure or Outdated Components]]` | `[[#IoT:I5: Using Insecure or Outdated Components]]` |
| IoT | `[[IoT Vulnerabilities#IoT I8 - Lack of device management]]` | `[[#IoT:I8 - Lack of device management]]` |
| IoT | `[[IoT Vulnerabilities#No. 9 Insecure Default Settings]]` | `[[#IoT:I9 - Insecure Default Settings]]` |
| IoT | `[[IoT Vulnerabilities#IoT I3 - Insecure Ecosystem Interfaces]]` | `[[#IoT:I3 - Insecure Ecosystem Interfaces]]` |
| IoT | `[[IoT Vulnerabilities#IoT I9 - Insecure Default Settings\|IoT9]]` | `[[#IoT:I9 - Insecure Default Settings\|IoT9]]` |
| IoT | `[[IoT Vulnerabilities#IoT I1 - Weak, Guessable, or Hardcoded Passwords]]` | `[[#IoT:I1 - Weak Guessable, or Hardcoded Passwords]]` (comma drift) |
| IoT | `[[IoT Vulnerabilities#IoT I10 - Lack of Physical Hardening]]` | `[[#IoT:I10 - Lack of Physical Hardening]]` |
| IoT | `[[IoT Vulnerabilities#FTP\|FTP]]` | `[[#2.4 FTP\|FTP]]` |

Image embeds (`[[api1_*.png]]`, `[[iot3_*.png]]`, etc., 12 of them) were left untouched: Obsidian resolves them by basename against `API/images/` and `IoT (Router)/images/`, matching how OWL-D4 handled embeds.

## Verification

`grep -E '\[\[IoT Vulnerabilities#|\[\[#API8 2023'` returns nothing. A script that extracts every `[[#anchor]]` and checks it against the doc's real headings reports ALL RESOLVE (2 API + 10 IoT anchors, each matching an existing heading, including the colon-in-text `IoT:I5:` and the numbered `2.4 FTP`).

## Stage cleanup

01_spec (wikilink enumeration + heading map) performed inline. This log is the durable record. Wave 1 doc-integrity targets D1-D4 are complete; D5 (README onboarding) remains.

---

# RC-D5 - README onboarding: fabricated creds, stale paths, host/IP map (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-D5, wave 1, last). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code). Same class as OWL-D5. Closes wave 1.

## Problem (verified against the overlay)

- The README advertised web/API credentials `admin` / `admin123` (and `user` / `user123` in the access section), but no `admin` or `user` account is created anywhere. `11-add-users.sh` creates only `openwrtuser`, `anonymous`, `nobody`, plus the base `root`. Both credentials were fabricated.
- The real web/API login is `root` / `uncrackable`: the LuCI dispatcher gates the admin tree with `allowed_users = track.sysauth` (root-only), and `openwrtuser` only yields the differential 403/401 used for the enumeration exercise.
- The setup step referenced an `openwrt_resources/` folder that exists nowhere in the repo (grep: only the README named it).

## Change (`docs/RoutCoon/README.md`)

- Added a "Hosts, ports and credentials" map table (device `192.168.2.1` canonical, LuCI :80 root-only, SSH :22 openwrtuser, FTP :21 anon, Telnet :5515 unauth root, SNMP :161 public/private, UPnP :5000/:1900, Device Manager :8080), with a note that `192.168.2.1` is authoritative over the `192.168.1.1` seen in some walkthroughs.
- Replaced the fabricated `admin:admin123` / `user:user123` with the real `root:uncrackable`, framed as the white-box shortcut, and stated there is no `admin` account so the black-box path is credential discovery.
- Dropped the dead `openwrt_resources/` reference, repointed setup to the real `API/Vulnerabilities.md` and `IoT (Router)/Vulnerabilities.md`.
- Kept the correct white-box line (`openwrtuser:openwrtuserpwned`, `root:uncrackable`) and clarified SSH (openwrtuser) vs web/API (root) as separate paths, noting root SSH password login is disabled.

## Flagged (out of D5 scope, later targets)

- The vuln-doc scans still use `192.168.1.1` in places (network drift) -> RC-C4.
- The FTP anonymous home in the vuln docs is described as `/tmp`; the real ftpd root is `/opt/oem-updates/pending` -> RC-C2. The README map deliberately states no FTP path to avoid pre-empting that fix.

## Verification

`grep` confirms the README no longer carries `admin123`, `user123`, `openwrt_resources`, or the "default credentials or those you have configured" line. The host/port/credential map, the `root:uncrackable` login, and the "no `admin` account" note are present and consistent across the map, the Getting Started API section, and the Access section.

## Stage cleanup

01_spec (account/login verification against the overlay) performed inline. This log is the durable record. **Wave 1 (RC-D1..D5, MWP/doc integrity) is complete.**

---

# RC-C1 - root credential drift: IoT1 "crack root" is false (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-C1, wave 2, first). Pass: `01_spec -> 04_integrate` (02 N/A, the credential is intended and must not be weakened). Doc-truth fix.

## Problem (verified against the overlay)

IoT1 told the reader that the `pwned` wordlists "can be used to crack the root user's password" and showed a `john` run recovering `pwned`. The overlay sets `root:uncrackable` (`11-add-users.sh:42`), and IoT9's own demo uses `sshpass -p "uncrackable" ssh root@...`. No account has the password `pwned`, so the `john`-cracks-root block was fabricated/stale. The CONTEXT.md user table (`root | pwned`) and the IoT:I1 bullet ("Crackable root hash (type 5 - SHA256)") carried the same false claim. The genuinely crackable account is `openwrtuser` (`openwrtuserpwned`, `sha256crypt $5$`, combination attack), which was already documented correctly.

## Change

- `IoT (Router)/Vulnerabilities.md` (IoT1): replaced the false "crack root" sentence and the fabricated `john`-recovers-`pwned` block with an accurate paragraph: `pwned` is the tell for `openwrtuser`, the `root` hash is a decoy whose password `uncrackable` is not in the `pwned` wordlists, so a `john` run against it exhausts the list with no result, and root is reached by escalating from `openwrtuser` (wikilink to IoT9), not by cracking. Kept the real `grep pwned rockyou`, the `openwrtuser` hashcat combination attack, and the web-differential brute force.
- `labs/routcoon/CONTEXT.md`: user table `root | pwned` -> `root | uncrackable` (and "SSH disabled" -> "SSH password login disabled"); the IoT:I1 bullets rewritten so `openwrtuser` is named the crackable account and `root` is the deliberately-uncrackable escalation target.

## Verification

`grep` for a root-cracking / `Crackable root` / `root ... pwned` claim across the two docs, the README and CONTEXT returns only the corrected text (which states root is NOT crackable) and the IoT9 `sshpass -p "uncrackable"` demo. The new `[[#IoT:I9 - Insecure Default Settings|IoT9]]` wikilink resolves to the real heading (line 1028), matching the anchor RC-D4 already uses. Password values are confirmed from `11-add-users.sh`; the on-image `/etc/shadow` hash type is a reasonable inference (chpasswd default = the `$5$` sha256crypt the `openwrtuser` hash already shows) but a live flashed-image confirmation is still pending.

## Stage cleanup

01_spec (IoT1 + CONTEXT re-read, overlay credential verification) performed inline. This log is the durable record.

---

# RC-C2 - FTP root drift: /tmp vs /opt/oem-updates/pending (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-C2, wave 2). Pass: `01_spec -> 04_integrate` (02 N/A, the code chain is correct and intended). Doc-truth fix.

## Problem (verified against the overlay)

The FTP -> cron RCE chain works in code: `files/etc/init.d/ftpd:10` serves anonymous write on `/opt/oem-updates/pending` (and `80-routcoon-services.sh:90` `chmod 777`s it), `auto-updater.sh` scans that directory every 3 min and `/bin/sh`-executes any uploaded `.sh` as root. But the docs described the FTP home as `/tmp`, so the exercise fails as written: the docs sent the learner to the wrong upload directory. The IoT2 doc even embedded a stale copy of the init script (`ftpd -w -a anonymous /tmp`, plus a `mkdir/chmod/chown /tmp/ftp` block that the real script does not have).

## Change (docs match the working code now)

`IoT (Router)/Vulnerabilities.md` (5 sites):
- IoT2 2.4: the "/tmp home" description -> `/opt/oem-updates/pending` (named as the OEM update staging area), with a wikilink to IoT4 explaining why anonymous write there is dangerous (root cron executes it).
- IoT2 2.4: replaced the embedded stale `start()` block with the real `files/etc/init.d/ftpd` body (`tcpsvd ... /opt/oem-updates/pending`, no `/tmp/ftp` prep, that lives in the services hook).
- IoT4: "upload the script to the /tmp/cron-tmp folder" -> `/opt/oem-updates/pending` (the anonymous FTP home).
- IoT9: anonymous upload target "/tmp" -> `/opt/oem-updates/pending`; the `mount -o remount,noexec /tmp/ftp` remediation -> `/opt/oem-updates/pending`.

`labs/routcoon/CONTEXT.md` (5 sites): user table anonymous home, the IoT:I2 `tcpsvd` snippet + its comment, the users list, the Outputs FTP row, and Chain 3 all moved `/tmp` (and `/tmp/ftp`) -> `/opt/oem-updates/pending`.

Legitimate `/tmp` uses were deliberately left untouched: the dnsmasq lease/hosts files (`/tmp/dhcp.leases`, `/tmp/hosts`) and the reverse-shell fifo (`mkfifo /tmp/f`) are real and unrelated to the FTP home.

## Verification

`grep` for any FTP-home `/tmp` pattern (`/tmp/ftp`, `/tmp/cron-tmp`, `anonymous /tmp`, write/upload/home near `/tmp`) across the IoT doc and CONTEXT returns nothing. `/opt/oem-updates/pending` now appears 6x in each file. The three legitimate `/tmp` references remain. The new `[[#IoT:I4 - Lack of Secure Update Mechanism|IoT4]]` wikilink resolves to the real heading. Live confirmation (anon `put` lands in pending, cron executes it as root) still needs a flashed image.

## Stage cleanup

01_spec (FTP-reference enumeration, init-script diff) performed inline. This log is the durable record.

---

# RC-C3 - IoT5 endpoint/header drift + IoT3 duplication (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-C3, wave 2). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code). Doc-truth fix + dedup.

## Problem (verified against the overlay)

The IoT5 claims about SSH-key injection did not match the code. The wrong `/cgi-bin/luci/debug/ssh` route and `X-Debug-Mode` header lived in `labs/routcoon/CONTEXT.md` (the IoT:I5 bullets and the summary table); grep-confirmed neither string exists in the overlay, and there is no `/debug` entry node in any controller. The real mechanism is `controller/support/remote.lua`: the "Remote Connectivity Check" at `/cgi-bin/luci/support/remote/diagnostic` (`sysauth = false`), which authorizes by a spoofable forwarded-IP (`X-Forwarded-For`/`real_ip`/`xff`/`remote_addr`) matched to `203.0.113.0/24`, answers `?debug=1` with an env dump, and exposes `update_ssh_access` -> `/etc/dropbear/authorized_keys`. Separately, the IoT5 doc body duplicated the entire IoT3 wfuzz endpoint-discovery section verbatim (114 lines).

## Change

- `IoT (Router)/Vulnerabilities.md` (IoT5): removed the 114-line duplicated IoT3 wfuzz block and replaced it with a one-paragraph cross-reference to IoT3. Reframed the vague "/api, /tools, /debug + X-Debug-Mode" narrative to the real surface: `/api` and `/tools` are the unauthenticated `network_tools.lua` SSRF/diagnostic nodes (cross-linked to API7/API8), and the high-value leftover is `/support/remote/diagnostic` with the forwarded-IP spoof, the `?debug=1` dump, and the `update_ssh_access` key injection into `authorized_keys` (noting the `RootPasswordAuth off` bypass). Kept all six IoT5 images and the IoT9 cross-link. The full forge-and-inject walkthrough is handed to RC-A1 (referenced in prose, no dead wikilink).
- `labs/routcoon/CONTEXT.md`: rewrote the IoT:I5 bullets (`/debug/ssh`, `X-Debug-Mode` -> the real endpoint, the forwarded-IP spoof, the `?debug=1` dump) and the IoT summary-table Evidence cell.

The IoT5 "OpenWrt 24.10.3" version line was left untouched (RC-E1 owns the version drift).

## Verification

`grep -E "debug/ssh|X-Debug-Mode"` over all RoutCoon docs and CONTEXT returns nothing. The real `support/remote/diagnostic` + `203.0.113.0/24` mechanism is named in both files. An `awk` scan of the IoT5 section counts zero `luci/admin/FUZZ` lines (duplication gone), all six `iot5_*` images remain, the IN PROGRESS badge and the frontmatter (byte 0) are intact. Live forge-and-inject confirmation is RC-A1 / a flashed image.

## Stage cleanup

01_spec (IoT5 read, support/remote.lua confirmation, no-`/debug`-node check) performed inline. The IoT-doc dedup+reframe was done with a line-range splice (asserted anchors) because the wfuzz tables carry trailing whitespace. This log is the durable record.

---

# RC-C4 - dnsmasq drift: rapid-commit + network subnet (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-C4, wave 2). Pass: `01_spec -> 04_integrate` (02 N/A, decided against a blind config change). Doc-truth fix.

## Problem (verified against the overlay)

`CONTEXT.md` IoT9 listed "DHCP rapid commit enabled", but `dnsmasq.conf:87` has `#dhcp-rapid-commit` commented out (disabled). The IoT doc DHCP/DNS section already stated this correctly ("`dhcp-rapid-commit` is commented out"), so only CONTEXT carried the false claim. Separately, `dnsmasq.conf` serves `dhcp-range=192.168.1.100-254` / gateway `192.168.1.1` while the lab's management surface is `192.168.2.1`.

## Decision on the subnet (01_spec)

The overlay ships no `/etc/config/network`, so the LAN interface IP comes from the base image (OpenWRT default `br-lan` = `192.168.1.1`), not the routcoon overlay. The `192.168.1.x` DHCP pool is consistent with a default `br-lan`, while the attack surface answers on `eth0` at `192.168.2.1` (per the SNMP scan in the doc). Whether the device is genuinely dual-homed (`br-lan` .1.x + `eth0` .2.1) or the range should be `.2.x` cannot be settled without a live Pi, and changing the DHCP subnet blindly could break a working `br-lan`. So the config was left unchanged and the reality documented instead, with the topology flagged for a live check.

## Change

- `labs/routcoon/CONTEXT.md`: IoT9 bullet "DHCP rapid commit enabled" -> "No DHCP rate limiting (`dhcp-rapid-commit` commented out, `dhcp-lease-max=100000`)", which is both accurate and the real insecure-default framing.
- `IoT (Router)/Vulnerabilities.md` (2.7 DHCP/DNS): added a paragraph clarifying the DHCP pool is `192.168.1.x` / gw `192.168.1.1` (`br-lan` default) while the targeted management surface is `eth0` `192.168.2.1`, and that `192.168.2.1` is the canonical target.

Not changed: `dnsmasq.conf` (no live confirmation of the interface topology; the insecure options themselves are intended) and the many `192.168.1.1` nmap-output lines in the scans (illustrative; RC-D5 already made `192.168.2.1` authoritative in the README, and mass-rewriting captured tool output is out of proportion).

## Verification

`grep` for a "rapid commit enabled" claim across the docs, README and CONTEXT returns nothing. The CONTEXT bullet now reads "No DHCP rate limiting", the IoT doc keeps the correct "commented out" statement and carries the new subnet note. Ground truth: `dnsmasq.conf:87` `#dhcp-rapid-commit` is commented. The `br-lan` vs `eth0` interface topology still needs a flashed-image confirmation.

## Stage cleanup

01_spec (option-by-option diff of `dnsmasq.conf` vs the docs, interface-IP search) performed inline. This log is the durable record.

---

# RC-C5 - SNMP: drop unverifiable CVE claims (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-C5, wave 2, last). Pass: `01_spec -> 04_integrate` (02 N/A, no vuln code). Doc-truth trim. Closes wave 2.

## Problem

The SNMP section (2.5) pinned "Net-SNMP version 5.9.4" and cited specific CVEs, including `CVE-2025-68615` framed as a "CVSS 9.8 Critical (RCE attack)". The version was not evidenced anywhere (the nmap `snmp-sysdescr` shows only the kernel `OpenWrt 6.6.104`, not the net-snmp package version), and a 9.8 RCE in net-snmp is implausible and unverifiable at this cutoff. The reproducible, config-backed finding is the default communities (`rocommunity public` / `rwcommunity private`, written by `80-routcoon-services.sh` / `files/etc/snmp/snmpd.conf`).

## Change (`IoT (Router)/Vulnerabilities.md`, 2.5 SNMP)

Replaced the version + CVE block (the "5.9.4" pin, the `CVE-2024-26464` / `CVE-2025-68615` links, the "CVSS 9.8 RCE", the malformed-OID and exploitation bullets) with two honest paragraphs: net-snmp has had memory-safety issues in general (no fabricated CVE numbers), but the in-scope reproducible finding is the default-community + cleartext-v1/v2c misconfiguration; the exact package version is deliberately not asserted and must be read off the running image (`opkg list-installed | grep snmp`) and checked against advisories before chaining any version-specific bug.

Kept intact: the `nmap -sU -p161` scan output (real evidence of the exposed net-snmp agent), and the entire 2.5.1 Default Community Strings section (the `snmpwalk -c public` enumeration repro, the risk table, the `rwcommunity private` exposure, the attack-chain and remediation).

## Verification

`grep` for `5.9.4`, `CVE-2024-26464`, `CVE-2025-68615`, `CVSS 9.8`, `RCE attack` across the IoT doc returns nothing; none of these ever appeared in CONTEXT/README. The default-community finding, the config lines, the `snmpwalk` repros and the nmap scan are all still present. The honest "does not pin a specific CVE / read the version off the image" framing is in place. The net-snmp package version remains intentionally unconfirmed (that was the point) pending a live image.

## Stage cleanup

01_spec (SNMP section read, evidence check for the version pin) performed inline. The intro replacement used a line-range splice (asserted anchors) because the block carries trailing whitespace and Obsidian `==highlight==` markup. This log is the durable record. **Wave 2 (RC-C1..C5, doc<->code chain truth) is complete.**

---

# RC-A1 - Document the support/remote SSH-key-injection chain (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-A1, wave 3, first). Pass: `01_spec -> 04_integrate` (02 N/A, the endpoint exists and is intended, this was a documentation gap). Doc only.

## What was undocumented

`controller/support/remote.lua` exposes the lab's strongest chain and had no prose (only the `iot5_*` images). RC-C3 named the mechanism and handed the full writeup here.

## Change (`IoT (Router)/Vulnerabilities.md`, new `##` subsection under IoT5)

Added "Unauthenticated SSH key injection via the support endpoint", a first-class writeup with the code-quoted root cause and a copy-pasteable repro:
- The endpoint `/cgi-bin/luci/support/remote/diagnostic` is registered `page.sysauth = false` (unauthenticated).
- `get_forwarded_ip()` falls through from real headers to attacker-controlled form params (`X-Forwarded-For`, `real_ip`, `xff`, `remote_addr`), and `is_support_ip()` authorizes anything in `203.0.113.0/24`, so a POST `real_ip=203.0.113.100` becomes "authorized support". The unauthorized page leaks the expected `203.0.113.100` in an HTML comment and advertises `?debug=1` (env dump).
- The `update_ssh_access` action appends the supplied key to `/etc/dropbear/authorized_keys`. The repro forges the IP, injects an ed25519 key, and SSHes in.
- Impact framed as unauthenticated-to-root: `/etc/dropbear/authorized_keys` is root's key file and `RootPasswordAuth off` (IoT9) gates only password auth, so the injected pubkey is expected to bypass the whole restricted-shell path. OWASP API5:2023 / CWE-290 / CWE-306, plus remediation.

## Verification

The subsection is placed before IoT6, the IoT9 wikilink resolves, and all five quoted code snippets (`page.sysauth = false`, `http.formvalue("real_ip")`, the `203%.0%.113%.%d+$` match, `action == "update_ssh_access"`, `auth_file = "/etc/dropbear/authorized_keys"`) exist verbatim in `support/remote.lua`. The endpoint reachability and the key write are code-verified; the final root pubkey login is explicitly marked as needing a flashed-image confirmation (dropbear `RootLogin`/`authorized_keys` handling comes from the base image, not the overlay), so the IoT5 frontmatter finding stays IN PROGRESS.

## Stage cleanup

01_spec (support/remote.lua trace) performed inline. This log is the durable record.

---

# RC-A2 - Document the IoTGoat legacy surface (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-A2, wave 3). Pass: `01_spec -> 04_integrate` (02 N/A, code exists and is intended). Doc only.

## What was undocumented

`controller/iotgoat/iotgoat.lua` registers a hidden IoTGoat developer console (`admin/iotgoat/cmdinject` + `webcmd`) plus two menu stubs (`cam`, `door`), none of it documented.

## 01_spec findings (auth resolved)

- `webcmd()` runs `io.popen(tostring(cmd).." 2>&1")` with no filtering, as root (LuCI/uhttpd context). `cmd.htm` is the "Secret Developer Diagnostics Page" console that POSTs `cmd` to it.
- Auth: the admin root node sets `page.sysauth = "root"` (`controller/admin/index.lua:17`), and the iotgoat entries do not override it, so `admin/iotgoat/webcmd` requires an authenticated root session (NOT unauthenticated). `vulnerable_mode` in the luci config is not consulted in the dispatcher sysauth path.
- `camera.htm` / `door.htm` are empty `PLACEHOLDER` stubs (no backend).

## Change (`API/Vulnerabilities.md`, new `##` under API8)

Added "OS Command Injection via the IoTGoat developer console": the code-quoted `cmdinject`/`webcmd` registration and the unfiltered `io.popen`, an Authentication subsection (root session required, obtained via `root:uncrackable` white-box or by chaining the IoT5 SSH-key injection to a root shell first), a browser + `curl` repro, and an honest "Non-functional siblings" note that `cam`/`door` are placeholder stubs. Framed as a cleaner post-auth root RCE than `diag_ping`. Extended the frontmatter (`iotgoat.lua` component, an `API8 IoTGoat webcmd console (CWE-78): DONE` finding).

## Verification

The subsection sits under API8, the frontmatter parses (component + finding added), and all four quoted snippets (`cmdinject` entry, `webcmd` entry, `http.formvalue("cmd")`, `io.popen(tostring(cmd).." 2>&1")`) exist verbatim in `iotgoat.lua`. The route registration and the root-context `io.popen` are code-verified; the page render and live execution still want a flashed image.

## Stage cleanup

01_spec (iotgoat.lua + templates + admin sysauth trace) performed inline. This log is the durable record.

---

# RC-A3 - Document check_service RCE + service_status SSRF (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-A3, wave 3, last). Pass: `01_spec -> 04_integrate` (02 N/A, intended and unfiltered by design). Doc only. Closes wave 3.

## What was undocumented

`network_tools.lua` was documented only as the `file://` SSRF on `/api/v1/check` and the filtered `ping_host`. Two stronger `sysauth = false` sinks in the same file were undocumented.

## 01_spec findings

- `check_service` builds `string.format("curl -m %d '%s' 2>&1", timeout, url)` and `io.popen`s it. The `url` is single-quoted but unsanitized, so a `'` breaks out into command injection. The node is `sysauth = false`, so this is unauthenticated RCE over a plain GET, no `diag_ping` pivot needed. (The existing API7 prose implied the injection only reachable via a pivot to `diag_ping`, which undersold this endpoint.)
- `service_status` fetches any `internal_url` server-side, unauthenticated, and logs it `critical`, a second SSRF distinct from the `file://` read.
- `ping_host` is the filtered one (`host:match("[;&|...]")`), which is why `check` is the clean injection.

## Change (`API/Vulnerabilities.md`, new `##` at the end of API7)

Added "Additional unauthenticated sinks in network_tools.lua" with two code-quoted subsections: the `/api/v1/check` single-quote-breakout command injection (unauth RCE, CWE-78, with a `curl --data-urlencode "url=x';id;'"` repro and the exact shell string it builds) and the `/api/v1/status` `internal_url` SSRF (CWE-918). Contrasted with the filtered `ping_host`. Extended the frontmatter findings.

## Verification

The subsection sits at the end of API7 (before API8), the frontmatter parses with the new finding, and the three quoted snippets (the single-quoted `curl` `string.format`, the `url` formvalue, the `internal_url` formvalue) exist verbatim in `network_tools.lua`. The single-quote breakout and the unauthenticated reachability are code-verified; the live `id`-in-JSON and internal-fetch outputs want a flashed image.

## Stage cleanup

01_spec (network_tools.lua re-trace, quote-breakout reasoning) performed inline. This log is the durable record. **Wave 3 (RC-A1..A3, the strong undocumented surfaces) is complete.**

---

# RC-I1 - Realize IoT:I7 Insecure Data Transfer and Storage (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-I1, wave 4, first). Pass: `01_spec -> 04_integrate` (02 N/A, realized from exposures already on the device). This is the first of the "finish the OWASP IoT Top 10" targets the README asks for.

## 01_spec: realize from existing exposures, no new code

I7 was a `PENDING` stub. It is fully realizable from what already ships, so no overlay change was needed (YAGNI):
- In transit (CWE-319): `30-uhttpd-config.sh` sets `listen_http` on `:80` only (no `listen_https`, no cert), so the LuCI login is cleartext; FTP `:21`, SNMP v1/v2c `:161`, Telnet `:5515`, and the `support/remote` key POST are all plaintext too.
- At rest (CWE-312 / CWE-732): `dnsmasq.conf` stores the DHCP database world-modifiable in `/tmp` (`dhcp-leasefile=/tmp/dhcp.leases`, `dhcp-hostsfile=/tmp/hosts`) and logs DNS queries to `/var/log/dnsmasq.log`; `support/remote.lua` writes `/tmp/support_env_debug.log` and `/var/log/support_access.log`; provisioning writes `/root/vulnzoo.log`.

## Change (`IoT (Router)/Vulnerabilities.md`, IoT7 section)

Replaced the stub with a full section: an "In transit" subsection (the cleartext-login `tcpdump` repro recovering `root:uncrackable` + the `sysauth` cookie, plus the other plaintext services), an "At rest" subsection (the `/tmp` DHCP state and a table of the plaintext log/key sinks), impact + remediation, and the OWASP/CWE mapping (CWE-319/312/732). Flipped the finding badge and the frontmatter `IoT7: PENDING (not developed) -> IN PROGRESS`. The DHCP-section link that already pointed at this heading now lands on real content.

## Verification

The section carries the In transit / At rest / Impact subsections and the CWE mapping (no longer a `PENDING` stub); the frontmatter parses with `IoT7: IN PROGRESS`; the existing `[[#IoT:I7 ...]]` link resolves. Ground truth holds: `30-uhttpd-config.sh` configures `listen_http` `:80` only and `dnsmasq.conf` puts the leasefile in `/tmp`. The live packet capture is the one step left for a flashed image (hence the finding stays IN PROGRESS).

## Stage cleanup

01_spec (exposure inventory across uhttpd/dnsmasq/support-remote/hooks) performed inline. This log is the durable record.

---

# RC-I2 - Realize IoT:I8 Lack of Device Management (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-I2, wave 4). Pass: `01_spec -> 04_integrate` (02 N/A). Doc synthesis.

## 01_spec: a management-lens synthesis, no new code

I8 is a lifecycle/management category, not a single exploit. It is realized by tying together management-layer gaps already demonstrated by concrete, code-verified findings: no secure update management (IoT4), no monitoring/response and tamperable world-readable logs (IoT7), no brute-force protection on any auth surface (IoT2 SSH / API2 LuCI / the unauth `api`,`tools` endpoints), and no key/credential lifecycle or decommissioning (IoT5 injected keys persist, hardcoded creds). No overlay change (YAGNI).

## Change (`IoT (Router)/Vulnerabilities.md`, IoT8 section)

Replaced the stub with four gap subsections (Update management -> IoT4, No monitoring/response CWE-778 -> IoT7, No brute-force protection CWE-307 -> IoT2/API2, No key-lifecycle/decommissioning -> IoT5) plus impact + remediation and the OWASP/CWE mapping. Flipped the finding badge and frontmatter `IoT8 -> DONE`.

## Verification

The section carries all four gap subsections and the CWE mapping (no longer a stub); the two new wikilinks (`IoT4`, `IoT7`) resolve to real headings; the frontmatter parses with `IoT8: DONE`. All the cross-linked findings this synthesis rests on are code-verified, so I8 is DONE without a separate live step.

## Stage cleanup

01_spec (management-gap synthesis across the existing findings) performed inline. This log is the durable record.

---

# RC-I3 - Realize IoT:I6 Insufficient Privacy Protection (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-I3, wave 4). Pass: `01_spec -> 04_integrate` (02 N/A). Doc.

## 01_spec: realize with a scope note (not a blank downgrade)

A router holds little classic PII, so I6 was decided as realize-with-honest-scope rather than fabricate a data store. The genuine privacy exposure is network metadata: device identity/presence (SNMP `public` ARP table, `/tmp/dhcp.leases` hostnames + `read-ethers`) and browsing behavior (dnsmasq `log-queries` -> `/var/log/dnsmasq.log`, a per-client DNS history). All exist already, so no overlay change.

## Change (`IoT (Router)/Vulnerabilities.md`, IoT6 section)

Replaced the stub with two angle subsections ("Who is on the network" via the unauth SNMP ARP dump + DHCP hostnames; "What they browse" via the DNS query log, cross-linked to IoT7 for the cleartext capture), impact + remediation, an explicit **Scope note** that this is network-metadata privacy and there is no stored end-user PII to invent, and the OWASP/CWE mapping (CWE-359 / CWE-200). Flipped the finding badge and frontmatter `IoT6 -> DONE`.

## Verification

The section carries the two angle subsections, the scope note and the CWE mapping (no longer a stub); the IoT7 wikilink resolves; the frontmatter parses with `IoT6: DONE`. The SNMP ARP repro it rests on is already presented (with output) in section 2.5, and the DNS-log read is a trivial `cat`, so the finding is realized rather than left pending.

## Stage cleanup

01_spec (privacy-sink inventory, realize-vs-downgrade decision) performed inline. This log is the durable record.

---

# RC-I4 - Realize IoT:I10 Lack of Physical Hardening (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-I4, wave 4, last). Pass: `01_spec -> 04_integrate` (02 N/A). Doc. Closes wave 4.

## 01_spec: realize scoped to the Pi hardware

I10 is realizable for a Raspberry Pi lab and was written rather than downgraded: no secure boot, an unencrypted removable microSD, and an exposed GPIO UART. `50-ttylogin.sh` sets `ttylogin=1` (serial getty requires a password), so the free-shell-on-serial angle is honestly qualified, but microSD extraction is unconditional. No overlay change.

## Change (`IoT (Router)/Vulnerabilities.md`, IoT10 section)

Replaced the stub with two angle subsections (microSD extraction -> full rootfs read/write, secret theft, and persistence, cross-linked to IoT1 as the physical mechanism behind its firmware-extraction assumption; UART serial console -> boot-log leak and login/bootloader access, qualified by `ttylogin=1`), impact + remediation, an **On-device note** (hardware findings, microSD unconditional, exact serial behavior needs the physical Pi), and OWASP/CWE (CWE-1263 / CWE-1191). Flipped the finding badge and frontmatter `IoT10 -> DONE`.

## Verification

The section carries both angle subsections, the on-device note and the CWE mapping; the IoT1 wikilink resolves; the frontmatter parses. With this, **all ten OWASP IoT Top 10 findings now carry real content, no `not developed` / `PENDING (not developed)` entry remains** (IoT1/3/4/6/8/9/10 DONE, IoT2/5/7 IN PROGRESS pending live steps). This meets the README's stated purpose of finishing the undeveloped points.

## Stage cleanup

01_spec (Pi physical-surface inventory, `50-ttylogin.sh` check) performed inline. This log is the durable record. **Wave 4 (RC-I1..I4, finish the OWASP IoT Top 10) is complete.**

---

# RC-B1 - Samba "ON DEVELOPMENT": honest downgrade (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-B1, wave 5, first). Pass: `01_spec -> 04_integrate` (02 N/A). Doc.

## 01_spec: wire vs downgrade

Decided to downgrade honestly, not wire. `samba.conf` defines a genuinely dangerous share (`[public]`, `guest ok = yes`, `read only = no`, `force user = root`, an unauthenticated world-writable root-owned share), but the SMB **server** package is not in the image: `labs/routcoon/.config` has `samba4-server` and every `ksmbd-server`/`samba4-*` package `is not set` (only `kmod-fs-ksmbd`, the filesystem module, is enabled), and no hook starts a daemon. Adding an `smbd` start to the services hook would fail on flash because no server binary ships, which is exactly the doc<->code drift this backlog removes. Wiring it is a build-time change (enable the package, rebuild) that cannot be verified without a Pi.

## Change (`IoT (Router)/Vulnerabilities.md`, IoT2 2.2)

Expanded the RC-D3 one-line note into an honest downgrade: retitled the section (dropped the unsubstantiated "Samba 4.18.8"), quoted the intended dangerous share config, explained precisely why it is not reachable (`samba4-server`/`ksmbd-server` unset, no daemon), corrected the fabricated version, and gave the build-time enable path (enable an SMB server package in `.config`, ship the init script, create `/mnt/sdcard/share`, start it from `80-routcoon-services.sh`). Kept the finding PENDING; the IoT2 frontmatter already reads "Samba not yet enabled".

## Verification

The 2.2 section now documents the share design and its non-reachability; grep confirms no `Samba 4.18.8` version is asserted (only the explicit "was not substantiated" correction). Ground truth: `.config` has `ksmbd-server` and `samba4-server` unset. No overlay change was made (a non-functional `smbd` hook would have been the wrong move).

## Stage cleanup

01_spec (samba.conf read, `.config` package check) performed inline. This log is the durable record.

---

# RC-B1 (revised) - Samba wired after the user installed the server packages (2026-07-28)

Supersedes the RC-B1 downgrade above: the user installed `samba4-server` and `ksmbd-server` on the device, so the wire path is now viable. Pass: `01_spec -> 04_integrate` with a real `02_implement`.

## Decision

Wired samba4 `smbd` (not ksmbd): the existing `/etc/samba/samba.conf` is Samba smb.conf format (`/etc/samba/` path, `force user` directive), so smbd consumes it natively. Only one server can bind `:445`, so ksmbd is intentionally left unwired (and unset in `.config`) to avoid the conflict.

## Code (02_implement)

- `labs/routcoon/.config`: `samba4-server` and `samba4-libs` flipped to `=y` (they were `is not set`; the user had installed them via opkg, so the repo build config now matches). `ksmbd-server` left unset; `kmod-fs-ksmbd` was already `=y` and is harmless.
- `files/etc/samba/samba.conf`: added a `[global]` with `map to guest = bad user` + `guest account = root` (so anonymous connections are accepted) and `server min protocol = NT1` (allow SMB1, a deliberate weakening); kept the `[public]` guest-writable `force user = root` share.
- `files/usr/lib/vulnzoo-hooks/profile-init.d/80-routcoon-services.sh`: after the FTP block, create `/mnt/sdcard/share` (chmod 777) and start `smbd -s /etc/samba/samba.conf &` + `nmbd` (guarded by `command -v smbd`, logged), matching the lab's direct-daemon idiom (telnetd/ftpd). Marked with a `ponytail:` comment noting it bypasses the UCI-driven `/etc/init.d/samba4` to serve the raw vulnerable config.

## Doc (03_document)

`IoT (Router)/Vulnerabilities.md` 2.2 flipped from the PENDING downgrade to an IN PROGRESS wired finding: the full config, how `map to guest` + `guest ok` + `force user = root` yields an unauthenticated root-owned file drop, and an `smbclient -N` list + write repro. Frontmatter IoT2 note -> "Samba wired, live-pending".

## Verification

`.config` shows `samba4-server=y`/`samba4-libs=y` and `ksmbd-server` unset; the hook block is present and `sh -n` passes; `samba.conf` carries the `[global]` guest mapping and the `[public]` share; the doc + frontmatter are consistent and parse. The live check is on the user's device: after re-running the hook (or reflashing), `smbclient -L //192.168.2.1 -N` should list `public`, and `smbclient //192.168.2.1/public -N -c 'put ...'` should drop a root-owned file in `/mnt/sdcard/share`. If the user prefers ksmbd, or if `smbd` needs different flags on their samba build, that is the one open item.

## Stage cleanup

This revision is the durable record. The finding stays IN PROGRESS until the user confirms the share live.

---

# RC-B2 - UPnP AddPortMapping 501 / internal_iface lo: document honestly (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-B2, wave 5). Pass: `01_spec -> 04_integrate` (02 N/A). Doc-truth.

## 01_spec: make-functional vs document-honestly

Documented honestly, no config change. The 501 is topological, not a package gap: `miniupnpd` refuses `internal_iface == external_iface`, and the lab has a single NIC (`eth0`), so the UCI pins `internal_iface 'lo'` / `external_iface 'eth0'`. With no distinct internal LAN interface and no separate WAN, the NAT redirect rule cannot be built, so `AddPortMapping` returns 501. No config makes a single-NIC box do real external->internal forwarding (setting internal to a LAN alias would collide with external and stop miniupnpd), so there is nothing to "make functional". The actual vulnerability, `secure_mode '0'` plus a wide-open `perm_rule`, is real and already demonstrated by the unauthenticated SOAP request reaching the execution phase.

## Change (`IoT (Router)/Vulnerabilities.md`, 2.6 UPNP)

- Replaced the vague "absence of WAN NAT capabilities" in the intro with the concrete cause (single NIC -> `internal_iface 'lo'` -> no interface to build a forward on).
- Added a paragraph naming the authoritative UCI source (`/etc/config/upnpd`): `secure_mode '0'` + the permissive `perm_rule` (`int_addr '0.0.0.0/0'`, `ext_ports '0-65535'`) are the flaw, `internal_iface 'lo'` is the single-NIC constraint and the concrete reason for the 501 (a topology limit, not a security control), and on a real two-interface router the same config forwards attacker-chosen ports to arbitrary internal hosts.

Kept the existing honest 501 breakdown (request accepted, reached execution, failed at the iptables/NAT layer) and the risk assessment.

## Verification

The 2.6 section now explains `internal_iface 'lo'` and the single-NIC 501, and every config value it cites matches the UCI ground truth (`internal_iface 'lo'`, `external_iface 'eth0'`, `secure_mode '0'`, `int_addr '0.0.0.0/0'`). No overlay change was made (the config is correct for a single-NIC lab; the vuln is at the authorization layer).

## Stage cleanup

01_spec (miniupnpd 501 root-cause analysis, UCI read) performed inline. This log is the durable record.

---

# RC-B3 - dnsmasq attacks: scope the prose against the real config (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-B3, wave 5, last). Pass: `01_spec -> 04_integrate` (02 N/A). Doc-truth. Closes wave 5.

## 01_spec: verify each attack against dnsmasq.conf

The 2.7 section listed three attacks as prose. Checked against the shipped config (static read, no live run this session):
- Lease-file tampering: works, but as a LOCAL attack, `dhcp-leasefile=/tmp/dhcp.leases` is world-writable so any local user can rewrite leases and `killall -HUP dnsmasq`.
- DHCP starvation: does NOT work as written. `dhcp-ignore=tag:!known` makes dnsmasq ignore requests from unknown clients, so the random-MAC `DISCOVER` flood is dropped and no leases are consumed. Starvation would need MACs already in `/etc/ethers`.
- DNS cache poisoning: the naive off-path scapy snippet is unreliable (dnsmasq randomizes source port + txid). The real config-backed DNS weakness is DNS rebinding, `stop-dns-rebind` is commented out.

## Change (`IoT (Router)/Vulnerabilities.md`, 2.7)

Five surgical edits (labels/prose, code blocks left intact): updated the badge to name the per-attack outcome; scoped the intro; relabeled lease tampering as "works, local" with the `/tmp` reason; relabeled starvation as "does not work as written" with the `dhcp-ignore=tag:!known` explanation; relabeled the DNS item to lead with the real DNS-rebinding weakness (`stop-dns-rebind` commented) and mark the off-path poisoning as illustrative-only against port/txid randomization.

## Verification

The three scoped labels are present and the scapy/zsh code blocks are unchanged; the old bullet labels are gone. Every claim matches the config ground truth: `dhcp-ignore=tag:!known` (starvation blocked), `#stop-dns-rebind` commented (rebinding), `dhcp-leasefile=/tmp/dhcp.leases` (local tamper). No overlay change; live reproduction still wants a flashed image. **Wave 5 (RC-B1..B3, the half-built services) is complete** (B1 wired pending the user's live SMB test, B2/B3 documented honestly).

## Stage cleanup

01_spec (per-attack config verification) performed inline. This log is the durable record.

---

# RC-F1 - Expand the API doc (API5/API9) + reconcile orphan images (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-F1, wave 6). Pass: `01_spec -> 04_integrate` (02 N/A). Doc + a cross-lab file move.

## 01_spec findings

- Categories the LuCI `:80` API genuinely supports beyond API2/API7/API8: **API5 (Broken Function-Level Authorization)** and **API9 (Improper Inventory Management)**. API1 BOLA was deliberately skipped, there is no object-ownership check to violate in this API, and the `api1_*` images are the IoT1 login-brute-force screenshots (already used in the IoT doc), not OWASP API1.
- The two unreferenced images turned out to be **misfiled OwlCam assets**: reading them showed a Flask/Werkzeug app on `:5000` (`GET /admin` with an `X-Auth-Token` JWT returning the "Admin Panel - User Management"; `POST /register` returning `409 User already exists`). No such Flask service exists in the routcoon overlay (`cloud_api/` has only careotter/octobot/owlcam), and OwlCam's own API doc references both by basename (`OwlCam/API/Vulnerabilities.md:324,578`). They belong to OwlCam, not RoutCoon.

## Change

- `git mv` `api2_admin_access.png` and `api8_register.png` from `docs/RoutCoon/IoT (Router)/images/` to `docs/OwlCam/API/images/` (their owning lab, which references them). Obsidian resolves embeds by basename, so OwlCam's `![[...]]` still resolve, now from the correct folder; no RoutCoon doc referenced them, so nothing breaks.
- `API/Vulnerabilities.md`: added two categories.
  - **API5 Broken Function-Level Authorization**: a table of privileged functions reachable without proper function-level auth (`api/v1/check` RCE, `api/v1/status` SSRF, `support/remote/diagnostic` SSH provisioning, all `sysauth=false`; `admin/iotgoat/webcmd` root RCE gated only by a generic session), cross-referencing the concrete repros under API7/API8/IoT5. CWE-285/862.
  - **API9 Improper Inventory Management**: the leftover/undocumented debug endpoints shipped in production (`support/remote`, `api/v1/status` and the `api`/`tools` tree, the `iotgoat` console). CWE-1059/489.
  - Frontmatter extended: owasp string (+API5,+API9), two cwe entries, `API5: DONE` / `API9: DONE`.

No routcoon Flask/registration finding was fabricated (there is no such service).

## Verification

The API doc now carries API2/API5/API7/API8/API9; the frontmatter parses with API5/API9 in owasp and findings and 5 cwe entries. The moved images exist under `docs/OwlCam/API/images/` and OwlCam's two embeds resolve to them; no routcoon doc referenced them. The API5/API9 content rests on already-code-verified endpoints (RC-A1/A2/A3).

## Stage cleanup

01_spec (image content read, cloud_api inventory, category mapping) performed inline. This log is the durable record.

---

# RC-E1 - Version drift + build note (2026-07-28)

Target from `stages/TARGET_ROUTCOON.md` (RC-E1, ongoing, last). Pass: `01_spec -> 04_integrate` (02 N/A). Doc.

## 01_spec: the drift is the reverse of the assumption

The banner `files/etc/banner` reads `OpenWrt 24.10.3, r28739-d9340319c6`, so the routcoon image really is 24.10.3, and the IoT5 "OpenWrt 24.10.3" claim is correct. The stale value was routcoon's own `CONTEXT.md` ("OpenWRT v24.10.2"). The SNMP scan's `6.6.104` is the kernel version (correct for 24.10.x), not a conflict. `.config` carries no explicit version string (it comes from the source tree).

## Change (`labs/routcoon/CONTEXT.md`)

- Platform line `v24.10.2` -> `v24.10.3` (`r28739-d9340319c6`, per the banner), noting it is a point release above the 24.10.2 project baseline in AGENTS.md.
- Added `samba4 (smbd, guest share)` to the Services list (wired in RC-B1).
- Added a `## Build` section: compile `rshell.c` for bcm27xx/ARM -> `files/usr/bin/rshell` (openwrtuser's login shell); select `samba4-server` + `samba4-libs` in `.config` (`make defconfig` reconciles deps, `ksmbd-server` unset to avoid the `:445` conflict); package `files/` as `routcoon.tar.gz`.

The project-wide `AGENTS.md` / `PROJECT_OVERVIEW.md` "24.10.2" were left unchanged: that is the ecosystem baseline across labs, not a routcoon-specific value, and changing cross-lab docs for one lab's point release is out of scope.

## Verification

banner == CONTEXT == IoT5 == `24.10.3` now; the build note is present; the project baseline stays `24.10.2`. Doc-only, no overlay change.

## Stage cleanup

01_spec (banner/`.config`/doc version reconciliation) performed inline. This log is the durable record. **The RoutCoon backlog (waves 1-6 + RC-E1) is complete.**
