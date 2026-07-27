# OwlCam Lab - Improvement Targets (divide-and-conquer backlog)

> **Factory-level planning artifact.** Source: OwlCam structural + vulnerability-doc analysis (2026-07-27), cross-checked against `src/cloud_api/owlcam/`, `src/labs/owlcam/`, and live runtime on the Pi and the Docker stack. The **product** lives in [`../src/`](../src/). This file only tracks *what* to change and *how far along* each change is.

This backlog applies **divide and conquer on top of MWP**: every target is split into the four pipeline stages defined in [`CONTEXT.md`](CONTEXT.md) (`01_spec -> 02_implement -> 03_document -> 04_integrate`), and a target is only crossed off once `04_integrate` has promoted it into `src/`. Work one target at a time, tick each stage as its `output/` is written and reviewed, tick the target when it lands in the product.

## How to use this file

- Pick the top open target of the current wave. Do not fan out across many targets at once, the point of divide and conquer is a small reviewable pass per target.
- Split it into the four stages below. A stage that does not apply to a target is marked `N/A` (for example a pure-documentation target skips `02_implement`).
- Tick `- [x]` on a stage when its `output/` exists and passed its review gate. Tick the target row in the master table when `04_integrate` writes it into `src/` and logs it in [`04_integrate/output/integration-log.md`](04_integrate/output/integration-log.md).
- Preserve the intentional vulnerabilities. "Fix" here means make a broken or non-functional vulnerability actually exploitable and documented, or make the docs match the code. It never means hardening a working vuln away.
- Status badges follow the product convention: `DONE`, `IN PROGRESS`, `PENDING`. `[verified]` marks a claim confirmed live this session, `[doc]` marks a claim from the doc/code review still to be reproduced.

## Priority waves (suggested order)

1. **Wave 1 - Make the docs tell the truth** (structural, low risk, unblocks navigation): OWL-D1..D5, OWL-C1, OWL-C3, OWL-F3.
2. **Wave 2 - Repair the broken flagship chains** (intended vulns that do not fire): OWL-B1, OWL-B2.
3. **Wave 3 - Build the streaming centerpiece** (the lab is an IP-camera lab and this is its weakest surface): OWL-A1, OWL-A2, OWL-A3.
4. **Wave 4 - Expand coverage** (fill the thin categories): OWL-C2, OWL-F1, OWL-F2.
5. **Ongoing**: OWL-E1.

## Groundwork already promoted (this session)

- [x] **OWL-A0 - Virtual-camera streaming functional bring-up + HTTP MJPEG bridge** `DONE` [verified]. v4l2loopback producer moved from a broken ffmpeg call (`--disable-outdevs`) to gstreamer `v4l2sink`, plus a Flask bridge that serves the camera image on `:9090/video` so the cloud API marks the Pi camera active and snapshots render the real frame. Commit `490b0f9`. This is the enabling groundwork the streaming targets (OWL-A1..A3) build on.

---

## Master table

| ID | Done | Target | Group | Type | Status |
|----|------|--------|-------|------|--------|
| OWL-D1 | [x] | Dead doc routing `docs/IP Camera/` -> `docs/OwlCam/` | MWP integrity | Doc/Config | DONE [verified] |
| OWL-D2 | [x] | Add YAML frontmatter to every OwlCam vuln doc | MWP integrity | Doc | DONE [verified] |
| OWL-D3 | [x] | Standardize status badges to DONE/IN PROGRESS/PENDING | MWP integrity | Doc | DONE [verified] |
| OWL-D4 | [x] | Fix broken Obsidian wikilinks | MWP integrity | Doc | DONE [verified] |
| OWL-D5 | [x] | README onboarding polish (creds, host/IP confusion) | MWP integrity | Doc | DONE [verified] |
| OWL-C1 | [x] | Document the strong undocumented API vulns | API coverage | Doc | DONE [verified] |
| OWL-C3 | [x] | Fix API doc<->code drifts | API coverage | Code/Doc | DONE [verified] |
| OWL-F3 | [x] | C2 doc path drift + C2 port inconsistency | Mobile/C2 | Doc | DONE [verified] |
| OWL-B1 | [x] | IoT4 firmware crypto parity, finish the RCE chain | Broken chains | Code/Doc | DONE [verified] |
| OWL-B2 | [x] | `alg:none` JWT: make it work or remove it | Broken chains | Code/Doc | DONE [verified] |
| OWL-A1 | [x] | RTSP `:8554` serves corrupted JPEG (RFC 2435) | Streaming | Code/Doc | DONE [verified] |
| OWL-A2 | [x] | IoT2 real streaming attack (cleartext sniff/replay) | Streaming | Doc | DONE [verified] |
| OWL-A3 | [ ] | IoT3 concrete repro, de-stub | Streaming | Doc | PENDING [doc] |
| OWL-C2 | [ ] | Implement or downgrade the prose-only API categories | API coverage | Code/Doc | PENDING [doc] |
| OWL-F1 | [ ] | M6 token brute-force step-by-step repro | Mobile/C2 | Doc | PENDING [doc] |
| OWL-F2 | [ ] | Mobile coverage expansion (pinning, deep-links, MASVS) | Mobile/C2 | Code/Doc | PENDING [doc] |
| OWL-E1 | [ ] | API/mongo OOM (exit 137) under `mem_limit: 512m` | Operational | Config | PENDING [verified] |

---

## Targets divided into stages

### Wave 1 - Make the docs tell the truth

#### OWL-D1 - Dead doc routing `docs/IP Camera/` -> `docs/OwlCam/` · DONE [verified]
The folder `docs/IP Camera/` does not exist, the real path is `docs/OwlCam/`, yet Layer 0 (`src/AGENTS.md`) and both Layer 2 `CONTEXT.md` files route there. The whole owlcam doc chain is broken.
- [x] 01_spec - grepped every `docs/IP Camera` reference (AGENTS.md, both CONTEXT.md, cloud_api/CONTEXT.md, glossary, promotion-map), split path refs from prose
- [x] 02_implement - N/A (in-place path edits, no vuln code)
- [x] 03_document - N/A
- [x] 04_integrate - rewrote 6 files to `docs/OwlCam/`, verified no path ref remains, logged in integration-log.md

#### OWL-D2 - YAML frontmatter on every OwlCam vuln doc · DONE [verified]
No OwlCam vuln doc carries frontmatter (id/title/category/status/severity/owasp/cwe/affected_components), which the AGENTS.md convention requires and CANary already follows.
- [x] 01_spec - decided per-file collection frontmatter (docs aggregate many findings), 3 files in scope, README + C2 guides out
- [x] 02_implement - N/A
- [x] 03_document - authored 3 frontmatter blocks (8 convention fields + compact per-finding status), CWE/owasp aligned to the code paths
- [x] 04_integrate - prepended into the 3 files, validated YAML parses at byte 0, logged in integration-log.md

#### OWL-D3 - Standardize status badges · DONE [verified]
The API doc uses non-standard markers (`NOT DEVELOPED`, `PENDING REVIEW`, `ATTACK DOCUMENTATION PENDING`) instead of `DONE`/`IN PROGRESS`/`PENDING`.
- [x] 01_spec - mapped 7 non-standard markers (NOT DONE/NOT DEVELOPED/NOT DEVELOPED YET/ATTACK DOCUMENTATION PENDING/PENDING REVIEW) to canonical badges per finding
- [x] 02_implement - N/A
- [x] 03_document - normalized the 7 badges in API/Vulnerabilities.md, reconciled API8 frontmatter DONE -> IN PROGRESS
- [x] 04_integrate - verified no non-standard badge remains, logged in integration-log.md

#### OWL-D4 - Fix broken Obsidian wikilinks · DONE [verified]
Links like `[[IoT - Vulnerabilities and features#...]]`, `[[API - Vulnerabilities and features]]`, `[[Mobile - Vulnerabilities and features#...]]` and `app://obsidian.md/...` do not resolve to the actual `Vulnerabilities.md` filenames.
- [x] 01_spec - enumerated 15 dead links across the 3 docs, classified cross-file / self-ref / anchor-drift / junk, mapped real targets
- [x] 02_implement - N/A
- [x] 03_document - repointed all 15 (path-qualified cross-file, same-file anchors, junk removed) via asserted literal replacements
- [x] 04_integrate - verified no legacy note name / junk scheme remains and every anchor matches a real heading, logged

#### OWL-D5 - README onboarding polish · DONE [verified]
The README is vague on the device credentials ("default credentials or those you configured", real value `admin:12345678` only appears under IoT1) and mixes host targets (`10.0.2.2` emulator vs `192.168.2.2` host vs `localhost:5000`) without a clear map.
- [x] 01_spec - listed vague/stale spots, verified real values live (SSH root:12345678, admin denied; compose path, app path, package)
- [x] 02_implement - N/A
- [x] 03_document - added a host/port/cred map, made the credential explicit, fixed 3 wrong setup paths, aligned the mermaid SSH node
- [x] 04_integrate - verified README self-consistent and correct, flagged IoT1/M9 admin/package drifts for a C-family target, logged

#### OWL-C1 - Document the strong undocumented API vulns · DONE [verified]
The most powerful real findings are undocumented: `/firmware/trigger_update` command injection RCE (`subprocess.Popen(f"ssh root@{device_ip} ...", shell=True)` with attacker-controlled `device_ip`), `/sessions` unauthenticated session dump, `/camerasdb/delete` and `/camerasdb/restart` unauthenticated DB wipe, `/firmware/upload` unauthenticated upload, `/api/debug/decode_token`, `/api/v1/debug/sessions`.
- [x] 01_spec - confirmed all 6 in `app.py`, assigned OWASP/CWE, corrected the review (`/sessions` excludes `_id`, the token leak is `/api/v1/debug/sessions`)
- [x] 02_implement - N/A (endpoints already exist, documentation gap)
- [x] 03_document - added an "Exposed Debug and Administrative Endpoints" section: 6 findings with OWASP/CWE, curl repro, expected result, IN PROGRESS badges
- [x] 04_integrate - extended frontmatter findings (+6), verified YAML parses and prose style, logged

#### OWL-C3 - Fix API doc<->code drifts · DONE [verified]
`/admin/assign-role` does not exist (real route `/admin/roles`), the XSS payload reads `localStorage 'jwt'` but the key is `auth` (payload exfiltrates null), the `/snapshot` session-only bypass dead-ends because no session document ever sets `status:'active'`, plus the `/admin/v2/userinfo` and `/profile-change_password` typos. Broadened to absorb the IoT1 (SSH `admin`->`root`) and M9 (package `com.example.vulnzoo`->`com.example.owlcamapp`) drifts flagged in D5.
- [x] 01_spec - verified every drift against `app.py`/JS/manifest inline (real routes, `auth` key, 4 session sites with no `status`)
- [x] 02_implement - added `'status': 'active'` to all four session-creation sites so the documented `/snapshot` session bypass is reproducible (chains with the C1 `/api/v1/debug/sessions` token leak)
- [x] 03_document - corrected routes (`/admin/roles`, `/api/v2/userinfo`, `/profile/change_password`), the weak-Referer CSRF claim, the XSS `auth` key, the M9 package, the IoT1 `root:12345678` credential
- [x] 04_integrate - grep-verified no drift remains, `app.py` parses with 4 `status:'active'`, logged. Code change needs `docker compose up --build` for live repro (containers OOM), noted

#### OWL-F3 - C2 doc path + port consistency · DONE [verified]
The migration doc points the simulator at `cd cloud_api/c2_server` (real path `cloud_api/owlcam/c2_server`), and the M6 doc mixes "ports 80/443" prose with the actual C2 port `4999`.
- [x] 01_spec - verified real path, network (`owlcam_c2_net` from the live container) and port (4999) inline
- [x] 02_implement - N/A
- [x] 03_document - fixed the `cloud_api/owlcam/c2_server` path and `owlcam_c2_net` network in ARCH + MIGRATION, reconciled M6 to HTTP on port 4999
- [x] 04_integrate - grep-verified no drift remains, the referenced README resolves, logged

### Wave 2 - Repair the broken flagship chains

#### OWL-B1 - IoT4 firmware crypto parity + finish the chain · DONE [verified]
The doc encrypts the firmware with `openssl enc ... -pbkdf2 -salt`, but the on-device `/etc/init.d/update-firmware` decrypts with plain `-aes-256-cbc -k 'supersecret'` (no `-pbkdf2`, no salt). Under OpenSSL 3.x the KDF mismatch makes decryption fail, so the firmware-to-RCE chain never completes. Turned out to be broken three ways (parity + signature-grep-on-encrypted-file + a UTF-8-corrupted `firmware-v1.0.3`).
- [x] 01_spec - inline: found all three breaks, chose `-pbkdf2` canonical + grep-after-decrypt, validated the crypto round-trip
- [x] 02_implement - device `update-firmware` now decrypts with `-pbkdf2` and greps the decrypted script, regenerated `firmware-v1.0.3` (pbkdf2, clean binary), added a `.gitattributes` to keep it binary
- [x] 03_document - IoT4 snippet/inspect commands fixed, end-to-end repro + expected result added, badge + frontmatter `IN PROGRESS -> DONE`
- [x] 04_integrate - verified device-side on the live Pi (decrypt+grep+run), logged. `owlcam.tar.gz` rebuild (fresh flashes) and `docker compose up --build` (serve the new blob + full API walkthrough) are pending, noted

#### OWL-B2 - `alg:none` JWT: make it work or remove it · DONE [verified]
The config advertises `JWT_ALLOW_NONE_ALGORITHM=True` and `jwt_service` lists `'none'`, and the code comments call it an intended vuln, but it is non-functional: `decode_token` passes the non-empty `Config.JWT_SECRET_KEY`, and PyJWT 2.13 rejects `alg:none` with `InvalidKeyError: When alg = "none", key value must be None` (verified in isolation this session). The HS256 weak-secret path (`supersecretkey`) works and stays the intended chain.
- [x] 01_spec - decided to make it real (the classic attack), fix = decode with `verify_signature=False` when the header alg is `none`
- [x] 02_implement - `jwt_service.decode_token` branches on the header alg: `none` -> keyless decode, HS256 -> keyed decode (signature still enforced)
- [x] 03_document - corrected the false "does not bypass signature validation" claim, added a "Bypass: the `none` algorithm" subsection under API2 with the forge repro
- [x] 04_integrate - isolation-verified (alg:none accepted, HS256 wrong-secret still rejected), logged. Live-against-API and the `docker compose up --build` are pending (containers OOM), doc badge IN PROGRESS

### Wave 3 - Build the streaming centerpiece

#### OWL-A1 - RTSP `:8554` serves corrupted JPEG · DONE [verified]
v4l2rtspserver ships the loopback MJPEG as JPEG-over-RTP (RFC 2435), which strips the JPEG Huffman/quant tables so the receiver reconstructs a scrambled frame. Confirmed with two independent clients and a standard-Huffman re-encode, all corrupt. The loopback itself is byte-perfect. The API no longer depends on this (it reads the `:9090` bridge), but the RTSP surface the lab advertises is broken.
- [x] 01_spec - live-checked the Pi: no H264/H265 encoder on this build (only RTP payloaders + libav audio, no libx264), so H264-over-RTSP is out. Decision: declare the HTTP MJPEG on `:9090` the canonical decodable stream, re-scope RTSP to the raw insecure-services surface (feeds OWL-A2)
- [x] 02_implement - fixed a packaging bug: `camera-http` init script + `23-camera-http.sh` hook were tracked `100644` (non-exec) so the bridge never auto-started on flash. Both now `100755` (staged). Bridge config itself already serves the intact frame
- [x] 03_document - IoT2 rewritten with the two concrete plaintext endpoints (`:9090/video` MJPEG canonical, `:8554-:8556` RTSP mangled) + no-auth capture; README mermaid repointed the API feed to the HTTP bridge; CONTEXT.md Outputs/checklist updated; frontmatter streaming stack + IoT2 badge `IN PROGRESS`
- [x] 04_integrate - verified live: `:9090/video` serves a valid 640x480 JPEG byte-identical to source (md5 `fb672c...`), and the packaged hook->init path brings it up. Logged. `owlcam.tar.gz` rebuild pending (user-managed)

#### OWL-A2 - IoT2 real streaming attack · DONE [verified]
IoT2 (Insecure Network Services) was purely conceptual, no reproduction, no capture, no replay. For a camera lab the streaming attack is the centerpiece.
- [x] 01_spec - deviated from the original "weak-cred RTSP" idea: with the RTSP payload mangled (OWL-A1) and no on-device H264 encoder, weak-cred RTSP is low value and needs a re-flash. Centered the exercise on the cleartext capture (CWE-319) of the rendering HTTP MJPEG feed, plus unauthenticated RTSP as a secondary open-service target
- [x] 02_implement - N/A. The services are insecure by design (unauthenticated, plaintext), no overlay change needed. Repro tooling is inline in the doc (tcpdump/tshark/Wireshark + short carve/replay snippets)
- [x] 03_document - added Recon/enumeration, Passive capture (cleartext sniffing), and Replay subsections to IoT2 with copy-pasteable commands and expected results, kept impact + remediation, flipped the IoT2 finding badge to DONE
- [x] 04_integrate - verified live on the Pi: a frame reassembled from a `tcpdump` sniff of `:9090` is byte-identical to the live camera image (md5 `fb672c...`), unauthenticated RTSP DESCRIBE confirmed. Logged. `owlcam.tar.gz` unchanged (no overlay edit)

#### OWL-A3 - IoT3 concrete repro, de-stub · PENDING [doc]
IoT3 (Insecure Ecosystem Interfaces) is a stub that defers entirely to the API docs, with no repro of its own.
- [ ] 01_spec - define the concrete ecosystem path (stream reachable through the API BOLA/snapshot chain) that IoT3 owns
- [ ] 02_implement - N/A (reuses existing API + streaming), or minor glue if a demo needs it
- [ ] 03_document - give IoT3 its own repro tying the camera stream to the API access-control break
- [ ] 04_integrate - promote, log

### Wave 4 - Expand coverage

#### OWL-C2 - Implement or downgrade the prose-only API categories · PENDING [doc]
API4 (rate limiting), API6 (voucher/free-purchase), API7 (SSRF/CSRF/avatar-RCE) and the API3 mass-assignment sub-item are documented as attacks but not implemented, so three OWASP categories are dead prose.
- [ ] 01_spec - per category, decide implement vs downgrade-to-PENDING with an honest status
- [ ] 02_implement - build the endpoints/behaviors chosen for implementation
- [ ] 03_document - repro + expected result for the implemented ones, honest status for the rest
- [ ] 04_integrate - promote code + docs, repackage the API image, log

#### OWL-F1 - M6 token brute-force step-by-step repro · PENDING [doc]
M6 describes the weak C2 token (hex-digit sum mod 7) but has no runnable brute-force / token-forge walkthrough.
- [ ] 01_spec - define the repro (generate a valid token, validate via `/api/v2/diag/validate`, open the SSE channel, drive a capability)
- [ ] 02_implement - N/A (uses the existing c2_server), or a small helper script if useful
- [ ] 03_document - add the concrete steps and expected result to M6
- [ ] 04_integrate - promote, log

#### OWL-F2 - Mobile coverage expansion · PENDING [doc]
Only M6 and M9 are covered. Candidates to broaden the MASVS surface: certificate-pinning bypass, deep-link / exported-intent abuse, insecure logging, backup extraction.
- [ ] 01_spec - pick the next 1-2 MASVS findings that fit the app and are worth building
- [ ] 02_implement - app-side changes for the chosen findings
- [ ] 03_document - findings with frontmatter and repro
- [ ] 04_integrate - promote app + docs, log

### Ongoing

#### OWL-E1 - API/mongo OOM under `mem_limit: 512m` · PENDING [verified]
`vulnzoo-vulnerable` and `mongo` are currently `Exited (137)` (OOM-kill) under the compose `mem_limit: 512m`. The lab is not running until restarted. Decide whether the limit is too tight or document the expected restart.
- [ ] 01_spec - reproduce the OOM, decide raise-limit vs document-restart
- [ ] 02_implement - N/A
- [ ] 03_document - N/A (or a note in the setup guide)
- [ ] 04_integrate - adjust `docker-compose.yml` limit and/or the run docs, log

---

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Implemented in code and verified, promoted to `src/`. |
| IN PROGRESS | Implemented and documented, not yet verified on the live lab. |
| PENDING | Scoped here, not yet implemented or verified. |
| [verified] | Claim confirmed live this session (Pi, Docker stack, or isolated test). |
| [doc] | Claim from the doc/code review, still to be reproduced. |

## References

- Analysis these targets came from: this session's OwlCam structural + vuln-doc review.
- Pipeline contract: [`CONTEXT.md`](CONTEXT.md) and the per-stage `CONTEXT.md` files.
- Product routing: [`../src/AGENTS.md`](../src/AGENTS.md) (Layer 0) and [`../src/docs/OwlCam/`](../src/docs/OwlCam/).
- Promotion mapping: [`../_config/promotion-map.md`](../_config/promotion-map.md).
- Durable record of promotions: [`04_integrate/output/integration-log.md`](04_integrate/output/integration-log.md).
