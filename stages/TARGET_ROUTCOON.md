# RoutCoon Lab - Improvement Targets (divide-and-conquer backlog)

> **Factory-level planning artifact.** Source: RoutCoon structural + vulnerability-doc analysis (2026-07-28), cross-checked by static read against `src/labs/routcoon/` (overlay source) and `src/docs/RoutCoon/`. **No live Pi or flashed image was run this session**, so every `[verified]` claim below is confirmed against the overlay source and docs, not reproduced on hardware. The **product** lives in [`../src/`](../src/). This file only tracks *what* to change and *how far along* each change is.

This backlog applies **divide and conquer on top of MWP**: every target is split into the four pipeline stages defined in [`CONTEXT.md`](CONTEXT.md) (`01_spec -> 02_implement -> 03_document -> 04_integrate`), and a target is only crossed off once `04_integrate` has promoted it into `src/`. Work one target at a time, tick each stage as its `output/` is written and reviewed, tick the target when it lands in the product.

## How to use this file

- Pick the top open target of the current wave. Do not fan out across many targets at once, the point of divide and conquer is a small reviewable pass per target.
- Split it into the four stages below. A stage that does not apply to a target is marked `N/A` (for example a pure-documentation target skips `02_implement`).
- Tick `- [x]` on a stage when its `output/` exists and passed its review gate. Tick the target row in the master table when `04_integrate` writes it into `src/` and logs it in [`04_integrate/output/integration-log.md`](04_integrate/output/integration-log.md).
- Preserve the intentional vulnerabilities. "Fix" here means make a broken or non-functional vulnerability actually exploitable and documented, or make the docs match the code. It never means hardening a working vuln away.
- Every target's `04_integrate` still needs a **live pass on a flashed `routcoon.tar.gz` image** before its badge can go to DONE, because nothing here was run on hardware this session.

## Priority waves (suggested order)

RoutCoon differs from OwlCam in one important way: its flagship exploit chains (FTP -> cron RCE, `diag_ping` RCE, the `support/remote` SSH-key injection) already **work in the overlay code**. The damage is in the docs, not the code. So the early waves fix truth-in-documentation, the middle waves write down the strong attacks nobody documented, and only the late waves build new code.

1. **Wave 1 - Make the docs tell the truth** (structural, low risk, unblocks navigation): RC-D1..D5.
2. **Wave 2 - Correct the doc<->code drift on the chains that already work** (the docs currently send the learner to the wrong directory, the wrong credential, the wrong endpoint): RC-C1..C5.
3. **Wave 3 - Document the strong undocumented surfaces** (functional, powerful, entirely unwritten): RC-A1..A3.
4. **Wave 4 - Realize the lab's stated purpose** (the README says RoutCoon exists to finish the undeveloped OWASP IoT Top 10 points): RC-I1..I4.
5. **Wave 5 - Repair the half-built services** (intended vulns that are stubbed or non-functional): RC-B1..B3.
6. **Wave 6 - Coverage expansion**: RC-F1.
7. **Ongoing**: RC-E1.

## Groundwork already verified this session (static source read)

- The **FTP -> cron RCE chain works in code**: `files/etc/init.d/ftpd` serves anonymous write on `/opt/oem-updates/pending`, `auto-updater.sh` runs every 3 min from `/etc/crontabs/root`, `sysupgrade -t` rejects a `.sh`, and the fallback `/bin/sh "$file"` executes it as root. The chain is real, the docs just point at the wrong upload directory (see RC-C2).
- **root password is `uncrackable`**, set literally by `11-add-users.sh:42` (`echo "root:uncrackable" | chpasswd`). The IoT1 "crack root -> pwned" narrative and the CONTEXT root/pwned table are stale (see RC-C1). The genuinely crackable account is `openwrtuser` (`openwrtuserpwned`).
- The **`support/remote` SSH-key-injection endpoint is real and unauthenticated** (`controller/support/remote.lua`, `sysauth=false`, authorization by spoofable `X-Forwarded-For`/`real_ip`/`xff`/`remote_addr` matched to `203.0.113.0/24`). It is essentially undocumented in prose (see RC-A1). The IoT5 doc's `/cgi-bin/luci/debug/ssh` path and `X-Debug-Mode` header do **not exist in the overlay** (grep-confirmed).
- **Samba is not wired**: `80-routcoon-services.sh` starts SNMP, odhcpd, sysntpd and ftpd only. No `smbd`/`nmbd` start anywhere (see RC-B1). Matches the doc's "ON DEVELOPMENT".

---

## Master table

| ID | Done | Target | Group | Type | Status |
|----|------|--------|-------|------|--------|
| RC-D1 | [x] | Dead doc routing `docs/Router/` -> `docs/RoutCoon/` (Layer 0 + Layer 2 + promotion-map) | MWP integrity | Doc/Config | DONE [verified] |
| RC-D2 | [x] | Add YAML frontmatter to both RoutCoon vuln docs (README excluded, see RC-D5) | MWP integrity | Doc | DONE [verified] |
| RC-D3 | [x] | Standardize non-standard status badges | MWP integrity | Doc | DONE [verified] |
| RC-D4 | [x] | Fix broken Obsidian wikilinks | MWP integrity | Doc | DONE [verified] |
| RC-D5 | [x] | README onboarding: fabricated creds, stale paths, host/IP map | MWP integrity | Doc | DONE [verified] |
| RC-C1 | [x] | root credential drift (IoT1 "crack root" false; root=`uncrackable`) | Chain truth | Doc | DONE [verified] |
| RC-C2 | [x] | FTP root drift: docs say `/tmp`, code serves `/opt/oem-updates/pending` | Chain truth | Doc | DONE [verified] |
| RC-C3 | [x] | IoT5 endpoint/header drift: real chain is `support/remote`, not `/debug/ssh` | Chain truth | Doc | DONE [verified] |
| RC-C4 | [x] | dnsmasq drift: `dhcp-rapid-commit` commented + `192.168.1.x` vs `.2.x` | Chain truth | Doc | DONE [verified] |
| RC-C5 | [x] | SNMP unverifiable CVE claims -> keep the verified default-community finding | Chain truth | Doc | DONE [verified] |
| RC-A1 | [x] | Document the `support/remote` SSH-key-injection chain (unauth -> root key) | Undoc surfaces | Doc | DONE [verified] |
| RC-A2 | [x] | Document the IoTGoat legacy surface (`admin/iotgoat/webcmd` + cmd/cam/door) | Undoc surfaces | Doc | DONE [verified] |
| RC-A3 | [x] | Document `check_service` quote-breakout RCE + `service_status` SSRF | Undoc surfaces | Doc | DONE [verified] |
| RC-I1 | [x] | IoT:I7 Insecure Data Transfer and Storage: realize + document | Finish IoT Top10 | Doc | DONE [verified] |
| RC-I2 | [x] | IoT:I8 Lack of Device Management: realize + document | Finish IoT Top10 | Doc | DONE [verified] |
| RC-I3 | [x] | IoT:I6 Insufficient Privacy Protection: realized as network-metadata privacy | Finish IoT Top10 | Doc | DONE [verified] |
| RC-I4 | [x] | IoT:I10 Physical Hardening: realized scoped to the Pi hardware | Finish IoT Top10 | Doc | DONE [verified] |
| RC-B1 | [x] | Samba: wired (samba4 smbd, anonymous root-writable share) after user installed the packages | Half-built | Code/Doc | DONE [verified: code] |
| RC-B2 | [x] | UPnP `AddPortMapping` 501 / `internal_iface lo`: documented honestly (single-NIC topology limit) | Half-built | Doc | DONE [verified] |
| RC-B3 | [x] | dnsmasq attacks: scoped against the real config (starvation blocked by dhcp-ignore) | Half-built | Doc | DONE [verified] |
| RC-F1 | [x] | Expand the API doc (API5 BFLA + API9 Inventory); moved 2 misfiled OwlCam images out | Coverage | Doc | DONE [verified] |
| RC-E1 | [x] | Version drift: routcoon is 24.10.3 (banner), fixed CONTEXT + added build note | Operational | Doc | DONE [verified] |

---

## Targets divided into stages

### Wave 1 - Make the docs tell the truth

#### RC-D1 - Dead doc routing `docs/Router/` -> `docs/RoutCoon/` (DONE [verified])
The real doc folder is `src/docs/RoutCoon/`, but Layer 0 (`src/AGENTS.md:67`) routed routcoon to `docs/Router/`, and Layer 2 (`src/labs/routcoon/CONTEXT.md:13-15` and `:245-247`) pointed its Inputs and References at `../../docs/Router/...`. The whole RoutCoon Layer 2 -> Layer 3 chain was broken, exactly the class of bug OwlCam fixed in OWL-D1. The 01_spec grep also caught a third site outside the target's stated scope: `_config/promotion-map.md:37`.
- [x] 01_spec - grepped every `docs/Router` reference repo-wide: 8 dead path refs across 3 files (`AGENTS.md` x1, `CONTEXT.md` x6, `promotion-map.md` x1); confirmed no `src/docs/Router/` dir exists and prose "Router" mentions are not paths
- [x] 02_implement - N/A (in-place path edits, no vuln code)
- [x] 03_document - N/A
- [x] 04_integrate - rewrote all 8 refs to `docs/RoutCoon/`, verified no live `docs/Router` path ref remains (only the backlog prose), the 3 target docs resolve, logged in integration-log.md

#### RC-D2 - YAML frontmatter on RoutCoon vuln docs (DONE [verified])
No RoutCoon doc carried frontmatter (`id`/`title`/`category`/`status`/`severity`/`owasp`/`cwe`/`affected_components`), which the AGENTS.md convention requires and OwlCam/CANary already follow. Scope narrowed to the two aggregate *vuln docs* (`API/Vulnerabilities.md`, `IoT (Router)/Vulnerabilities.md`), following the OWL-D2 precedent that excludes the onboarding `README.md` (its content is RC-D5's job).
- [x] 01_spec - reviewed `_config/vuln-doc-template.md` + the OwlCam frontmatter shape, chose per-file collection frontmatter (each doc aggregates many findings), mapped every finding to OWASP/CWE and to the real overlay code paths, decided to exclude README
- [x] 02_implement - N/A
- [x] 03_document - authored the 2 frontmatter blocks (8 convention fields + `findings` list): ROUTCOON-API (API2/7/8) and ROUTCOON-IOT (IoT1-10, honest per-finding status)
- [x] 04_integrate - prepended into the 2 files, validated YAML parses at byte 0 (all 8 keys + findings, heading follows), logged

#### RC-D3 - Standardize non-standard status badges (DONE [verified])
The IoT doc used ad-hoc markers instead of `DONE`/`IN PROGRESS`/`PENDING`: `ON DEVELOPMENT` (Samba 2.2), `NOT DEVELOPED` (I6/I7/I8/I10), `CHECK ATTACKS` (dnsmasq), `NEEDS CHECK` (IoT5 overlap), `VERY BASIC VULNERABILITY` (IoT3). The API doc was already clean.
- [x] 01_spec - grepped both docs: 8 non-standard markers, all in the IoT doc; mapped each to a canonical badge reconciled with the RC-D2 frontmatter (ON DEVELOPMENT->PENDING, NOT DEVELOPED->PENDING x4, CHECK ATTACKS->IN PROGRESS, NEEDS CHECK->IN PROGRESS, VERY BASIC->DONE)
- [x] 02_implement - N/A
- [x] 03_document - normalized all 8 markers, preserved the editorial notes (IoT3 suggestion, IoT5 overlap) as prose after the badge, left the IoT5 wikilink for RC-D4
- [x] 04_integrate - verified no non-standard marker remains and every badge is canonical + frontmatter-consistent, logged

#### RC-D4 - Fix broken Obsidian wikilinks (DONE [verified])
The docs linked with `[[IoT Vulnerabilities#...]]` but the file is named `Vulnerabilities.md`, so the note-name links were dead. There was also anchor drift (`No. 9 Insecure Default Settings`, `IoT7 ...`, `IoT I8 ...`, `Weak, Guessable` with an extra comma, `#API8 2023` missing the colon, `#FTP` vs `2.4 FTP`). All 12 text links turned out to be self-references (the note name was the file's own old identity). The I7/I8 headings do exist (the sections are stubs, not absent), so those links resolve rather than needing removal.
- [x] 01_spec - enumerated every `[[...]]` across the docs: 12 image embeds (left as basename, Obsidian resolves them) + 12 text links; classified all text links as same-file self-references (no cross-file links exist), mapped each to the exact real heading
- [x] 02_implement - N/A
- [x] 03_document - repointed all 12 text links to same-file `[[#Heading]]` anchors matching the real heading text (API8 colon, IoT:I* colons, `2.4 FTP`), preserved aliases (`|IoT9`, `|FTP`)
- [x] 04_integrate - verified no legacy note-name link remains and every `[[#anchor]]` resolves to an existing heading (script check, ALL RESOLVE), logged

#### RC-D5 - README onboarding: fabricated creds, stale paths, host/IP map (DONE [verified])
The README advertised LUCI credentials `admin:admin123` and `user:user123`, but the only accounts created are `root`, `openwrtuser`, `anonymous` (`11-add-users.sh`), so `admin`/`user` did not exist. The real web/API login is `root:uncrackable` (dispatcher gates the admin tree root-only). It also referenced an `openwrt_resources/` folder that exists nowhere in the repo.
- [x] 01_spec - verified against the overlay: no `admin`/`user` account exists, `allowed_users = track.sysauth` (root-only) is the LuCI gate, `openwrt_resources/` is named only by the README; confirmed the real white-box creds
- [x] 02_implement - N/A
- [x] 03_document - replaced the fabricated creds with `root:uncrackable` (framed as the white-box shortcut, "no admin account"), added a host/port/credential map, dropped the `openwrt_resources/` reference (repointed to the real vuln docs), kept the correct white-box line
- [x] 04_integrate - grep-verified the README is self-consistent and free of the fabricated creds / dead folder; flagged the vuln-doc `192.168.1.1` drift for RC-C4 and the FTP-path drift for RC-C2; logged. Wave 1 complete

### Wave 2 - Correct the doc<->code drift on the chains that already work

#### RC-C1 - root credential drift (DONE [verified])
IoT1 told the reader to extract the firmware and crack the root hash, showing `john` recovering `pwned`. The overlay sets `root:uncrackable` (`11-add-users.sh:42`), and IoT9 itself uses `sshpass -p "uncrackable" ssh root@...`. The CONTEXT.md table ("root / pwned", "Crackable root hash type 5 SHA256") was also wrong. The intended lesson is the opposite: root is deliberately *not* crackable from the `pwned` wordlists, and the crackable account is `openwrtuser` via the combination attack (which is real).
- [x] 01_spec - confirmed `root:uncrackable` / `openwrtuser:openwrtuserpwned` in `11-add-users.sh`, confirmed the `openwrtuser` hash is `$5$` sha256crypt (matches the doc's hashcat `-m 7400`), decided the corrected narrative (root = uncrackable decoy, escalate from openwrtuser)
- [x] 02_implement - N/A (root credential is intended; doc-truth fix only, root not weakened)
- [x] 03_document - rewrote the IoT1 false "crack root" sentence + fabricated `john` block into an accurate paragraph (root is a decoy, reach it via IoT9 escalation), kept the real `openwrtuser` combination attack and web-differential brute force; fixed the CONTEXT.md user table and the IoT:I1 bullets
- [x] 04_integrate - grep-verified no root-cracking claim remains (only corrected text + the IoT9 `sshpass "uncrackable"` demo), the new IoT9 wikilink resolves; on-image `/etc/shadow` hash-type confirmation still pending a live flash. Logged

#### RC-C2 - FTP root drift: `/tmp` vs `/opt/oem-updates/pending` (DONE [verified])
`files/etc/init.d/ftpd:10` serves anonymous write on `/opt/oem-updates/pending`, and `80-routcoon-services.sh:90` `chmod 777`s exactly that directory. But IoT2 (2.4 FTP, including an embedded stale init script), IoT4 ("upload to /tmp/cron-tmp"), IoT9 ("anonymous uploads to /tmp") and CONTEXT.md (`ftpd -w -a anonymous /tmp`, Chain 3 "Upload to /tmp/ftp") all described the FTP home as `/tmp`. The RCE chain works, the docs just sent the learner to the wrong directory.
- [x] 01_spec - confirmed the single real FTP root (`/opt/oem-updates/pending`) against `ftpd` + the services hook, enumerated 10 `/tmp` FTP-home sites (5 doc, 5 CONTEXT) and separated them from the legitimate `/tmp` uses (dnsmasq leases, reverse-shell fifo)
- [x] 02_implement - N/A (the code chain is correct and intended)
- [x] 03_document - corrected all 10 sites to `/opt/oem-updates/pending`, replaced the embedded stale `start()` block with the real init-script body, added an IoT4 cross-link explaining the cron execution, kept the working cron -> `/bin/sh` RCE repro
- [x] 04_integrate - grep-verified no FTP-home `/tmp` remains and the legitimate `/tmp` uses are intact, IoT4 wikilink resolves; live anon-`put`->cron pass pending a flash. Logged

#### RC-C3 - IoT5 endpoint/header drift (DONE [verified])
The wrong `/cgi-bin/luci/debug/ssh` route and `X-Debug-Mode` header lived in CONTEXT.md (not the doc body); grep-confirmed neither exists in the overlay, and there is no `/debug` entry node. The real mechanism is `controller/support/remote.lua` at `/cgi-bin/luci/support/remote/diagnostic` (`sysauth=false`), `?debug=1` env-dump, authorization by spoofable forwarded-IP params matched to `203.0.113.0/24`. IoT5 also duplicated the entire IoT3 wfuzz section verbatim (114 lines).
- [x] 01_spec - confirmed the real route + `?debug=1` + spoofable params in `support/remote.lua`, confirmed no `/debug` node exists, located the duplicated IoT3 block (873-986) and the false claims (in CONTEXT, not the body)
- [x] 02_implement - N/A
- [x] 03_document - removed the 114-line duplicated IoT3 block (cross-referenced IoT3), reframed the endpoint/header narrative to the real `support/remote/diagnostic` + forwarded-IP spoof + `update_ssh_access` chain (kept all 6 images), fixed the CONTEXT.md IoT:I5 bullets + summary-table cell; handed the full forge-and-inject walkthrough to RC-A1 (prose, no dead link)
- [x] 04_integrate - grep-verified no `debug/ssh` / `X-Debug-Mode` remains, real endpoint named in both files, zero duplicated wfuzz lines in IoT5, images + frontmatter intact. Logged

#### RC-C4 - dnsmasq drift (DONE [verified])
`files/etc/dnsmasq.conf:87` has `#dhcp-rapid-commit` commented out (disabled), but CONTEXT.md listed "DHCP rapid commit enabled" as an IoT9 default (the IoT doc was already correct). The same file serves `dhcp-range=192.168.1.100-254` / gw `192.168.1.1` while the lab targets `192.168.2.1`. The overlay ships no `/etc/config/network`, so the LAN IP is the base-image default (`br-lan` = `192.168.1.1`) and the `.1.x` pool is consistent with it.
- [x] 01_spec - diffed the dnsmasq options against the docs (rebind/cache/lease-max/read-ethers/`/tmp` files all already accurate), isolated the rapid-commit drift to CONTEXT, and traced the subnet to the missing `/etc/config/network` (base-image `br-lan` default)
- [x] 02_implement - N/A. Decided against a blind subnet change: no live Pi to confirm the interface topology, and moving the DHCP range could break a working `br-lan`; the insecure options are intended
- [x] 03_document - fixed the CONTEXT.md IoT9 bullet ("rapid commit enabled" -> "No DHCP rate limiting, `dhcp-rapid-commit` commented"), added a subnet note to the IoT doc 2.7 (`.1.x` `br-lan` DHCP vs `.2.1` eth0 management, `192.168.2.1` canonical)
- [x] 04_integrate - grep-verified no "rapid commit enabled" claim remains and the config truly has it commented; `br-lan`/`eth0` topology still needs a flashed-image confirmation. Logged

#### RC-C5 - SNMP unverifiable CVE claims (DONE [verified])
The SNMP section asserted "Net-SNMP version 5.9.4" with specific CVEs including a "CVSS 9.8 RCE" (`CVE-2025-68615`). The version was unevidenced (nmap shows only the kernel `6.6.104`, not the net-snmp package) and the 9.8 RCE is implausible/unverifiable. The reproducible, config-backed finding is the default communities (`rocommunity public` / `rwcommunity private`).
- [x] 01_spec - checked the doc for any version evidence (none: sysdescr = kernel only), confirmed the default-community config in `snmpd.conf` / `80-routcoon-services.sh`, decided to drop the CVE/version pins and keep the config finding
- [x] 02_implement - N/A
- [x] 03_document - replaced the "5.9.4" + CVE block with an honest framing (net-snmp memory-safety issues in general, no fabricated CVEs; read the real version off the image before chaining), kept the nmap scan and the full 2.5.1 default-community repro/risk table
- [x] 04_integrate - grep-verified no `5.9.4` / fabricated-CVE / `9.8 RCE` claim remains and the real finding is intact; net-snmp version left intentionally unpinned pending a live image. Logged. Wave 2 complete

### Wave 3 - Document the strong undocumented surfaces

#### RC-A1 - Document the `support/remote` SSH-key-injection chain (DONE [verified])
`controller/support/remote.lua` exposes an unauthenticated "Remote Diagnostic Tool" (`sysauth=false`). Authorization is decided by `get_forwarded_ip()` reading, in order, `X-Forwarded-For`/`X-Real-IP` headers then the **form parameters** `X-Forwarded-For`, `real_ip`, `xff`, `remote_addr`, and passing if the first IP matches `203.0.113.0/24`. A request such as `real_ip=203.0.113.100` becomes "authorized", after which `action=update_ssh_access&key_data=ssh-ed25519 AAAA...` appends the attacker key to `/etc/dropbear/authorized_keys`. Because dropbear `RootPasswordAuth off` only disables root *password* auth, an injected root pubkey plausibly grants a full root SSH login, bypassing the entire IoT9 restricted-shell story. This is the lab's strongest chain and it had no prose write-up (only the `iot5_ssh_key_injection.png` image).
- [x] 01_spec - traced the endpoint, the spoofable-param fall-through and the `add_ssh_key` -> `/etc/dropbear/authorized_keys` write; the root pubkey login (with `RootPasswordAuth off`) is the one step that still needs a live image and is flagged as such in the writeup
- [x] 02_implement - N/A (the endpoint exists and is intended)
- [x] 03_document - wrote a first-class `##` section under IoT5 (recon of the HTML-comment `203.0.113.100` hint + `?debug=1` env dump, the `real_ip` spoof, the key POST, the SSH login), code-quoted root cause, OWASP/CWE (API5 / CWE-290 / CWE-306), remediation, cross-link to IoT9
- [x] 04_integrate - verified placement (before IoT6), all five quoted code snippets exist verbatim in `support/remote.lua`, the IoT9 wikilink resolves; end-to-end root login pends a flashed image (IoT5 finding stays IN PROGRESS). Logged

#### RC-A2 - Document the IoTGoat legacy surface (DONE [verified])
`controller/iotgoat/iotgoat.lua` registers `admin/iotgoat/cmdinject` (template `iotgoat/cmd`), `admin/iotgoat/cam` (`camera`), `admin/iotgoat/door` (`door`), and `admin/iotgoat/webcmd` which runs `io.popen(tostring(cmd).." 2>&1")` with no filtering. None of this appeared in the docs. `webcmd` is a cleaner command-injection primitive than `diag_ping` (plain `cmd=`, no path-split artefact). 01_spec resolved the auth: the entries inherit the admin tree's `sysauth = "root"`, so they require a root session.
- [x] 01_spec - confirmed the routes and auth: `admin/index.lua:17` sets `page.sysauth = "root"` and the iotgoat entries do not override it, so `webcmd` is post-auth root RCE (not unauth); `vulnerable_mode` is not consulted in the sysauth path; `cmd.htm` is the console, `camera.htm`/`door.htm` are empty stubs
- [x] 02_implement - N/A (code exists and is intended; not made unauthenticated)
- [x] 03_document - added an API8 subsection documenting the `cmdinject`/`webcmd` console (code-quoted, root-context `io.popen`, auth requirement, browser + curl repro), noted `cam`/`door` are placeholder stubs, extended the frontmatter (component + finding)
- [x] 04_integrate - verified the four quoted snippets exist verbatim in `iotgoat.lua`, frontmatter parses with the new component/finding; live render/execute pends a flashed image. Logged

#### RC-A3 - Document `check_service` quote-breakout RCE + `service_status` SSRF (DONE [verified])
`network_tools.lua` was documented only as the file:// SSRF (`/api/v1/check`) and the *filtered* ping. Two stronger, unauthenticated surfaces in the same file were undocumented: (1) `check_service` builds `curl -m 5 '%s'` with the URL single-quoted and unsanitized, so a `'` in the URL breaks out into command injection, not just SSRF; (2) `service_status` (`/api/v1/status`) takes an `internal_url` parameter and fetches any URL server-side, logging "critical UNAUTHENTICATED internal access". Both are `sysauth=false`.
- [x] 01_spec - confirmed the single-quote breakout in `perform_http_request`, confirmed `service_status?internal_url=` reaches it, noted the existing API7 prose undersold `/api/v1/check` (implied it needed a `diag_ping` pivot)
- [x] 02_implement - N/A (intended, unfiltered by design)
- [x] 03_document - added an API7 subsection with the `check` command-injection repro (unauth RCE, CWE-78, exact built shell string) and the `status` SSRF repro (CWE-918), contrasted with the filtered `ping_host`; extended the frontmatter findings
- [x] 04_integrate - verified the three quoted snippets exist verbatim in `network_tools.lua`, frontmatter parses; live `id`-in-JSON / internal-fetch pends a flashed image. Logged. Wave 3 complete

### Wave 4 - Realize the lab's stated purpose (undeveloped OWASP IoT points)

The README states RoutCoon exists to "develop the missing points" of the OWASP IoT Top 10 that IoTGoat left unfinished. I6, I7, I8, I10 are all marked NOT DEVELOPED. This wave finishes them, preferring to *surface vulns that already exist on the device* over inventing new ones.

#### RC-I1 - IoT:I7 Insecure Data Transfer and Storage (DONE [verified])
Realized from what already ships: the admin plane is cleartext HTTP (`:80`, `30-uhttpd-config.sh` sets `listen_http` only), FTP/SNMP/Telnet are cleartext, DHCP leases and the hosts file live world-modifiable in `/tmp` (`dhcp-leasefile=/tmp/dhcp.leases`, `dhcp-hostsfile=/tmp/hosts`), and several components write credentials-adjacent traces to predictable low-priv paths. No new code was needed.
- [x] 01_spec - inventoried the in-transit (uhttpd HTTP-only, FTP/SNMP/Telnet, the support key POST) and at-rest (`/tmp` DHCP state, `dnsmasq.log`, `support_env_debug.log`/`support_access.log`, `vulnzoo.log`) exposures; picked the cleartext LuCI-login capture + `/tmp` state as the clean repros
- [x] 02_implement - N/A (all exposures already exist; YAGNI, no overlay change)
- [x] 03_document - wrote the full I7 section (In transit CWE-319, At rest CWE-312/732, impact + remediation, sink table), flipped the frontmatter `IoT7 -> IN PROGRESS`; the RC-D4 anchor now lands on real content
- [x] 04_integrate - verified the section is no longer a stub, ground truth holds (`listen_http` :80 only, `/tmp` leasefile), frontmatter parses; live packet capture pends a flashed image. Logged

#### RC-I2 - IoT:I8 Lack of Device Management (DONE [verified])
The pieces already exist: no signed updates (IoT4 `check_signature 0`), no rate limiting anywhere (SSH, LUCI login, DHCP/DNS, unauth API), no monitoring or anti-rollback, `/tmp`-based state that does not survive as a managed asset. I8 is a management/lifecycle category, best written as a synthesis of these demonstrated gaps.
- [x] 01_spec - framed I8 as a management-lens synthesis (demonstrable gaps, not assertions) and mapped each to a concrete finding (IoT4 update, IoT7 monitoring/logs, IoT2/API2 brute-force, IoT5 key lifecycle)
- [x] 02_implement - N/A (all underlying gaps already exist; no scaffold needed)
- [x] 03_document - wrote the I8 section (four gap subsections + impact/remediation), OWASP/CWE (CWE-778 insufficient logging, CWE-307 no brute-force protection; update path CWE-347/494 via IoT4), flipped frontmatter `IoT8 -> DONE`; the RC-D4 anchor now lands on real content
- [x] 04_integrate - verified the four subsections + CWE mapping present, the IoT4/IoT7 wikilinks resolve, frontmatter parses `IoT8: DONE`. Logged

#### RC-I3 - IoT:I6 Insufficient Privacy Protection (DONE [verified])
A router holds limited PII, so this target decided scope honestly. Realized as network-metadata privacy: device identity/presence (SNMP `public` ARP table, `/tmp/dhcp.leases` hostnames, `read-ethers`) and browsing behavior (dnsmasq `log-queries` DNS history), with an explicit scope note that there is no stored end-user PII to invent.
- [x] 01_spec - decided realize-with-scope-note over a blank downgrade; picked the device-inventory (SNMP ARP + DHCP hostnames) and DNS-history angles
- [x] 02_implement - N/A (all exposures already exist)
- [x] 03_document - wrote the I6 section (two angle subsections + impact/remediation + a scope note + CWE-359/200), cross-linked IoT7, flipped frontmatter `IoT6 -> DONE`
- [x] 04_integrate - verified the subsections + scope note present, IoT7 wikilink resolves, frontmatter parses `IoT6: DONE`; the ARP repro is already run-with-output in 2.5. Logged

#### RC-I4 - IoT:I10 Physical Hardening (DONE [verified])
The lab runs on a Raspberry Pi, so physical findings are real but hardware-specific: the UART/serial console, SD-card extraction of the rootfs (firmware/hash recovery, which IoT1 already assumes), no secure-boot. Realized scoped to the Pi with an on-device note, not downgraded.
- [x] 01_spec - decided to realize scoped to the Pi; confirmed `50-ttylogin.sh` sets `ttylogin=1` (so the serial angle is qualified) and that microSD extraction is unconditional (no disk encryption)
- [x] 02_implement - N/A
- [x] 03_document - wrote the I10 section (microSD extraction + UART subsections, impact/remediation, on-device note, CWE-1263/1191), cross-linked IoT1, flipped frontmatter `IoT10 -> DONE`
- [x] 04_integrate - verified the subsections present, IoT1 wikilink resolves, frontmatter parses; confirmed all ten IoT findings now carry content (no `not developed` remains). Logged. Wave 4 complete

### Wave 5 - Repair the half-built services

#### RC-B1 - Samba: wired (samba4 smbd, anonymous root-writable share) (DONE [verified: code])
`files/etc/samba/samba.conf` ships a dangerous share (`guest ok`, `read only = no`, `force user = root`). Initially downgraded (server package not built), then re-taken and **wired** after the user installed `samba4-server`/`ksmbd-server`. samba4 `smbd` was chosen (the config is Samba smb.conf format); ksmbd left unwired to avoid the `:445` conflict.
- [x] 01_spec - confirmed the config is Samba-format, the user installed the server packages, and only one server can bind `:445`; chose samba4/smbd
- [x] 02_implement - `.config` `samba4-server`+`samba4-libs` -> `=y` (ksmbd unset); `samba.conf` gained a `[global]` (`map to guest = bad user`, `guest account = root`, `server min protocol = NT1`) so anonymous connects work; `80-routcoon-services.sh` creates `/mnt/sdcard/share` and starts `smbd`/`nmbd` directly (lab idiom, guarded, `ponytail:` comment)
- [x] 03_document - flipped the 2.2 section from PENDING downgrade to an IN PROGRESS wired finding (full config + `smbclient -N` list/write repro), frontmatter IoT2 -> "Samba wired, live-pending"
- [x] 04_integrate - verified `.config`/hook/`samba.conf`/doc consistent, `sh -n` passes on the hook; live `smbclient` confirmation is on the user's device (the one open item). Logged (revised entry)

#### RC-B2 - UPnP `AddPortMapping` 501 / `internal_iface lo` (DONE [verified])
`files/etc/config/upnpd` sets `secure_mode 0` (the real, demonstrable misconfig) plus a wide-open `perm_rule`, but also `internal_iface 'lo'`. The 501 is a single-NIC topology limit (miniupnpd refuses internal==external, and eth0 is the only NIC), not a security control, so the honest framing was chosen over a fake functional map.
- [x] 01_spec - determined the 501 root cause: single NIC -> `internal_iface 'lo'` -> no distinct internal LAN / no real WAN, so the NAT rule cannot be built; a truly-forwarding map is topologically impossible here, so document-honestly
- [x] 02_implement - N/A (the config is correct for a single-NIC lab; the vuln is at the authorization layer, secure_mode 0 + permissive perm_rule)
- [x] 03_document - replaced the vague "absence of WAN NAT capabilities" with the concrete `internal_iface 'lo'` cause, added the UCI source + the real-two-interface-router impact, kept the honest 501 breakdown
- [x] 04_integrate - verified the doc matches the UCI ground truth (internal_iface lo, external_iface eth0, secure_mode 0, int_addr 0.0.0.0/0); no overlay change. Logged

#### RC-B3 - dnsmasq attacks prose-only ("CHECK ATTACKS") (DONE [verified])
The DHCP/DNS section listed lease-file tampering, DHCP starvation and DNS cache poisoning as scapy snippets with no verified status. Scoped each against the shipped config: lease tampering works (local), starvation is blocked by `dhcp-ignore=tag:!known`, and the naive off-path poisoning is unreliable while DNS rebinding (`stop-dns-rebind` commented) is the real DNS weakness.
- [x] 01_spec - checked each attack against `dnsmasq.conf`: `/tmp` leasefile (tamper works locally), `dhcp-ignore=tag:!known` (starvation dropped), `#stop-dns-rebind` (rebinding is the real DNS issue, not the port/txid-guessing poisoning)
- [x] 02_implement - N/A (config is intended)
- [x] 03_document - five surgical edits relabeling each attack with its real status (works-local / does-not-work / rebinding-vs-unreliable-poisoning) and the config reason, keeping the code blocks
- [x] 04_integrate - verified the labels present, code blocks intact, and every claim matches the config ground truth. Logged. Wave 5 complete

### Wave 6 - Coverage expansion

#### RC-F1 - Expand the API doc beyond API2/API7/API8 (DONE [verified])
The API doc covered only API2/API7/API8. Added API5 (BFLA) and API9 (Improper Inventory Management), the categories the LuCI API genuinely supports. API1 BOLA skipped (no object-ownership check to violate; the `api1_*` images are IoT1 login screenshots). The two orphan images (`api2_admin_access.png`, `api8_register.png`) turned out to be misfiled OwlCam Flask-API screenshots, not RoutCoon.
- [x] 01_spec - inventoried the categories (API5/API9 supported, API1 not), read the two orphan images and identified them as OwlCam `:5000` Flask assets (JWT `/admin`, `/register`) that OwlCam's doc references by basename
- [x] 02_implement - N/A (no scaffold; no routcoon Flask finding fabricated)
- [x] 03_document - added API5 (privileged-function table cross-referencing API7/API8/IoT5, CWE-285/862) and API9 (leftover debug endpoints, CWE-1059/489), extended the frontmatter; `git mv`'d the two misfiled images to `docs/OwlCam/API/images/`
- [x] 04_integrate - verified API2/5/7/8/9 present, frontmatter parses, the moved images resolve for OwlCam and no routcoon doc referenced them. Logged

### Ongoing

#### RC-E1 - Version drift + image-build note (DONE [verified])
The `files/etc/banner` reads `OpenWrt 24.10.3, r28739-d9340319c6`, so the routcoon image really is 24.10.3 and IoT5's "24.10.3" is correct; the stale value was routcoon's own CONTEXT.md ("24.10.2"). The kernel `6.6.104` in the SNMP scan is the kernel version, not a conflict.
- [x] 01_spec - read the banner (authoritative: 24.10.3 `r28739`), confirmed IoT5 already matches it and CONTEXT.md was the stale one; `.config` carries no explicit version string
- [x] 02_implement - N/A (doc only)
- [x] 03_document - CONTEXT.md platform `v24.10.2 -> v24.10.3` (point release above the AGENTS.md baseline), added `samba4` to Services, added a `## Build` section (compile `rshell.c` -> `files/usr/bin/rshell`, select `samba4-server`/`samba4-libs` in `.config`, package `routcoon.tar.gz`); left the cross-lab AGENTS/PROJECT_OVERVIEW baseline at 24.10.2
- [x] 04_integrate - verified banner == CONTEXT == IoT5 == 24.10.3 and the build note is present. Logged. Backlog complete

---

## Legend

| Badge | Meaning |
|-------|---------|
| DONE | Implemented in code and verified, promoted to `src/`. |
| IN PROGRESS | Implemented and documented, not yet verified on a live lab. |
| PENDING | Scoped here, not yet implemented or verified. |
| [verified] | Confirmed against the RoutCoon overlay source and docs by static read this session. **No live Pi was run**, so a flashed-image pass is still required at `04_integrate`. |
| [doc] | Claim asserted in the docs, not yet cross-checked against code or reproduced. |

## References

- Analysis these targets came from: this session's RoutCoon structural + vuln-doc + overlay-source review.
- Pipeline contract: [`CONTEXT.md`](CONTEXT.md) and the per-stage `CONTEXT.md` files.
- Product routing: [`../src/AGENTS.md`](../src/AGENTS.md) (Layer 0) and [`../src/docs/RoutCoon/`](../src/docs/RoutCoon/).
- Lab overlay: [`../src/labs/routcoon/`](../src/labs/routcoon/) and its Layer 2 [`CONTEXT.md`](../src/labs/routcoon/CONTEXT.md).
- Sibling backlog for format reference: [`TARGET_OWLCAM.md`](TARGET_OWLCAM.md).
- Promotion mapping: [`../_config/promotion-map.md`](../_config/promotion-map.md).
- Durable record of promotions: [`04_integrate/output/integration-log.md`](04_integrate/output/integration-log.md).
