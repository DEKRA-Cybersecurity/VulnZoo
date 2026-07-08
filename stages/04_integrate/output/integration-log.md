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
