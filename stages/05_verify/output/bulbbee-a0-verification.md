# BULB-A0 - Verification

Target: `BULB-A0` (physical base + local CLI). Verified live on the Pi (`root@192.168.2.1`), hardware mode.

## Acceptance criteria vs result

| # | Criterion | Result |
|---|-----------|--------|
| 1 | SPI enabled + clock pinned | `/dev/spidev0.0` present; `/boot/config.txt` has `dtparam=spi=on` + `core_freq=250` + `core_freq_min=250` (the pin that fixed the ~15-20s freeze). PASS |
| 2 | `bulbctl color 0 255 0` -> solid green | `/state`: `color=[0,255,0]`, `scene=solid`, `simulated=false`. PASS |
| 3 | `bright`/`scene`/`on`/`off` change state | `bright 40` -> brightness 40; `scene rainbow` -> rainbow; `off` -> off. PASS |
| 4 | CLI never opens `/dev/spidev0.0` | `bulbctl` is a `curl` client of `:8082`; `lighting_service` stays the single ring writer. PASS |
| 5 | Sim fallback with no ring / SPI off | `ws2812.py` degrades to `simulated=true` and never raises (verified earlier this session). PASS |
| 6 | Bad/no sub-command -> usage, non-zero exit | `bulbctl` and `bulbctl frobnicate` both print usage and exit 1. PASS |

## Notes

Physical ring: after the `core_freq` pin the ring drives stably (user-confirmed "passed all tests" this session), so `simulated=false` frames reach the LEDs. Software bring-up and the CLI are fully certified on the Pi.

Badge -> DONE.
