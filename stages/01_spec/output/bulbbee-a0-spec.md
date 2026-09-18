# BULB-A0 - Physical base: SPI + WS2812 driver + local CLI (spec)

Target: `BULB-A0` (Phase 0, functional bring-up, no intentional weakness).
Pipeline: `01_spec` (this) -> `02_implement` -> `03_document` -> `04_integrate` -> `05_verify`.

## Why it matters

Every plane in the BulbBee blueprint (BLE, cloud tunnel, LAN/TCP) drives the same ring. The physical base is the honest groundwork they all sit on: a stable WS2812 signal and a bare local way to set a colour, with no network and no plane involved. If the base is not solid, every plane inherits the fault (as the core_freq clock-drift bug showed).

## Design

Reuse the working groundwork, add one net-new piece:

- **Reuse (already verified in `src/`):** `ws2812.py` (three-SPI-bit WS2812 encoder over `/dev/spidev0.0`, with the in-memory sim fallback), and `99-bulbbee-spi.sh` (enables SPI via `dtparam=spi=on` and pins the SPI clock with `core_freq=250` + `core_freq_min=250`, without which the baud drifts on CPU idle and the ring freezes). `lighting_service.py` remains the single owner of the ring, so the CLI must not open `/dev/spidev0.0` itself (a second writer corrupts the frame).
- **Net-new: `bulbctl`**, a local CLI colour command. It is a thin client of the on-device control surface (`127.0.0.1:8082`, owned by `lighting_service`), so it drives the ring without touching SPI directly. Sub-commands: `color R G B`, `bright N`, `scene NAME`, `on`, `off`, `state`. POSIX `sh` + `curl`, no new package.
- **`led_count` is a fitted-ring knob.** The blueprint product is a 12-LED ring; the current test hardware is a 16-LED ring and works at 16. `led_count` in `config.json` is set to match the physically fitted ring, so it stays 16 for the current lab hardware and is set to 12 when a 12-LED ring is fitted. This spec does not hardcode 12 (that would leave four LEDs dark on the 16-ring).

## Affected components (concrete `src/` paths)

- Reuse, unchanged: `src/labs/bulbbee/files/opt/bulbbee/ws2812.py`, `src/labs/bulbbee/files/usr/lib/vulnzoo-hooks/profile-init.d/99-bulbbee-spi.sh`.
- New: `src/labs/bulbbee/files/usr/bin/bulbctl` (0755).
- Config knob, confirm value: `src/labs/bulbbee/files/opt/bulbbee/config.json` (`led_count`, `use_real_hardware`, `spi_hz`, `color_order`).
- Repackage: `src/labs/vulnzoo/files/usr/lib/vulnzoo-devices/bulbbee.tar.gz`.

## Acceptance criteria

1. SPI is enabled and the clock is pinned: after the `99` hook + reboot, `/dev/spidev0.0` exists and `/boot/config.txt` carries `dtparam=spi=on` + `core_freq=250` + `core_freq_min=250`.
2. `bulbctl color 0 255 0` sets the ring to solid green: `bulbctl state` then reports `color=[0,255,0]`, `scene=solid`, `simulated=false` on hardware.
3. `bulbctl bright 40`, `bulbctl scene rainbow`, `bulbctl off`, `bulbctl on` each change the reported state accordingly.
4. `bulbctl` never opens `/dev/spidev0.0` itself (no ring contention with `lighting_service`).
5. With no ring / SPI off, the service degrades to `simulated=true` and `bulbctl` still returns state cleanly (no crash).
6. `bulbctl` with no/unknown sub-command prints usage and exits non-zero.
