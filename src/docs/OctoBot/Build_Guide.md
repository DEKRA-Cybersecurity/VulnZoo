# OctoBot Build Guide

This guide has been merged into [`OPENWRT_INTEGRATION.md`](./OPENWRT_INTEGRATION.md) to avoid duplication. That file is the single OctoBot build plan and MWP stages roadmap.

What moved there:

- The architecture decision (Arduino stays the real-time controller, the Pi is the network gateway on top, never inserted into the PWM path) - Section 1.
- The physical wiring, including the external-servo-power warning and the GPIO-UART alternative - Section 2.
- The flat, unsegmented industrial LAN model - Section 3.
- The deliberately vulnerable gateway and its per-item config toggle - Section 5.
- The OWASP IoT Top 10 -> implementation mapping (originally tagged `[I1]..[I10]`, now `IoT:I1..I10` with CWEs) - Section 7.
- The phased roadmap, recast as the MWP stages plan - Section 8.
- The lab isolation checklist - Section 11.

The original draft also proposed an `M <servo> <angle>` / `C` / `R` / `L` serial protocol referencing firmware symbols (`pos[]`, `moverServo`) that do not exist in the shipped Youfang v1.71 sketch. The integration doc standardizes on the firmware-accurate `Sx:angle` protocol instead.
