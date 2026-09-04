"""WS2812 ring driver: SPI on real hardware, in-memory frame buffer in simulation.

Stdlib only. Each WS2812 data bit is encoded as three SPI bits at ~2.4 MHz
(1 -> 0b110, 0 -> 0b100), so one color byte becomes three SPI bytes and one
LED (24 bits, GRB) becomes nine SPI bytes. No python3-spidev, no rpi_ws281x
(that needs /dev/mem DMA). If the spidev node is missing or use_real_hardware
is false, the driver falls back to simulation and never raises.
"""

import os
import struct
import fcntl

# _IOW('k', 4, __u32) == SPI_IOC_WR_MAX_SPEED_HZ
_SPI_IOC_WR_MAX_SPEED_HZ = 0x40046B04

# byte -> three SPI bytes, MSB first, 1->110 0->100
_LUT = []
for _b in range(256):
    _v = 0
    for _i in range(8):
        _bit = (_b >> (7 - _i)) & 1
        _v = (_v << 3) | (0b110 if _bit else 0b100)
    _LUT.append(_v.to_bytes(3, "big"))


def _gamma_table(gamma):
    # ponytail: recompute per instance, 256 entries is nothing
    return [int((i / 255.0) ** gamma * 255.0 + 0.5) for i in range(256)]


class WS2812:
    def __init__(self, config, logger):
        self.log = logger
        self.led_count = int(config.get("led_count", 16))
        self.brightness = int(config.get("brightness", 128))
        self.gamma = float(config.get("gamma", 2.2))
        self.spi_hz = int(config.get("spi_hz", 2_400_000))
        self.color_order = str(config.get("color_order", "GRB")).upper()
        self.spi_device = config.get("spi_device", "/dev/spidev0.0")
        self._gamma = _gamma_table(self.gamma)
        # last frame pushed, as a flat list of (r,g,b), for /state and simulation
        self.frame = [(0, 0, 0)] * self.led_count

        self.fd = None
        want_hw = config.get("use_real_hardware", False)
        if want_hw and os.path.exists(self.spi_device):
            try:
                self.fd = os.open(self.spi_device, os.O_RDWR)
                fcntl.ioctl(self.fd, _SPI_IOC_WR_MAX_SPEED_HZ,
                            struct.pack("I", self.spi_hz))
                self.log("ws2812: driving %d LEDs over %s @ %d Hz"
                         % (self.led_count, self.spi_device, self.spi_hz))
            except OSError as e:
                self.log("ws2812: SPI open failed (%s), using simulation" % e)
                self.fd = None
        if self.fd is None:
            reason = "use_real_hardware=false" if not want_hw else \
                     "%s absent" % self.spi_device
            self.log("ws2812: simulation mode (%s)" % reason)

    @property
    def simulated(self):
        return self.fd is None

    def _order(self, r, g, b):
        m = {"R": r, "G": g, "B": b}
        return bytes(m[c] for c in self.color_order)

    def show(self, pixels):
        """pixels: list of (r,g,b) 0-255. Length is clamped/padded to led_count."""
        px = list(pixels)[: self.led_count]
        px += [(0, 0, 0)] * (self.led_count - len(px))
        self.frame = px

        scale = self.brightness / 255.0
        buf = bytearray()
        for (r, g, b) in px:
            r = self._gamma[int(r * scale)]
            g = self._gamma[int(g * scale)]
            b = self._gamma[int(b * scale)]
            for byte in self._order(r, g, b):
                buf += _LUT[byte]
        # latch: >50us idle low
        buf += b"\x00" * 8

        if self.fd is None:
            return  # simulation: frame kept in self.frame
        try:
            os.write(self.fd, bytes(buf))
        except OSError as e:
            self.log("ws2812: SPI write failed (%s), dropping to simulation" % e)
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def clear(self):
        self.show([(0, 0, 0)] * self.led_count)

    def close(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def _demo():
    # ponytail: one runnable check for the bit-encoding math, no framework
    assert _LUT[0x00] == bytes([0b100100_10, 0b0100_1001, 0b00_100100])  # 0x92 0x49 0x24
    assert _LUT[0xFF] == bytes([0b110110_11, 0b0110_1101, 0b10_110110])  # 0xDB 0x6D 0xB6
    # every input byte expands to exactly 3 SPI bytes
    assert all(len(v) == 3 for v in _LUT)

    logs = []
    dev = WS2812({"use_real_hardware": False, "led_count": 4}, logs.append)
    assert dev.simulated
    dev.show([(255, 0, 0), (0, 255, 0)])
    assert dev.frame[0] == (255, 0, 0) and dev.frame[2] == (0, 0, 0)
    assert len(dev.frame) == 4
    dev.clear()
    assert dev.frame[0] == (0, 0, 0)
    print("ws2812 self-check OK (LUT + simulation)")


if __name__ == "__main__":
    _demo()
