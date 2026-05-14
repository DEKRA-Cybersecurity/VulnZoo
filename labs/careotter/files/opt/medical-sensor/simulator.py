# /opt/medical-sensor/simulator.py
import math, time, random, json

class MAX30102Simulator:
    def __init__(self, bpm=72, spo2=98, noise=0.02):
        self.bpm        = bpm
        self.spo2       = spo2
        self.noise      = noise
        self.start_time = time.time()
        self.registers  = {
            0xFF: 0x15,  # Part ID
            0xFE: 0x03,  # Revision ID
            0x09: 0x0F,  # FIFO config
            0x0A: 0x03,  # Mode: SpO2
        }

    def _ppg_sample(self):
        t    = time.time() - self.start_time
        freq = self.bpm / 60.0
        red  = 80000 + 20000 * math.sin(2 * math.pi * freq * t)
        red += 5000  * math.sin(4 * math.pi * freq * t)
        red += random.gauss(0, 80000 * self.noise)
        ir   = red * (0.96 + 0.04 * (self.spo2 / 100.0))
        return int(max(0, min(0xFFFFFF, red))), \
               int(max(0, min(0xFFFFFF, ir)))

    def read_byte_data(self, addr, reg):
        if addr != 0x57:
            raise OSError(f"No device at 0x{addr:02X}")
        return self.registers.get(reg, 0x00)

    def read_i2c_block_data(self, addr, reg, length):
        samples = []
        for _ in range(length // 6):
            red, ir = self._ppg_sample()
            samples += [(red>>16)&0xFF, (red>>8)&0xFF, red&0xFF,
                        (ir >>16)&0xFF, (ir >>8)&0xFF, ir &0xFF]
            time.sleep(0.01)
        return samples[:length]

    def write_byte_data(self, addr, reg, value):
        self.registers[reg] = value


def get_bus(real=False, bus_number=1, **kwargs):
    """
    Single entry point.
    real=False  → simulator (no hardware)
    real=True   → real smbus2 (physical chip)
    """
    if real:
        import smbus2
        return smbus2.SMBus(bus_number)
    return MAX30102Simulator(**kwargs)