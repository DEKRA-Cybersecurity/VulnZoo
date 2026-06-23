"""
modbus_service.py — Modbus/TCP master to the Raspberry Pi gateway

The Pi exposes holding registers that map to servo setpoints, command codes,
and real-time angle feedback from the Arduino firmware.
"""

from pymodbus.client import ModbusTcpClient
from config import Config


class ModbusService:
    """Single shared Modbus/TCP client for talking to the Pi."""

    def __init__(self, host: str = None, port: int = None):
        self.host = host or Config.MODBUS_HOST
        self.port = port or Config.MODBUS_PORT
        self._client = ModbusTcpClient(self.host, port=self.port)

    def write_register(self, addr: int, value: int):
        """Write a single holding register."""
        self._client.connect()
        self._client.write_register(addr, int(value))
        self._client.close()

    def read_state(self) -> dict:
        """Read the full state block (14 registers) from the Pi."""
        self._client.connect()
        rr = self._client.read_holding_registers(0, count=14)
        self._client.close()
        regs = getattr(rr, 'registers', [0] * 14)
        return {
            'base': regs[0],
            'left': regs[1],
            'right': regs[2],
            'claw': regs[3],
            'command': regs[4],
            'speed': regs[5],
            'status': regs[6],
            'feedback': regs[10:14],
        }
