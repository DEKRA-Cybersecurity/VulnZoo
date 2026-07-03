"""
modbus_service.py — Modbus/TCP master to the Raspberry Pi gateway

The Pi exposes holding registers that map to servo setpoints, command codes,
and real-time angle feedback from the Arduino firmware.

The Pi now requires the actuator password to be written (XOR-encrypted) to
registers 40021-40036 before any command register write. If authentication
fails, the untested error path leaks the cleartext password into registers
40038-40053 instead of returning a generic error.
"""

from pymodbus.client import ModbusTcpClient
from config import Config

# Shared actuator password; sent encrypted over Modbus. [IoT:I1]
HARD_CODED_PASSWORD = 'OctoSuperBot2026'
AUTH_KEY = 0x55   # fixed XOR "encryption" key
PWD_LEN = len(HARD_CODED_PASSWORD)
PWD_OFFSET = 20   # 40021
HINT_OFFSET = 37  # 40038


class ModbusAuthError(Exception):
    """Raised when the Pi rejects a Modbus command due to bad/missing password."""

    def __init__(self, leaked_password: str):
        self.hint = leaked_password
        super().__init__(f'Actuator auth failed; leaked password: {leaked_password}')


def _encrypt_password():
    return [ord(c) ^ AUTH_KEY for c in HARD_CODED_PASSWORD]


class ModbusService:
    """Single shared Modbus/TCP client for talking to the Pi."""

    def __init__(self, host: str = None, port: int = None):
        self.host = host or Config.MODBUS_HOST
        self.port = port or Config.MODBUS_PORT
        self._client = ModbusTcpClient(self.host, port=self.port)

    def _send_password(self):
        """Write the XOR-encrypted password to the Pi auth register block."""
        resp = self._client.write_registers(PWD_OFFSET, _encrypt_password())
        if resp.isError():
            raise ModbusAuthError('unknown')

    def _read_hint(self) -> str:
        """Read the cleartext password the Pi leaks into registers on auth failure."""
        rr = self._client.read_holding_registers(HINT_OFFSET, count=PWD_LEN)
        if rr.isError():
            return 'unknown'
        return ''.join(chr(r) for r in rr.registers)

    def write_register(self, addr: int, value: int):
        """Write a single holding register, including the encrypted password first."""
        self._client.connect()
        try:
            self._send_password()
            resp = self._client.write_register(addr, int(value))
            if resp.isError():
                hint = self._read_hint()
                raise ModbusAuthError(hint)
        finally:
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
