#!/usr/bin/env python3
"""
CareOtter BLE GATT Server using BlueZ DBUS API
Compatible with OpenWRT + Raspberry Pi
Fixes: Bleak is client-only, so we use subprocess + bluetoothctl
"""
import asyncio
import json
import logging
from typing import Dict, Optional
import subprocess
import os

logger = logging.getLogger(__name__)

# Standard Bluetooth SIG UUIDs
HEART_RATE_SERVICE = "0000180d-0000-1000-8000-00805f9b34fb"
HR_MEASUREMENT_CHAR = "00002a37-0000-1000-8000-00805f9b34fb"

# Proprietary UUIDs (custom CareOtter characteristics)
ALERT_STATUS_CHAR = "c0a10000-0000-1000-8000-00805f9b34fb"
DEVICE_CONTROL_CHAR = "c0de0000-0000-1000-8000-00805f9b34fb"


class CareOtterBLEServer:
    """BLE GATT Server for CareOtter Cardiac Monitor using BlueZ"""
    
    def __init__(self, sensor, alert_engine, config: Dict):
        self.sensor = sensor
        self.alert_engine = alert_engine
        self.config = config
        self.connected_clients = set()
        self.device_name = "CareOtter_HR"
        
        # Security from config
        self.require_pairing = config.get('ble', {}).get('pairing_mode') != 'just_works'
        self.require_encryption = config.get('ble', {}).get('encryption_required', True)
        self.require_bonding = config.get('ble', {}).get('bonding') != 'none'
        
    async def start(self) -> None:
        """Start BLE server using BlueZ backend"""
        logger.info("[*] Starting CareOtter BLE Server (BlueZ)...")
        
        # Enable BLE advertising
        await self._setup_ble()
        
        # Main monitoring loop
        await self._monitoring_loop()
    
    async def _setup_ble(self) -> None:
        """Configure BLE device via bluetoothctl"""
        try:
            # Enable BLE adapter
            result = subprocess.run(
                ["bluetoothctl", "power", "on"],
                check=False,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("[+] Bluetooth adapter powered on")
            else:
                logger.warning(f"[!] bluetoothctl power: {result.stderr}")
            
            # Set device name (requires btmgmt or advertising params)
            # For now, use default BLE advertising
            logger.info(f"[*] BLE device name: {self.device_name}")
            
            # Enable pairing mode if required
            if self.require_pairing:
                subprocess.run(
                    ["bluetoothctl", "pairable", "on"],
                    check=False,
                    capture_output=True
                )
                logger.info("[+] Pairing mode: ENABLED (Passkey required)")
            
            logger.info("[+] BLE configured. Setup complete.")
            
        except FileNotFoundError:
            logger.error("[-] bluetoothctl not found. Install bluez package.")
        except Exception as e:
            logger.error(f"[-] BLE setup failed: {e}")
    
    async def _monitoring_loop(self) -> None:
        """Main loop: read sensor → detect alerts → log data"""
        logger.info("[*] Starting cardiac monitoring loop...")
        
        while True:
            try:
                # Get cardiac reading
                reading = self.sensor.get_reading()
                
                # Process for alerts
                alerts = self.alert_engine.process_reading(reading)
                
                # Log current status
                logger.debug(f"HR: {reading['heart_rate']} BPM, SpO2: {reading['spo2']}%")
                
                # BLE notification payload (HR standard: [Flags, HR8])
                hr_value = reading['heart_rate']
                hr_data = bytes([0x00, min(255, hr_value)])  # Clamp to byte range
                
                # Alert notification
                if alerts:
                    alert_payload = {
                        'alerts': [a['type'] for a in alerts],
                        'severity': max(
                            [a['severity'] for a in alerts],
                            key=lambda x: ['info', 'warning', 'critical'].index(x)
                        )
                    }
                    alert_data = json.dumps(alert_payload).encode()
                    logger.warning(f"[!] ALERT: {alert_payload}")
                    # In production: notify connected BLE clients via dbus
                
                await asyncio.sleep(1)  # Real-time monitoring (1s intervals)
                
            except Exception as e:
                logger.error(f"[-] Monitoring loop error: {e}")
                await asyncio.sleep(2)
    
    async def handle_control_command(self, command_data: bytes) -> bytes:
        """
        Handle device control commands
        SECURE MODE: Validates authentication
        VULNERABLE MODE (Phase 2): Disabled auth, command injection possible
        """
        try:
            command = json.loads(command_data.decode())
            logger.info(f"[*] Control command: {command}")
            
            # SECURE MODE: Validate authentication
            if self.config.get('ble', {}).get('pairing_mode') == 'secure_passkey':
                # Require auth token
                if not self._validate_command_auth(command):
                    logger.warning("[!] Command rejected: authentication failed")
                    return b'{"error":"authentication_failed"}'
            else:
                # Vulnerable mode: no auth
                logger.warning("[?] WARNING: Commands not authenticated!")
            
            action = command.get('action', '').strip()
            
            if action == 'reset':
                logger.info("[*] Device reset command")
                return b'{"status":"resetting"}'
            elif action == 'silence_alarm':
                logger.info("[*] Silencing alarm")
                return b'{"status":"alarm_silenced"}'
            elif action == 'request_sync':
                logger.info("[*] Sync request from client")
                return b'{"status":"sync_scheduled"}'
            else:
                logger.warning(f"[!] Unknown action: {action}")
                return b'{"error":"unknown_action"}'
                
        except json.JSONDecodeError as e:
            logger.error(f"[-] Invalid JSON: {e}")
            return b'{"error":"invalid_json"}'
        except Exception as e:
            logger.error(f"[-] Command handling error: {e}")
            return b'{"error":"internal_error"}'
    
    def _validate_command_auth(self, command: Dict) -> bool:
        """
        Validate command authentication via HMAC
        Phase 1 (Secure): Validates token
        Phase 2 (Vulnerable): Will be bypassed
        """
        auth_token = command.get('auth_token', '')
        if not auth_token:
            return False
        
        # TODO: Implement HMAC-SHA256 validation against command + device_secret
        # For now, accept any token (enough for baseline)
        return True


# Legacy class name for compatibility
CareOtterServer = CareOtterBLEServer


if __name__ == "__main__":
    # Test instantiation
    logging.basicConfig(level=logging.INFO)
    
    from core.sensor_mock import MockMAX30102
    from core.cardiac_monitor import CardiacAlertEngine
    from core.data_store import DataStore
    
    # Dummy config
    config = {
        'ble': {
            'pairing_mode': 'secure_passkey',
            'encryption_required': True,
            'bonding': 'secure'
        }
    }
    
    store = DataStore()
    sensor = MockMAX30102(scenario='normal_sinus')
    engine = CardiacAlertEngine(store)
    
    server = CareOtterBLEServer(sensor, engine, config)
    asyncio.run(server.start())