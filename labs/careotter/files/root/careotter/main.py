#!/usr/bin/env python3
"""
CareOtter Main Entry Point
Orchestrates: Sensor → CardiacMonitor → BLE Server → Cloud Sync
"""
import asyncio
import logging
import sys
import signal
import yaml
import json
from pathlib import Path

# Local imports
from core.sensor_mock import MockMAX30102
from core.cardiac_monitor import CardiacAlertEngine
from core.data_store import DataStore
from api.ble_gatt_server import CareOtterBLEServer
from api.cloud_sync import CloudSync

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/root/careotter/data/careotter.log')
    ]
)
logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = Path(__file__).parent
CONFIG_DIR = BASE_DIR / 'config'
DATA_DIR = BASE_DIR / 'data'

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)


class CareOtterApplication:
    """Main application coordinator"""
    
    def __init__(self):
        self.config = self._load_config()
        self.running = True
        self.components = {}
        
    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        config_file = CONFIG_DIR / 'security_policy.yaml'
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"[+] Configuration loaded from {config_file}")
            return config
        except FileNotFoundError:
            logger.error(f"[-] Config file not found: {config_file}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"[-] YAML parse error: {e}")
            sys.exit(1)
    
    def _load_thresholds(self) -> dict:
        """Load medical thresholds from JSON"""
        thresholds_file = CONFIG_DIR / 'thresholds.json'
        
        try:
            with open(thresholds_file, 'r') as f:
                thresholds = json.load(f)
            logger.info(f"[+] Thresholds loaded from {thresholds_file}")
            return thresholds
        except FileNotFoundError:
            logger.warning(f"[!] Thresholds file not found: {thresholds_file}")
            return {}
    
    async def initialize(self) -> bool:
        """Initialize all components"""
        try:
            logger.info("[*] Initializing CareOtter Application...")
            
            # Data storage
            self.data_store = DataStore()
            logger.info("[+] DataStore initialized")
            
            # Sensor (mock or real)
            scenario = self.config.get('sensor', {}).get('scenario', 'normal_sinus')
            self.sensor = MockMAX30102(scenario=scenario)
            logger.info(f"[+] Sensor initialized (scenario: {scenario})")
            
            # Cardiac alert engine
            thresholds = self._load_thresholds()
            self.alert_engine = CardiacAlertEngine(self.data_store, thresholds=thresholds)
            logger.info("[+] Alert engine initialized")
            
            # BLE server
            self.ble_server = CareOtterBLEServer(self.sensor, self.alert_engine, self.config)
            logger.info("[+] BLE server initialized")
            
            # Cloud sync (if enabled)
            if self.config.get('cloud_api', {}).get('enabled', False):
                device_id = self.config.get('device', {}).get('id', 'careotter-001')
                self.cloud_sync = CloudSync(self.config, device_id)
                logger.info("[+] Cloud sync initialized")
            else:
                self.cloud_sync = None
                logger.info("[*] Cloud sync disabled")
            
            logger.info("[+] All components initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"[-] Initialization failed: {e}", exc_info=True)
            return False
    
    async def run(self) -> None:
        """Main application loop"""
        if not await self.initialize():
            sys.exit(1)
        
        logger.info("[*] Starting CareOtter Monitoring System...")
        
        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_event_loop()
        for signal_type in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(
                signal_type,
                lambda: asyncio.create_task(self.shutdown())
            )
        
        try:
            # Create concurrent tasks
            tasks = [
                self.ble_server.start(),  # BLE advertising + notifications
                self._sync_worker(),      # Periodic cloud sync
            ]
            
            await asyncio.gather(*tasks)
            
        except Exception as e:
            logger.error(f"[-] Runtime error: {e}", exc_info=True)
        finally:
            await self.shutdown()
    
    async def _sync_worker(self) -> None:
        """Periodically sync data to cloud"""
        if not self.cloud_sync:
            logger.info("[*] Cloud sync worker disabled")
            return
        
        sync_interval = self.config.get('cloud_api', {}).get('sync_interval_seconds', 300)
        
        logger.info(f"[*] Cloud sync worker started (interval: {sync_interval}s)")
        
        while self.running:
            try:
                await asyncio.sleep(sync_interval)
                
                # Get unsynced readings
                readings = self.data_store.get_recent_readings(limit=100)
                if readings:
                    logger.info(f"[*] Syncing {len(readings)} readings to cloud...")
                    if await self.cloud_sync.sync_readings(readings):
                        # Mark as synced
                        for reading in readings:
                            self.data_store.mark_synced(reading['id'], 'success')
                        logger.info("[+] Cloud sync completed")
                    else:
                        logger.warning("[!] Cloud sync failed")
                
                # Get unacked alerts
                alerts = self.data_store.get_unacked_alerts()
                if alerts:
                    logger.info(f"[*] Syncing {len(alerts)} alerts to cloud...")
                    if await self.cloud_sync.sync_alerts(alerts):
                        logger.info("[+] Alert sync completed")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[-] Sync worker error: {e}")
    
    async def shutdown(self) -> None:
        """Graceful shutdown"""
        logger.info("[*] Shutting down CareOtter...")
        self.running = False
        
        # Close database
        if hasattr(self, 'data_store'):
            try:
                logger.info("[*] Closing data store...")
                # DataStore should have __del__ that closes connection
            except Exception as e:
                logger.error(f"[-] Error closing data store: {e}")
        
        logger.info("[+] Shutdown complete")


def main():
    """Entry point"""
    app = CareOtterApplication()
    asyncio.run(app.run())


if __name__ == '__main__':
    main()
