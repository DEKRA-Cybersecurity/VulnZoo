"""
database_service.py — SQLite persistence service for CareOtter

Stores vital readings, device events, and configuration persistently
in an embedded SQLite database.
"""

import sqlite3
import os
import logging
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseService:
    """
    SQLite database service for storing CareOtter device data.
    """

    def __init__(self, db_path: str = None):
        """
        Initializes the database service.
        
        Args:
            db_path: Path to the SQLite file. If None, uses the
                    DB_PATH environment variable or default '/app/data/careotter.db'
        """
        self.db_path = db_path or os.getenv('DB_PATH', '/app/data/careotter.db')
        
        # Ensure the directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"[DB] Created database directory: {db_dir}")
            except Exception as e:
                logger.error(f"[DB] Failed to create directory {db_dir}: {e}")
                # Fallback to a temporary directory if we cannot create the directory
                self.db_path = '/tmp/careotter.db'
                logger.warning(f"[DB] Falling back to: {self.db_path}")
        
        logger.info(f"[DB] Using database: {self.db_path}")

        try:
            self._init_db()
            self._migrate_db()
            logger.info("[DB] Database initialized successfully")
        except Exception as e:
            logger.error(f"[DB] Failed to initialize database: {e}")
            raise

    def _init_db(self):
        """Initializes the database schema if it does not exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_users_username
                    ON users(username);

                -- Each physical device (identified by BLE MAC) is owned by one patient user.
                -- VULNERABILITY: MAC is stored and returned in plaintext — info disclosure.
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT UNIQUE NOT NULL,
                    patient_username TEXT NOT NULL,
                    device_name TEXT,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patient_username) REFERENCES users(username)
                );

                CREATE INDEX IF NOT EXISTS idx_devices_mac
                    ON devices(mac);

                CREATE INDEX IF NOT EXISTS idx_devices_patient
                    ON devices(patient_username);

                CREATE TABLE IF NOT EXISTS vitals_readings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_mac TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    bpm INTEGER,
                    spo2 INTEGER,
                    ir_raw INTEGER,
                    red_raw INTEGER,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_mac) REFERENCES devices(mac)
                );

                CREATE INDEX IF NOT EXISTS idx_vitals_timestamp
                    ON vitals_readings(timestamp);

                CREATE TABLE IF NOT EXISTS device_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                    ON device_events(timestamp);

                CREATE TABLE IF NOT EXISTS device_config (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Edge-triggered clinical alerts emitted by sensor_service.py
                -- (one row per healthy↔fired transition; steady-state firing
                -- produces zero rows).
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_mac TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    type TEXT NOT NULL,         -- bpm_low | bpm_high | spo2_low
                    state TEXT NOT NULL,        -- fired | cleared
                    severity TEXT NOT NULL,     -- info | warning | critical
                    value INTEGER,
                    threshold INTEGER,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(device_mac, timestamp, type, state),
                    FOREIGN KEY (device_mac) REFERENCES devices(mac)
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                    ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_mac_timestamp
                    ON alerts(device_mac, timestamp);
            ''')
            conn.commit()

    def _migrate_db(self):
        """Apply incremental schema migrations to existing databases."""
        with sqlite3.connect(self.db_path) as conn:
            existing = {row[1] for row in
                        conn.execute('PRAGMA table_info(vitals_readings)').fetchall()}

            # Migration: add device_mac column if missing
            if 'device_mac' not in existing:
                logger.info("[DB] Migration: adding device_mac to vitals_readings")
                default_mac = 'AA:BB:CC:DD:EE:FF'
                # SQLite requires a literal constant default (no ? placeholder) for ALTER TABLE
                conn.execute(
                    f"ALTER TABLE vitals_readings "
                    f"ADD COLUMN device_mac TEXT NOT NULL DEFAULT '{default_mac}'"
                )
                conn.commit()
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_vitals_mac "
                    "ON vitals_readings(device_mac)")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_vitals_mac_timestamp "
                    "ON vitals_readings(device_mac, timestamp)")
                conn.commit()
                n = conn.execute('SELECT COUNT(*) FROM vitals_readings').fetchone()[0]
                logger.info(f"[DB] Migration: backfilled {n} rows with mac={default_mac}")

    # ── User management ───────────────────────────────────────────────────────
    
    def _hash_password(self, password: str) -> str:
        """Simple SHA-256 hash for lab purposes (not production-safe)."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def create_user(self, username: str, password: str, role: str = 'user') -> bool:
        """
        Creates a new user.
        
        Args:
            username: Unique username
            password: Plaintext password (stored as a SHA-256 hash)
            role: User role (admin, user, doctor, etc.)
            
        Returns:
            True if created successfully, False if it already exists or failed
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                ''', (username, self._hash_password(password), role))
                conn.commit()
                logger.info(f"[DB] User created: {username} (role={role})")
                return True
        except sqlite3.IntegrityError:
            logger.warning(f"[DB] User already exists: {username}")
            return False
        except Exception as e:
            logger.error(f"[DB] Error creating user: {e}")
            return False

    def create_or_update_user(self, username: str, password: str, role: str = 'user') -> bool:
        """Create user or update password if already exists. Used by device registration."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        password_hash = excluded.password_hash,
                        role = excluded.role
                ''', (username, self._hash_password(password), role))
                conn.commit()
                logger.info(f"[DB] User upserted: {username} (role={role})")
                return True
        except Exception as e:
            logger.error(f"[DB] Error upserting user: {e}")
            return False
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """
        Gets a user by username.
        
        Args:
            username: Username
            
        Returns:
            Dictionary with user data or None if not found
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    'SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?',
                    (username,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] Error fetching user: {e}")
            return None
    
    def verify_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Verifies a user's credentials.
        
        Args:
            username: Username
            password: Plaintext password
            
        Returns:
            Dictionary with user data (without password_hash) if valid,
            None if the credentials are incorrect
        """
        user = self.get_user_by_username(username)
        if not user:
            return None
        if user['password_hash'] == self._hash_password(password):
            return {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'created_at': user['created_at']
            }
        return None
    
    # ── Device management ─────────────────────────────────────────────────────

    def register_device(self, mac: str, patient_username: str,
                        device_name: str = None) -> bool:
        """Register a device MAC and associate it with a patient user."""
        mac = mac.upper()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO devices (mac, patient_username, device_name)
                    VALUES (?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        patient_username = excluded.patient_username,
                        device_name      = excluded.device_name
                ''', (mac, patient_username, device_name))
                conn.commit()
                logger.info(f"[DB] Device registered: {mac} → {patient_username}")
                return True
        except Exception as e:
            logger.error(f"[DB] Error registering device: {e}")
            return False

    def get_device(self, mac: str) -> Optional[Dict]:
        """Return device info including the owning patient username."""
        mac = mac.upper()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT * FROM devices WHERE mac = ?', (mac,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] Error fetching device: {e}")
            return None

    def get_device_by_patient(self, username: str) -> Optional[Dict]:
        """Return the device assigned to a given patient username."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT * FROM devices WHERE patient_username = ?', (username,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] Error fetching device by patient: {e}")
            return None

    def get_devices_for_patient(self, username: str) -> List[Dict]:
        """Return devices for a patient (their own) or all devices for admin."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                user = self.get_user_by_username(username)
                if user and user.get('role') == 'admin':
                    rows = conn.execute(
                        'SELECT * FROM devices ORDER BY registered_at DESC'
                    ).fetchall()
                else:
                    rows = conn.execute(
                        'SELECT * FROM devices WHERE patient_username = ? ORDER BY registered_at DESC',
                        (username,)
                    ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] Error fetching devices for {username}: {e}")
            return []

    def list_devices(self) -> List[Dict]:
        """Return all registered devices with their patient owner."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    'SELECT * FROM devices ORDER BY registered_at DESC'
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] Error listing devices: {e}")
            return []

    # ── Signature-based device registration (WiFi-first provisioning) ────────

    EXPECTED_DEVICE_SIGNATURE = "CareOtterFactorySig2026"

    def register_device_with_signature(
        self, mac: str, signature: str,
        patient_username: str, patient_password: str,
        admin_username: str, admin_password: str,
        device_ip: str, device_name: str = "CareOtter_HR"
    ) -> bool:
        """Register a device using its factory signature.

        The bedside monitor sends this payload after being provisioned via BLE.
        VULNERABILITY: the signature is hardcoded and identical across all devices,
        so any attacker who captures it can register a rogue device.
        """
        if signature != self.EXPECTED_DEVICE_SIGNATURE:
            logger.warning(f"[DB] Device registration rejected: invalid signature from {mac}")
            return False
        try:
            # Create patient and admin users (idempotent — overwrite passwords)
            self.create_or_update_user(patient_username, patient_password, 'patient')
            self.create_or_update_user(admin_username, admin_password, 'admin')

            # Register / update device association
            self.register_device(mac, patient_username, device_name)

            # Store the device's WiFi IP for vitals polling
            self._set_config('device_ip', device_ip)
            self._set_config('device_mac', mac.upper())

            logger.info(f"[DB] Device registered via signature: {mac} → patient={patient_username} admin={admin_username} ip={device_ip}")
            return True
        except Exception as e:
            logger.error(f"[DB] Error in signature-based registration: {e}")
            return False

    def _set_config(self, key: str, value: str) -> bool:
        """Store a key-value setting in device_config."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO device_config (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = CURRENT_TIMESTAMP
                ''', (key, value))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[DB] Error setting config {key}: {e}")
            return False

    def get_device_ip(self) -> str:
        """Return the dynamically-registered device WiFi IP, or empty string."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    'SELECT value FROM device_config WHERE key = ?', ('device_ip',)
                ).fetchone()
                return row[0] if row else ''
        except Exception as e:
            logger.error(f"[DB] Error fetching device_ip: {e}")
            return ''

    def user_count(self) -> int:
        """Return total number of registered users."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute('SELECT COUNT(*) FROM users').fetchone()
                return row[0] if row else 0
        except Exception as e:
            logger.error(f"[DB] Error counting users: {e}")
            return 0
    
    def list_users(self) -> List[Dict]:
        """
        Lists all users (without password_hash).
        
        Returns:
            List of dictionaries with user data
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    'SELECT id, username, role, created_at FROM users ORDER BY id'
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"[DB] Error listing users: {e}")
            return []
    
    def update_user_role(self, username: str, new_role: str) -> bool:
        """
        Updates a user's role.
        
        Args:
            username: Username
            new_role: New role
            
        Returns:
            True if updated successfully
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'UPDATE users SET role = ? WHERE username = ?',
                    (new_role, username)
                )
                conn.commit()
                if cursor.rowcount > 0:
                    logger.info(f"[DB] Updated role for {username} to {new_role}")
                    return True
                return False
        except Exception as e:
            logger.error(f"[DB] Error updating user role: {e}")
            return False
    
    def delete_user(self, username: str) -> bool:
        """
        Deletes a user.
        
        Args:
            username: Username to delete
            
        Returns:
            True if deleted successfully
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'DELETE FROM users WHERE username = ?',
                    (username,)
                )
                conn.commit()
                if cursor.rowcount > 0:
                    logger.info(f"[DB] Deleted user: {username}")
                    return True
                return False
        except Exception as e:
            logger.error(f"[DB] Error deleting user: {e}")
            return False

    def store_vitals(self, data: dict, device_mac: str = None) -> bool:
        """Stores a vital reading associated with the device MAC.

        If device_mac is not provided, it tries to read data['device_mac'].
        If the MAC is not registered, the reading is rejected.
        """
        mac = (device_mac or data.get('device_mac', '')).upper()
        if not mac:
            logger.warning("[DB] store_vitals called without device_mac — rejected")
            return False
        # Auto-register with default patient if MAC unknown (lab convenience)
        if not self.get_device(mac):
            logger.warning(f"[DB] Unknown MAC {mac} — auto-registering with patient")
            self.register_device(mac, "patient", "CareOtter_HR")
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO vitals_readings
                    (device_mac, timestamp, bpm, spo2, ir_raw, red_raw, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    mac,
                    data.get('timestamp'),
                    data.get('bpm'),
                    data.get('spo2'),
                    data.get('ir_raw'),
                    data.get('red_raw'),
                    data.get('source', 'unknown')
                ))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[DB] Error storing vitals: {e}")
            return False

    def get_vitals_history(self, hours: int = 24, limit: int = 1000,
                           device_mac: str = None) -> List[Dict]:
        """Vital history with device info and owning patient."""
        since = (datetime.now() - timedelta(hours=hours)).timestamp()
        mac = device_mac.upper() if device_mac else None
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if mac:
                    rows = conn.execute('''
                        SELECT v.id, v.device_mac, v.timestamp, v.bpm, v.spo2,
                               v.ir_raw, v.red_raw, v.source, v.created_at,
                               d.patient_username, d.device_name
                        FROM vitals_readings v
                        LEFT JOIN devices d ON v.device_mac = d.mac
                        WHERE v.timestamp >= ? AND v.device_mac = ?
                        ORDER BY v.timestamp DESC
                        LIMIT ?
                    ''', (since, mac, limit)).fetchall()
                else:
                    rows = conn.execute('''
                        SELECT v.id, v.device_mac, v.timestamp, v.bpm, v.spo2,
                               v.ir_raw, v.red_raw, v.source, v.created_at,
                               d.patient_username, d.device_name
                        FROM vitals_readings v
                        LEFT JOIN devices d ON v.device_mac = d.mac
                        WHERE v.timestamp >= ?
                        ORDER BY v.timestamp DESC
                        LIMIT ?
                    ''', (since, limit)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] Error fetching history: {e}")
            return []

    def get_vitals_stats(self, hours: int = 24, device_mac: str = None) -> Dict:
        """Aggregated statistics, optionally filtered by device MAC.

        Vitals aggregates (avg/min/max/total) come from `vitals_readings`.
        Alert counts come from the `alerts` table — only rows with state='fired'
        are counted, so a single sustained alert episode contributes 1 (not one
        per cycle as the previous inline COUNT(CASE …) over vitals did).
        """
        since = (datetime.now() - timedelta(hours=hours)).timestamp()
        mac = device_mac.upper() if device_mac else None
        try:
            with sqlite3.connect(self.db_path) as conn:
                if mac:
                    cursor = conn.execute('''
                        SELECT
                            AVG(bpm), MIN(bpm), MAX(bpm),
                            AVG(spo2), MIN(spo2), MAX(spo2),
                            COUNT(*)
                        FROM vitals_readings
                        WHERE timestamp >= ? AND device_mac = ?
                    ''', (since, mac))
                else:
                    cursor = conn.execute('''
                        SELECT
                            AVG(bpm), MIN(bpm), MAX(bpm),
                            AVG(spo2), MIN(spo2), MAX(spo2),
                            COUNT(*)
                        FROM vitals_readings
                        WHERE timestamp >= ?
                    ''', (since,))

                row = cursor.fetchone()

                if mac:
                    alerts_row = conn.execute('''
                        SELECT
                            COUNT(CASE WHEN type IN ('bpm_low','bpm_high') THEN 1 END),
                            COUNT(CASE WHEN type = 'spo2_low' THEN 1 END),
                            COUNT(CASE WHEN severity = 'critical' THEN 1 END)
                        FROM alerts
                        WHERE timestamp >= ? AND device_mac = ? AND state = 'fired'
                    ''', (since, mac)).fetchone()
                else:
                    alerts_row = conn.execute('''
                        SELECT
                            COUNT(CASE WHEN type IN ('bpm_low','bpm_high') THEN 1 END),
                            COUNT(CASE WHEN type = 'spo2_low' THEN 1 END),
                            COUNT(CASE WHEN severity = 'critical' THEN 1 END)
                        FROM alerts
                        WHERE timestamp >= ? AND state = 'fired'
                    ''', (since,)).fetchone()

                return {
                    'bpm': {
                        'avg': round(row[0], 1) if row[0] else None,
                        'min': row[1],
                        'max': row[2]
                    },
                    'spo2': {
                        'avg': round(row[3], 1) if row[3] else None,
                        'min': row[4],
                        'max': row[5]
                    },
                    'total_readings': row[6] or 0,
                    'alerts': {
                        'bpm':      alerts_row[0] or 0,
                        'spo2':     alerts_row[1] or 0,
                        'critical': alerts_row[2] or 0
                    },
                    'period_hours': hours
                }
        except Exception as e:
            logger.error(f"[DB] Error fetching stats: {e}")
            return {
                'bpm': {'avg': None, 'min': None, 'max': None},
                'spo2': {'avg': None, 'min': None, 'max': None},
                'total_readings': 0,
                'alerts': {'bpm': 0, 'spo2': 0},
                'period_hours': hours
            }

    def get_vitals_count(self, hours: int = 24) -> int:
        """
        Gets the total number of readings over a period.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Number of readings
        """
        since = (datetime.now() - timedelta(hours=hours)).timestamp()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM vitals_readings 
                    WHERE timestamp >= ?
                ''', (since,))
                
                return cursor.fetchone()[0] or 0
        except Exception as e:
            logger.error(f"[DB] Error counting readings: {e}")
            return 0

    def get_db_info(self) -> Dict:
        """
        Gets database information for debugging.
        
        Returns:
            Dictionary with database info
        """
        try:
            # Check whether the file exists
            file_exists = os.path.exists(self.db_path)
            file_size = os.path.getsize(self.db_path) if file_exists else 0
            
            with sqlite3.connect(self.db_path) as conn:
                # Count total records
                cursor = conn.execute('SELECT COUNT(*) FROM vitals_readings')
                total_records = cursor.fetchone()[0]
                
                # Get date range
                cursor = conn.execute('''
                    SELECT MIN(timestamp), MAX(timestamp) FROM vitals_readings
                ''')
                min_ts, max_ts = cursor.fetchone()
                
                return {
                    'db_path': self.db_path,
                    'file_exists': file_exists,
                    'file_size_bytes': file_size,
                    'total_records': total_records,
                    'oldest_record': datetime.fromtimestamp(min_ts).isoformat() if min_ts else None,
                    'newest_record': datetime.fromtimestamp(max_ts).isoformat() if max_ts else None
                }
        except Exception as e:
            logger.error(f"[DB] Error getting DB info: {e}")
            return {
                'db_path': self.db_path,
                'file_exists': os.path.exists(self.db_path),
                'error': str(e)
            }

    def log_event(self, event_type: str, details: str = None, 
                  ip_address: str = None) -> bool:
        """
        Records a device event.
        
        Args:
            event_type: Event type (auth_success, auth_fail, etc.)
            details: Additional event details
            ip_address: Client IP address
            
        Returns:
            True if recorded successfully
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO device_events (event_type, details, ip_address)
                    VALUES (?, ?, ?)
                ''', (event_type, details, ip_address))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[DB] Error logging event: {e}")
            return False

    # ── Clinical alerts ─────────────────────────────────────────────────────

    def store_alert(self, event: dict, device_mac: str) -> bool:
        """Persist one alert event from the sensor.

        Idempotent via the UNIQUE(device_mac, timestamp, type, state) constraint —
        the cloud poller may re-fetch the same event if the watermark resets, but
        only one row will land in the table.
        """
        mac = (device_mac or '').upper()
        if not mac:
            logger.warning("[DB] store_alert called without device_mac — rejected")
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR IGNORE INTO alerts
                        (device_mac, timestamp, type, state, severity, value, threshold, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    mac,
                    float(event.get('timestamp', 0)),
                    str(event.get('type', '')),
                    str(event.get('state', 'fired')),
                    str(event.get('severity', 'warning')),
                    int(event.get('value', 0))     if event.get('value')     is not None else None,
                    int(event.get('threshold', 0)) if event.get('threshold') is not None else None,
                    str(event.get('source', 'unknown'))
                ))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[DB] Error storing alert: {e}")
            return False

    def get_alerts_history(self, hours: int = 24, limit: int = 500,
                           device_mac: str = None) -> List[Dict]:
        """Return alert events newest-first with the owning patient joined."""
        since = (datetime.now() - timedelta(hours=hours)).timestamp()
        mac = device_mac.upper() if device_mac else None
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if mac:
                    rows = conn.execute('''
                        SELECT a.id, a.device_mac, a.timestamp, a.type, a.state,
                               a.severity, a.value, a.threshold, a.source, a.created_at,
                               d.patient_username, d.device_name
                        FROM alerts a
                        LEFT JOIN devices d ON a.device_mac = d.mac
                        WHERE a.timestamp >= ? AND a.device_mac = ?
                        ORDER BY a.timestamp DESC
                        LIMIT ?
                    ''', (since, mac, limit)).fetchall()
                else:
                    rows = conn.execute('''
                        SELECT a.id, a.device_mac, a.timestamp, a.type, a.state,
                               a.severity, a.value, a.threshold, a.source, a.created_at,
                               d.patient_username, d.device_name
                        FROM alerts a
                        LEFT JOIN devices d ON a.device_mac = d.mac
                        WHERE a.timestamp >= ?
                        ORDER BY a.timestamp DESC
                        LIMIT ?
                    ''', (since, limit)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] Error fetching alerts history: {e}")
            return []

    def get_latest_alert_timestamp(self, device_mac: str = None) -> float:
        """Watermark used by the cloud collector to request only newer events."""
        mac = device_mac.upper() if device_mac else None
        try:
            with sqlite3.connect(self.db_path) as conn:
                if mac:
                    row = conn.execute(
                        'SELECT MAX(timestamp) FROM alerts WHERE device_mac = ?', (mac,)
                    ).fetchone()
                else:
                    row = conn.execute('SELECT MAX(timestamp) FROM alerts').fetchone()
                return float(row[0]) if row and row[0] else 0.0
        except Exception as e:
            logger.error(f"[DB] Error fetching latest alert timestamp: {e}")
            return 0.0

    def cleanup_old_data(self, days: int = 30) -> int:
        """
        Deletes old data to keep the database size under control.
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of deleted records
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Delete old readings
                cursor = conn.execute('''
                    DELETE FROM vitals_readings WHERE timestamp < ?
                ''', (cutoff.timestamp(),))
                vitals_deleted = cursor.rowcount
                
                # Delete old events
                cursor = conn.execute('''
                    DELETE FROM device_events WHERE timestamp < ?
                ''', (cutoff,))
                events_deleted = cursor.rowcount
                
                conn.commit()
                return vitals_deleted + events_deleted
        except Exception as e:
            logger.error(f"[DB] Error cleaning up old data: {e}")
            return 0
