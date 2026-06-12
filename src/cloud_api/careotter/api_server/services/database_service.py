"""
database_service.py — SQLite persistence service for CareOtter

Stores vital readings, device events, and configuration persistently
in an embedded SQLite database.
"""

import sqlite3
import os
import time
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
                    display_name TEXT,
                    profile_photo TEXT,            -- base64 data URI
                    email TEXT,                    -- contact PII (caregiver)
                    phone TEXT,                    -- contact PII (caregiver)
                    address TEXT,                  -- contact PII (caregiver)
                    active_appointments INTEGER NOT NULL DEFAULT 0,  -- denormalized live booking counter (API6)
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
                    auth_hash TEXT,
                    device_ip TEXT,
                    igp_port INTEGER DEFAULT 9999,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (patient_username) REFERENCES users(username)
                );

                CREATE INDEX IF NOT EXISTS idx_devices_mac
                    ON devices(mac);

                CREATE INDEX IF NOT EXISTS idx_devices_patient
                    ON devices(patient_username);

                -- Tiered storage (medical-grade pattern):
                --   vitals_readings   = hot tier, raw 10s samples, retention 24h
                --   vitals_minute_agg = warm tier, 1min averages, retention 30d
                --   vitals_hour_agg   = cold tier, 1h averages, retention indefinite
                -- ir_raw / red_raw are NOT stored in the cloud: they are local
                -- waveform ADC values that the bedside monitor uses for BPM
                -- derivation and are never queried by any cloud consumer.
                CREATE TABLE IF NOT EXISTS vitals_readings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_mac TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    bpm INTEGER,
                    spo2 INTEGER,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_mac) REFERENCES devices(mac)
                );

                CREATE INDEX IF NOT EXISTS idx_vitals_timestamp
                    ON vitals_readings(timestamp);

                CREATE TABLE IF NOT EXISTS vitals_minute_agg (
                    device_mac TEXT NOT NULL,
                    bucket_ts  REAL NOT NULL,        -- minute floor, seconds since epoch
                    bpm_avg    REAL,
                    bpm_min    INTEGER,
                    bpm_max    INTEGER,
                    spo2_avg   REAL,
                    spo2_min   INTEGER,
                    spo2_max   INTEGER,
                    samples    INTEGER NOT NULL,
                    PRIMARY KEY (device_mac, bucket_ts),
                    FOREIGN KEY (device_mac) REFERENCES devices(mac)
                );

                CREATE INDEX IF NOT EXISTS idx_min_agg_ts
                    ON vitals_minute_agg(bucket_ts);

                CREATE TABLE IF NOT EXISTS vitals_hour_agg (
                    device_mac TEXT NOT NULL,
                    bucket_ts  REAL NOT NULL,        -- hour floor, seconds since epoch
                    bpm_avg    REAL,
                    bpm_min    INTEGER,
                    bpm_max    INTEGER,
                    spo2_avg   REAL,
                    spo2_min   INTEGER,
                    spo2_max   INTEGER,
                    samples    INTEGER NOT NULL,
                    PRIMARY KEY (device_mac, bucket_ts),
                    FOREIGN KEY (device_mac) REFERENCES devices(mac)
                );

                CREATE INDEX IF NOT EXISTS idx_hour_agg_ts
                    ON vitals_hour_agg(bucket_ts);

                CREATE TABLE IF NOT EXISTS device_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                    ON device_events(timestamp);

                CREATE TABLE IF NOT EXISTS caregiver_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    caregiver_username TEXT NOT NULL,
                    patient_username TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(caregiver_username, patient_username),
                    FOREIGN KEY (caregiver_username) REFERENCES users(username),
                    FOREIGN KEY (patient_username) REFERENCES users(username)
                );

                CREATE INDEX IF NOT EXISTS idx_cg_assign_caregiver
                    ON caregiver_assignments(caregiver_username);

                CREATE INDEX IF NOT EXISTS idx_cg_assign_patient
                    ON caregiver_assignments(patient_username);

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

                -- API9:2023 (Improper Inventory Management): password-reset OTP.
                -- One active 6-digit code per user. `attempts` backs the SECURE
                -- mechanism's per-account lockout (api.careotter.lab, gated by the
                -- trusted X-OTP-Guard header). The forgotten beta vhost
                -- (beta.api.careotter.lab) has neither the edge limit nor the cap,
                -- so the code is brute-forceable by pivoting to it. Secure mode 404s
                -- beta. See docs/.../API9_Improper_Inventory_Management.md
                CREATE TABLE IF NOT EXISTS password_reset_otp (
                    username   TEXT PRIMARY KEY,
                    otp_code   TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    used       INTEGER NOT NULL DEFAULT 0,
                    attempts   INTEGER NOT NULL DEFAULT 0   -- API9 secure mechanism: per-account attempt cap
                );
            ''')
            conn.commit()

    def _migrate_db(self):
        """Apply incremental schema migrations to existing databases."""
        with sqlite3.connect(self.db_path) as conn:
            existing_vitals = {row[1] for row in
                        conn.execute('PRAGMA table_info(vitals_readings)').fetchall()}

            # Migration: add device_mac column if missing
            if 'device_mac' not in existing_vitals:
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

            # Migration: add auth_hash to devices if missing
            existing_devices = {row[1] for row in
                        conn.execute('PRAGMA table_info(devices)').fetchall()}
            if 'auth_hash' not in existing_devices:
                logger.info("[DB] Migration: adding auth_hash to devices")
                conn.execute("ALTER TABLE devices ADD COLUMN auth_hash TEXT")
                conn.commit()
                logger.info("[DB] Migration: auth_hash column added")

            # Migration: add device_ip and igp_port to devices if missing
            if 'device_ip' not in existing_devices:
                logger.info("[DB] Migration: adding device_ip to devices")
                conn.execute("ALTER TABLE devices ADD COLUMN device_ip TEXT")
                conn.commit()
                logger.info("[DB] Migration: device_ip column added")
            if 'igp_port' not in existing_devices:
                logger.info("[DB] Migration: adding igp_port to devices")
                conn.execute("ALTER TABLE devices ADD COLUMN igp_port INTEGER DEFAULT 9999")
                conn.commit()
                logger.info("[DB] Migration: igp_port column added")

            # Migration: add profile_photo + display_name to users if missing
            existing_users = {row[1] for row in
                        conn.execute('PRAGMA table_info(users)').fetchall()}
            if 'profile_photo' not in existing_users:
                logger.info("[DB] Migration: adding profile_photo to users")
                # Stored as a base64 data URI (data:image/png;base64,…) so the
                # lab doesn't need a writable upload directory inside the container.
                conn.execute("ALTER TABLE users ADD COLUMN profile_photo TEXT")
                conn.commit()
            if 'display_name' not in existing_users:
                logger.info("[DB] Migration: adding display_name to users")
                conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
                conn.commit()

            # Migration: add caregiver contact PII columns if missing.
            # These private fields are over-exposed to patients by
            # get_caregivers_for_patient() — see API3:2023 BOPLA in that method.
            for _pii_col in ('email', 'phone', 'address'):
                if _pii_col not in existing_users:
                    logger.info(f"[DB] Migration: adding {_pii_col} to users")
                    conn.execute(f"ALTER TABLE users ADD COLUMN {_pii_col} TEXT")
                    conn.commit()

            # Migration: denormalized appointment counter on users (API6 booking feature).
            # The per-patient cap is checked against THIS column, not a live COUNT over
            # appointment_slots — book_slot/cancel_slot keep it in sync.
            if 'active_appointments' not in existing_users:
                logger.info("[DB] Migration: adding active_appointments to users")
                conn.execute(
                    "ALTER TABLE users ADD COLUMN active_appointments INTEGER NOT NULL DEFAULT 0")
                conn.commit()
                # Backfill from current bookings if the appointments table already exists
                # (on a DB that predates appointments there is nothing to count yet).
                appt_exists = conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='appointment_slots'").fetchone()
                if appt_exists:
                    conn.execute(
                        "UPDATE users SET active_appointments = ("
                        "  SELECT COUNT(*) FROM appointment_slots "
                        "  WHERE booked_by = users.username AND status = 'booked')")
                    conn.commit()
                    logger.info("[DB] Migration: backfilled active_appointments from bookings")

            # Migration: add attempts to password_reset_otp (API9 secure mechanism =
            # per-account attempt cap). The table is created by _init_db; older DBs
            # (persisted volume) have it without this column.
            otp_cols = {row[1] for row in
                        conn.execute('PRAGMA table_info(password_reset_otp)').fetchall()}
            if otp_cols and 'attempts' not in otp_cols:
                logger.info("[DB] Migration: adding attempts to password_reset_otp")
                conn.execute(
                    "ALTER TABLE password_reset_otp ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
                conn.commit()

            # Migration: create caregiver_assignments if missing
            existing_tables = {row[0] for row in
                        conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if 'caregiver_assignments' not in existing_tables:
                logger.info("[DB] Migration: creating caregiver_assignments table")
                conn.executescript('''
                    CREATE TABLE caregiver_assignments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        caregiver_username TEXT NOT NULL,
                        patient_username TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(caregiver_username, patient_username),
                        FOREIGN KEY (caregiver_username) REFERENCES users(username),
                        FOREIGN KEY (patient_username) REFERENCES users(username)
                    );
                    CREATE INDEX idx_cg_assign_caregiver ON caregiver_assignments(caregiver_username);
                    CREATE INDEX idx_cg_assign_patient ON caregiver_assignments(patient_username);
                ''')
                conn.commit()
                logger.info("[DB] Migration: caregiver_assignments table created")

            # Migration: Health Store tables (API6:2023 — sensitive business flows feature)
            if 'products' not in existing_tables:
                logger.info("[DB] Migration: creating Health Store tables (wallets/products/orders)")
                conn.executescript('''
                    CREATE TABLE IF NOT EXISTS wallets (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        username    TEXT UNIQUE NOT NULL,
                        balance     REAL NOT NULL DEFAULT 0,
                        salary      REAL NOT NULL DEFAULT 0,
                        last_payout TIMESTAMP,
                        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (username) REFERENCES users(username)
                    );
                    CREATE TABLE IF NOT EXISTS products (
                        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                        sku                   TEXT UNIQUE NOT NULL,
                        name                  TEXT NOT NULL,
                        description           TEXT,
                        price                 REAL NOT NULL,
                        category              TEXT,
                        stock                 INTEGER NOT NULL DEFAULT 0,
                        requires_prescription INTEGER NOT NULL DEFAULT 1,
                        active                INTEGER NOT NULL DEFAULT 1,
                        created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS orders (
                        id         INTEGER PRIMARY KEY AUTOINCREMENT,
                        username   TEXT NOT NULL,
                        product_id INTEGER NOT NULL,
                        quantity   INTEGER NOT NULL,
                        unit_price REAL NOT NULL,
                        total      REAL NOT NULL,
                        status     TEXT DEFAULT 'completed',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (username)   REFERENCES users(username),
                        FOREIGN KEY (product_id) REFERENCES products(id)
                    );
                    CREATE INDEX IF NOT EXISTS idx_orders_username ON orders(username);
                ''')
                conn.commit()
                # Seed the fictional health catalog (idempotent by sku). Stock is
                # deliberately small — scarcity is what the Phase-2 API6 abuse exhausts.
                catalog = [
                    ('ICD-X1',
                     'Implantable Cardioverter-Defibrillator — OtterGuard X1',
                     'Subcutaneous ICD for cardiac arrhythmia management. Lab-fictional device.',
                     24500.00, 'cardiac', 5, 1),
                    ('PUMP-IP200',
                     'Insulin Pump — OtterFlow IP-200',
                     'Wearable insulin delivery pump with basal/bolus control. Lab-fictional device.',
                     6800.00, 'diabetes', 8, 1),
                    ('PACE-D3',
                     'Dual-Chamber Pacemaker — OtterPace D3',
                     'Dual-chamber implantable cardiac pacemaker. Lab-fictional device.',
                     18900.00, 'cardiac', 4, 1),
                ]
                conn.executemany(
                    'INSERT OR IGNORE INTO products '
                    '(sku, name, description, price, category, stock, requires_prescription) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?)', catalog)
                conn.commit()
                logger.info("[DB] Migration: Health Store catalog seeded (3 products)")

            # Migration: teleconsultation appointment slots (API6 booking feature)
            if 'appointment_slots' not in existing_tables:
                logger.info("[DB] Migration: creating appointment_slots table")
                conn.executescript('''
                    CREATE TABLE IF NOT EXISTS appointment_slots (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        clinician   TEXT NOT NULL,
                        specialty   TEXT NOT NULL,
                        slot_time   TEXT NOT NULL,
                        status      TEXT NOT NULL DEFAULT 'open',   -- 'open' | 'booked' | 'cancelled'
                        booked_by   TEXT,
                        booked_at   TIMESTAMP,
                        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_slots_status ON appointment_slots(status);
                    CREATE INDEX IF NOT EXISTS idx_slots_booked_by ON appointment_slots(booked_by);
                ''')
                conn.commit()
                logger.info("[DB] Migration: appointment_slots table created")

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

    def set_user_pii(self, username: str, display_name: str = None,
                     email: str = None, phone: str = None, address: str = None,
                     profile_photo: str = None) -> bool:
        """Set personal/contact info on a user. Used to seed caregiver PII for the
        lab so the API3 BOPLA leak exposes real personal data. Only non-None
        fields are updated. Column names are a fixed allow-list (no user input)."""
        fields = {'display_name': display_name, 'email': email, 'phone': phone,
                  'address': address, 'profile_photo': profile_photo}
        updates = {k: v for k, v in fields.items() if v is not None}
        if not updates:
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                set_clause = ', '.join(f"{k} = ?" for k in updates)
                conn.execute(
                    f"UPDATE users SET {set_clause} WHERE username = ?",
                    (*updates.values(), username))
                conn.commit()
                logger.info(f"[DB] PII set for user {username}: {', '.join(updates)}")
                return True
        except Exception as e:
            logger.error(f"[DB] Error setting user PII: {e}")
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

    # Device registration codes are 12 lowercase/uppercase hex characters.
    # ``HASH_PREFIX`` is retained as a defensive normalization layer: if any
    # legacy client still sends the older "CareOtter<hex>" form,
    # ``canonical_hash`` strips it so the row matches. New code paths,
    # device labels and seeded values never emit the prefix.
    HASH_PREFIX = "CareOtter"

    @classmethod
    def canonical_hash(cls, raw: str) -> str:
        """Return the storage form: prefix stripped, lowercased, trimmed.
        Idempotent — safe to call on values already in canonical form."""
        if not raw:
            return ""
        h = raw.strip()
        if h.startswith(cls.HASH_PREFIX):
            h = h[len(cls.HASH_PREFIX):]
        return h

    @classmethod
    def display_hash(cls, stored: str) -> str:
        """Prepend the prefix back for UI / device-label rendering."""
        if not stored:
            return ""
        return stored if stored.startswith(cls.HASH_PREFIX) else cls.HASH_PREFIX + stored

    def register_device(self, mac: str, patient_username: str,
                        device_name: str = None, auth_hash: str = None,
                        device_ip: str = None, igp_port: int = None) -> bool:
        """Register a device MAC and associate it with a patient user.
        ``auth_hash`` is normalized via :meth:`canonical_hash` before insert."""
        mac = mac.upper()
        stored_hash = self.canonical_hash(auth_hash) if auth_hash else None
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO devices (mac, patient_username, device_name, auth_hash, device_ip, igp_port)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                        patient_username = excluded.patient_username,
                        device_name      = excluded.device_name,
                        auth_hash        = COALESCE(excluded.auth_hash, auth_hash),
                        device_ip        = COALESCE(excluded.device_ip, device_ip),
                        igp_port         = COALESCE(excluded.igp_port, igp_port)
                ''', (mac, patient_username, device_name, stored_hash, device_ip, igp_port))
                conn.commit()
                logger.info(f"[DB] Device registered: {mac} → {patient_username} ip={device_ip}:{igp_port}")
                return True
        except Exception as e:
            logger.error(f"[DB] Error registering device: {e}")
            return False

    def delete_device_for_patient(self, patient_username: str) -> bool:
        """Unregister (not delete) the patient's device: keep the row but clear its
        owner. ``patient_username`` is ``NOT NULL`` in the schema, so the unowned
        marker is the empty string ``''`` — the same convention the seeded/unclaimed
        Pi device uses — not ``NULL`` (which would raise a NOT NULL IntegrityError)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    "UPDATE devices SET patient_username = '' WHERE patient_username = ?",
                    (patient_username,)
                )
                conn.commit()
                if cur.rowcount > 0:
                    logger.info(f"[DB] Unregistered device for patient: {patient_username}")
                    return True
                return False
        except Exception as e:
            logger.error(f"[DB] Error unregistering device for patient: {e}")
            return False

    def delete_other_devices_for_patient(self, patient_username: str,
                                         keep_mac: str) -> int:
        """Enforce single-device-per-patient: delete every device row owned by
        ``patient_username`` whose MAC differs from ``keep_mac``. Returns the
        number of rows deleted.

        Used by the cloud simulator bootstrap to clean up legacy demo rows from
        earlier seeds (where alice_g67 and genuinebob49 had a placeholder
        "demo-*" device alongside the real cloud-sim one).
        """
        keep_mac = keep_mac.upper()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    '''DELETE FROM devices
                       WHERE patient_username = ? AND UPPER(mac) != ?''',
                    (patient_username, keep_mac),
                )
                deleted = cur.rowcount
                conn.commit()
                if deleted:
                    logger.info(
                        f"[DB] Pruned {deleted} stray device row(s) for "
                        f"{patient_username} (kept {keep_mac})"
                    )
                return deleted
        except Exception as e:
            logger.error(f"[DB] delete_other_devices_for_patient failed: {e}")
            return 0

    def adopt_mac_for_signature(self, signature: str, new_mac: str) -> bool:
        """Replace a placeholder MAC with the real one for the device that
        owns ``signature`` (compared after :meth:`canonical_hash`)."""
        new_mac = new_mac.upper()
        sig = self.canonical_hash(signature)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    '''UPDATE devices
                       SET mac = ?
                       WHERE auth_hash = ?
                         AND mac IN ('00:00:00:00:00:00', '', '0')''',
                    (new_mac, sig),
                )
                conn.commit()
                if cur.rowcount > 0:
                    logger.info(f"[DB] Adopted MAC {new_mac} for signature …{sig[-6:]}")
                    return True
                return False
        except Exception as e:
            logger.error(f"[DB] adopt_mac_for_signature failed: {e}")
            return False

    def update_device_hash(self, mac: str, auth_hash: str) -> bool:
        """Update the auth_hash for a device (canonicalised before write)."""
        mac = mac.upper()
        stored = self.canonical_hash(auth_hash)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE devices SET auth_hash = ? WHERE mac = ?',
                    (stored, mac)
                )
                conn.commit()
                logger.info(f"[DB] Updated auth_hash for {mac}")
                return True
        except Exception as e:
            logger.error(f"[DB] Error updating device hash: {e}")
            return False

    def get_device_by_hash(self, auth_hash: str) -> Optional[Dict]:
        """Return the device whose auth_hash matches (compared after
        :meth:`canonical_hash`)."""
        stored = self.canonical_hash(auth_hash)
        if not stored:
            return None
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT * FROM devices WHERE auth_hash = ?', (stored,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] Error fetching device by hash: {e}")
            return None

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

    def get_device_by_mac(self, mac: str) -> Optional[Dict]:
        """Alias for get_device."""
        return self.get_device(mac)

    def get_latest_vitals(self, device_mac: str = None) -> Optional[Dict]:
        """Return the most recent vital reading for a device (or globally)."""
        mac = device_mac.upper() if device_mac else None
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if mac:
                    row = conn.execute('''
                        SELECT * FROM vitals_readings
                        WHERE device_mac = ?
                        ORDER BY timestamp DESC
                        LIMIT 1
                    ''', (mac,)).fetchone()
                else:
                    row = conn.execute('''
                        SELECT * FROM vitals_readings
                        ORDER BY timestamp DESC
                        LIMIT 1
                    ''').fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] Error fetching latest vitals: {e}")
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

    def update_device_ip(self, mac: str, device_ip: str, igp_port: int = 9999) -> bool:
        """Update the IP and IGP port for a device identified by MAC."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE devices SET device_ip = ?, igp_port = ? WHERE mac = ?',
                    (device_ip, igp_port, mac.upper())
                )
                conn.commit()
                logger.info(f"[DB] Updated device IP: {mac} → {device_ip}:{igp_port}")
                return True
        except Exception as e:
            logger.error(f"[DB] Error updating device IP for {mac}: {e}")
            return False

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

    def list_devices_with_ip(self) -> List[Dict]:
        """Return devices that have a non-null device_ip (reachable over network)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM devices WHERE device_ip IS NOT NULL AND device_ip != '' ORDER BY registered_at DESC"
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] Error listing devices with IP: {e}")
            return []

    # ── Signature-based device registration (WiFi-first provisioning) ────────

    EXPECTED_DEVICE_SIGNATURE = "9C0C306DEF2A"

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
        # Compare in canonical form: codes are 12 hex chars; the legacy
        # "CareOtter<hex>" form is still accepted via canonical_hash.
        import hmac as _hmac
        if not _hmac.compare_digest(
            self.canonical_hash(signature),
            self.canonical_hash(self.EXPECTED_DEVICE_SIGNATURE),
        ):
            logger.warning(f"[DB] Device registration rejected: invalid signature from {mac}")
            return False
        try:
            # Create patient and admin users (idempotent — overwrite passwords)
            self.create_or_update_user(patient_username, patient_password, 'patient')
            self.create_or_update_user(admin_username, admin_password, 'admin')

            # Register / update device association with WiFi IP
            self.register_device(mac, patient_username, device_name,
                                 auth_hash=signature, device_ip=device_ip, igp_port=9999)

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

    # ── Caregiver assignments ───────────────────────────────────────────────────

    def add_caregiver_assignment(self, patient_username: str, caregiver_username: str) -> bool:
        """Link a caregiver to a patient. The patient initiates this."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO caregiver_assignments (caregiver_username, patient_username)
                    VALUES (?, ?)
                    ON CONFLICT(caregiver_username, patient_username) DO NOTHING
                ''', (caregiver_username, patient_username))
                conn.commit()
                logger.info(f"[DB] Caregiver assignment: {caregiver_username} → {patient_username}")
                return True
        except Exception as e:
            logger.error(f"[DB] Error adding caregiver assignment: {e}")
            return False

    def remove_caregiver_assignment(self, patient_username: str, caregiver_username: str) -> bool:
        """Remove a caregiver→patient link."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    DELETE FROM caregiver_assignments
                    WHERE caregiver_username = ? AND patient_username = ?
                ''', (caregiver_username, patient_username))
                conn.commit()
                if cursor.rowcount > 0:
                    logger.info(f"[DB] Removed caregiver assignment: {caregiver_username} → {patient_username}")
                    return True
                return False
        except Exception as e:
            logger.error(f"[DB] Error removing caregiver assignment: {e}")
            return False

    def get_caregivers_for_patient(self, patient_username: str) -> List[Dict]:
        """Return all caregivers assigned to a patient. Object scope is correct:
        only the caller's own assignments (WHERE ca.patient_username = ?).

        VULNERABILITY (API3:2023 BOPLA — Broken Object Property Level Authorization):
        the projection over-exposes the caregiver object's *properties*. Beyond the
        assignment fields, it leaks the caregiver's private PII (display_name, email,
        phone, address, profile_photo) and internal fields (caregiver_id,
        password_hash). Object-level authorization is intact, but a patient must not
        be able to read these caregiver properties. The /api/patient/caregivers route
        strips them back to a safe whitelist only when VULNERABLE != 1.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute('''
                    SELECT ca.id, ca.caregiver_username, ca.patient_username, ca.created_at,
                           u.role,
                           u.id            AS caregiver_id,
                           u.display_name,
                           u.email,
                           u.phone,
                           u.address,
                           u.profile_photo,
                           u.password_hash
                    FROM caregiver_assignments ca
                    JOIN users u ON ca.caregiver_username = u.username
                    WHERE ca.patient_username = ?
                    ORDER BY ca.created_at DESC
                ''', (patient_username,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] Error fetching caregivers for patient: {e}")
            return []

    def get_patients_for_caregiver(self, caregiver_username: str) -> List[Dict]:
        """Return all patients assigned to a caregiver, with device info."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute('''
                    SELECT ca.id, ca.caregiver_username, ca.patient_username, ca.created_at,
                           d.mac AS device_mac, d.device_name
                    FROM caregiver_assignments ca
                    LEFT JOIN devices d ON ca.patient_username = d.patient_username
                    WHERE ca.caregiver_username = ?
                    ORDER BY ca.created_at DESC
                ''', (caregiver_username,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] Error fetching patients for caregiver: {e}")
            return []

    # ── Self-service profile management ───────────────────────────────────────

    def get_user_profile(self, username: str) -> Optional[Dict]:
        """Return public profile fields for a user (never the password hash)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    '''SELECT username, role, display_name, profile_photo, created_at
                       FROM users WHERE username = ?''',
                    (username,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] Error fetching profile: {e}")
            return None

    def update_password(self, username: str, new_password: str) -> bool:
        """Set a new password hash for the given user."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    'UPDATE users SET password_hash = ? WHERE username = ?',
                    (self._hash_password(new_password), username)
                )
                conn.commit()
                if cur.rowcount > 0:
                    logger.info(f"[DB] Password updated for {username}")
                    return True
                return False
        except Exception as e:
            logger.error(f"[DB] Error updating password: {e}")
            return False

    # ── API9:2023 password-reset OTP store ───────────────────────────────────
    # One active 6-digit code per user. Stored server-side and never returned to
    # the client — the legitimate user reads it out-of-band (in this lab: the
    # container log, written by app.py). `attempts` backs the SECURE mechanism's
    # per-account lockout (api.careotter.lab); the precarious beta host never reads
    # or increments it, so a lock on the secure side does not protect beta (API9).
    def create_otp(self, username: str, code: str, expires_at: float) -> bool:
        """Store (replacing any prior) the active reset OTP for a user."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'INSERT OR REPLACE INTO password_reset_otp '
                    '(username, otp_code, created_at, expires_at, used) '
                    'VALUES (?, ?, ?, ?, 0)',
                    (username, code, time.time(), expires_at)
                )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[DB] Error creating reset OTP: {e}")
            return False

    def get_active_otp(self, username: str) -> Optional[Dict]:
        """Return the stored OTP row for a user (or None). Expiry/used are NOT
        filtered here — the caller (app.py) checks them, so verification stays a
        single, explicit code path."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    'SELECT username, otp_code, created_at, expires_at, used, attempts '
                    'FROM password_reset_otp WHERE username = ?',
                    (username,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] Error fetching reset OTP: {e}")
            return None

    def mark_otp_used(self, username: str) -> bool:
        """Consume the active OTP after a successful reset."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE password_reset_otp SET used = 1 WHERE username = ?',
                    (username,)
                )
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[DB] Error marking reset OTP used: {e}")
            return False

    def increment_otp_attempts(self, username: str) -> int:
        """Count one failed verification and return the new attempt total. Used by
        the SECURE mechanism (api.careotter.lab) to lock the OTP after too many
        wrong codes — per account, persisted, so a page reload or IP change does not
        grant fresh tries. The PRECARIOUS beta mechanism never calls this."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE password_reset_otp SET attempts = attempts + 1 WHERE username = ?',
                    (username,)
                )
                conn.commit()
                row = conn.execute(
                    'SELECT attempts FROM password_reset_otp WHERE username = ?',
                    (username,)
                ).fetchone()
                return int(row[0]) if row else 0
        except Exception as e:
            logger.error(f"[DB] Error incrementing reset OTP attempts: {e}")
            return 0

    def set_display_name(self, username: str, display_name: str) -> bool:
        """Set the friendly display name shown in the UI (distinct from the
        login username)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    'UPDATE users SET display_name = ? WHERE username = ?',
                    (display_name, username)
                )
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            logger.error(f"[DB] Error setting display_name: {e}")
            return False

    def set_profile_photo(self, username: str, data_uri: str) -> bool:
        """Store the profile photo as a base64 data URI on the user row."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute(
                    'UPDATE users SET profile_photo = ? WHERE username = ?',
                    (data_uri, username)
                )
                conn.commit()
                return cur.rowcount > 0
        except Exception as e:
            logger.error(f"[DB] Error setting profile photo: {e}")
            return False

    def rename_user(self, old_username: str, new_username: str) -> bool:
        """Rename a user, cascading the change to every table that references
        the username as a natural key (devices, caregiver_assignments).

        Username is a natural foreign key throughout the schema, so all
        references are updated inside a single transaction. Returns False if
        ``new_username`` already exists or the source user is missing.
        """
        if not new_username or new_username == old_username:
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Reject collision with an existing account
                exists = conn.execute(
                    'SELECT 1 FROM users WHERE username = ?', (new_username,)
                ).fetchone()
                if exists:
                    logger.warning(f"[DB] rename_user: {new_username} already taken")
                    return False
                src = conn.execute(
                    'SELECT 1 FROM users WHERE username = ?', (old_username,)
                ).fetchone()
                if not src:
                    logger.warning(f"[DB] rename_user: {old_username} not found")
                    return False

                # Cascade across the natural-key references in one transaction
                conn.execute('UPDATE users SET username = ? WHERE username = ?',
                             (new_username, old_username))
                conn.execute('UPDATE devices SET patient_username = ? WHERE patient_username = ?',
                             (new_username, old_username))
                conn.execute('UPDATE caregiver_assignments SET caregiver_username = ? WHERE caregiver_username = ?',
                             (new_username, old_username))
                conn.execute('UPDATE caregiver_assignments SET patient_username = ? WHERE patient_username = ?',
                             (new_username, old_username))
                conn.commit()
                logger.info(f"[DB] Renamed user {old_username} → {new_username} (cascaded)")
                return True
        except Exception as e:
            logger.error(f"[DB] rename_user failed: {e}")
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
                    (device_mac, timestamp, bpm, spo2, source)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    mac,
                    data.get('timestamp'),
                    data.get('bpm'),
                    data.get('spo2'),
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
                               v.source, v.created_at,
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
                               v.source, v.created_at,
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

    # ── Tiered vitals retention ─────────────────────────────────────────────
    #
    # Three tables hold vitals at different resolutions:
    #   - vitals_readings   (raw 10s samples)  → retain RAW_RETENTION_HOURS
    #   - vitals_minute_agg (1 row per minute) → retain MINUTE_RETENTION_DAYS
    #   - vitals_hour_agg   (1 row per hour)   → retain forever (clinical trend)
    #
    # The aggregator thread in app.py wakes once a minute and calls
    # ``rollup_minute_aggregates`` + ``rollup_hour_aggregates`` to advance
    # both warm and cold tiers, then ``prune_vitals_tiers`` drops anything
    # outside its retention window.
    RAW_RETENTION_HOURS   = 24
    MINUTE_RETENTION_DAYS = 30

    @staticmethod
    def _floor(ts: float, bucket_seconds: int) -> float:
        return float(int(ts) // bucket_seconds * bucket_seconds)

    def rollup_minute_aggregates(self) -> int:
        """Collapse every minute bucket that already has a NEXT bucket of raw
        readings — guarantees the minute is complete before aggregating, so
        steady-state inserts do not produce a partial row that we'd later
        have to overwrite. Returns rows written.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Latest already-aggregated minute per device
                last = {
                    row[0]: row[1] for row in conn.execute(
                        'SELECT device_mac, MAX(bucket_ts) FROM vitals_minute_agg GROUP BY device_mac'
                    ).fetchall()
                }
                # Read raw readings that fall in COMPLETED minute buckets only
                # (timestamp < current_minute_floor).
                now_minute = self._floor(datetime.now().timestamp(), 60)
                rows = conn.execute('''
                    SELECT device_mac,
                           CAST(timestamp / 60 AS INTEGER) * 60 AS bucket_ts,
                           AVG(bpm), MIN(bpm), MAX(bpm),
                           AVG(spo2), MIN(spo2), MAX(spo2),
                           COUNT(*)
                    FROM vitals_readings
                    WHERE timestamp < ?
                    GROUP BY device_mac, bucket_ts
                ''', (now_minute,)).fetchall()
                inserted = 0
                for r in rows:
                    mac, bucket = r[0], float(r[1])
                    if bucket <= last.get(mac, 0):
                        continue
                    conn.execute('''
                        INSERT OR REPLACE INTO vitals_minute_agg
                        (device_mac, bucket_ts, bpm_avg, bpm_min, bpm_max,
                         spo2_avg, spo2_min, spo2_max, samples)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (mac, bucket, r[2], r[3], r[4], r[5], r[6], r[7], r[8]))
                    inserted += 1
                conn.commit()
                if inserted:
                    logger.info(f"[DB] Rolled up {inserted} minute aggregate rows")
                return inserted
        except Exception as e:
            logger.error(f"[DB] rollup_minute_aggregates failed: {e}")
            return 0

    def rollup_hour_aggregates(self) -> int:
        """Same pattern but folds completed-minute aggregates into hour buckets.
        Reads from vitals_minute_agg, not raw — avoids re-scanning samples that
        are already summarised.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                last = {
                    row[0]: row[1] for row in conn.execute(
                        'SELECT device_mac, MAX(bucket_ts) FROM vitals_hour_agg GROUP BY device_mac'
                    ).fetchall()
                }
                now_hour = self._floor(datetime.now().timestamp(), 3600)
                rows = conn.execute('''
                    SELECT device_mac,
                           CAST(bucket_ts / 3600 AS INTEGER) * 3600 AS bucket_ts,
                           AVG(bpm_avg),
                           MIN(bpm_min),
                           MAX(bpm_max),
                           AVG(spo2_avg),
                           MIN(spo2_min),
                           MAX(spo2_max),
                           SUM(samples)
                    FROM vitals_minute_agg
                    WHERE bucket_ts < ?
                    GROUP BY device_mac, bucket_ts
                ''', (now_hour,)).fetchall()
                inserted = 0
                for r in rows:
                    mac, bucket = r[0], float(r[1])
                    if bucket <= last.get(mac, 0):
                        continue
                    conn.execute('''
                        INSERT OR REPLACE INTO vitals_hour_agg
                        (device_mac, bucket_ts, bpm_avg, bpm_min, bpm_max,
                         spo2_avg, spo2_min, spo2_max, samples)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (mac, bucket, r[2], r[3], r[4], r[5], r[6], r[7], r[8]))
                    inserted += 1
                conn.commit()
                if inserted:
                    logger.info(f"[DB] Rolled up {inserted} hour aggregate rows")
                return inserted
        except Exception as e:
            logger.error(f"[DB] rollup_hour_aggregates failed: {e}")
            return 0

    def prune_vitals_tiers(self) -> dict:
        """Drop raw rows > RAW_RETENTION_HOURS and minute aggs > MINUTE_RETENTION_DAYS.
        Hour aggregates are NEVER pruned automatically — they are the clinical
        long-term trend and tiny (~8.7k rows/year/device).
        """
        now = datetime.now().timestamp()
        raw_cutoff   = now - self.RAW_RETENTION_HOURS * 3600
        minute_cutoff = now - self.MINUTE_RETENTION_DAYS * 86400
        try:
            with sqlite3.connect(self.db_path) as conn:
                raw_deleted = conn.execute(
                    'DELETE FROM vitals_readings WHERE timestamp < ?', (raw_cutoff,)
                ).rowcount
                min_deleted = conn.execute(
                    'DELETE FROM vitals_minute_agg WHERE bucket_ts < ?', (minute_cutoff,)
                ).rowcount
                conn.commit()
                if raw_deleted or min_deleted:
                    logger.info(
                        f"[DB] Prune: raw={raw_deleted}, minute_agg={min_deleted}"
                    )
                return {'raw': raw_deleted, 'minute': min_deleted}
        except Exception as e:
            logger.error(f"[DB] prune_vitals_tiers failed: {e}")
            return {'raw': 0, 'minute': 0}

    def get_vitals_history_tiered(self, hours: int = 24, limit: int = 5000,
                                  device_mac: str = None) -> dict:
        """Tier-selecting history query — the endpoint that should be used by
        any new UI code. Picks the granularity from the requested time span:

          ≤ 2h   → raw 10s readings
          ≤ 30d  → minute aggregates
          > 30d  → hour aggregates

        Returns a dict with ``tier`` so the frontend knows what fields are
        present (raw rows have bpm/spo2; aggregate rows have bpm_avg/min/max).
        """
        since = (datetime.now() - timedelta(hours=hours)).timestamp()
        mac = device_mac.upper() if device_mac else None
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                if hours <= 2:
                    tier = 'raw'
                    if mac:
                        rows = conn.execute('''
                            SELECT v.device_mac, v.timestamp, v.bpm, v.spo2,
                                   v.source, d.patient_username, d.device_name
                            FROM vitals_readings v
                            LEFT JOIN devices d ON v.device_mac = d.mac
                            WHERE v.timestamp >= ? AND v.device_mac = ?
                            ORDER BY v.timestamp DESC LIMIT ?
                        ''', (since, mac, limit)).fetchall()
                    else:
                        rows = conn.execute('''
                            SELECT v.device_mac, v.timestamp, v.bpm, v.spo2,
                                   v.source, d.patient_username, d.device_name
                            FROM vitals_readings v
                            LEFT JOIN devices d ON v.device_mac = d.mac
                            WHERE v.timestamp >= ?
                            ORDER BY v.timestamp DESC LIMIT ?
                        ''', (since, limit)).fetchall()
                elif hours <= 24 * 30:
                    tier = 'minute'
                    table_select = '''
                        SELECT a.device_mac, a.bucket_ts AS timestamp,
                               a.bpm_avg, a.bpm_min, a.bpm_max,
                               a.spo2_avg, a.spo2_min, a.spo2_max, a.samples,
                               d.patient_username, d.device_name
                        FROM vitals_minute_agg a
                        LEFT JOIN devices d ON a.device_mac = d.mac
                        WHERE a.bucket_ts >= ?'''
                    if mac:
                        rows = conn.execute(
                            table_select + ' AND a.device_mac = ? ORDER BY a.bucket_ts DESC LIMIT ?',
                            (since, mac, limit)).fetchall()
                    else:
                        rows = conn.execute(
                            table_select + ' ORDER BY a.bucket_ts DESC LIMIT ?',
                            (since, limit)).fetchall()
                else:
                    tier = 'hour'
                    table_select = '''
                        SELECT a.device_mac, a.bucket_ts AS timestamp,
                               a.bpm_avg, a.bpm_min, a.bpm_max,
                               a.spo2_avg, a.spo2_min, a.spo2_max, a.samples,
                               d.patient_username, d.device_name
                        FROM vitals_hour_agg a
                        LEFT JOIN devices d ON a.device_mac = d.mac
                        WHERE a.bucket_ts >= ?'''
                    if mac:
                        rows = conn.execute(
                            table_select + ' AND a.device_mac = ? ORDER BY a.bucket_ts DESC LIMIT ?',
                            (since, mac, limit)).fetchall()
                    else:
                        rows = conn.execute(
                            table_select + ' ORDER BY a.bucket_ts DESC LIMIT ?',
                            (since, limit)).fetchall()
                return {'tier': tier, 'readings': [dict(r) for r in rows]}
        except Exception as e:
            logger.error(f"[DB] get_vitals_history_tiered failed: {e}")
            return {'tier': 'raw', 'readings': []}

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

    # ── Health Store (API6:2023 — sensitive business flow) ─────────────────────
    # Raw persistence only; the business policy (cooldown/quota/stock toggle) lives
    # in services/store_service.py.

    # Each patient's wallet is pre-funded with a FIXED device-procurement budget.
    # There is intentionally NO top-up path — money cannot be added to a wallet
    # (the `salary` column is retained for schema stability but seeded to 0).
    WALLET_BUDGET = 5000.0

    def ensure_wallet(self, username: str, budget: float = None) -> bool:
        """Create a fixed-budget wallet for the user if absent. Idempotent."""
        budget = self.WALLET_BUDGET if budget is None else budget
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'INSERT OR IGNORE INTO wallets (username, balance, salary) VALUES (?, ?, ?)',
                    (username, budget, 0))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[DB] ensure_wallet error: {e}")
            return False

    def seed_store_wallets(self, budget: float = None) -> int:
        """Ensure a fixed-budget wallet for every patient user. Idempotent."""
        budget = self.WALLET_BUDGET if budget is None else budget
        try:
            with sqlite3.connect(self.db_path) as conn:
                patients = conn.execute(
                    "SELECT username FROM users WHERE role = 'patient'").fetchall()
                for (uname,) in patients:
                    conn.execute(
                        'INSERT OR IGNORE INTO wallets (username, balance, salary) VALUES (?, ?, ?)',
                        (uname, budget, 0))
                conn.commit()
                return len(patients)
        except Exception as e:
            logger.error(f"[DB] seed_store_wallets error: {e}")
            return 0

    def get_wallet(self, username: str) -> Optional[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT username, balance, updated_at '
                    'FROM wallets WHERE username = ?', (username,)).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] get_wallet error: {e}")
            return None

    def list_products(self, active_only: bool = True) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                q = ('SELECT id, sku, name, description, price, category, stock, '
                     'requires_prescription, active FROM products')
                if active_only:
                    q += ' WHERE active = 1'
                q += ' ORDER BY price DESC'
                return [dict(r) for r in conn.execute(q).fetchall()]
        except Exception as e:
            logger.error(f"[DB] list_products error: {e}")
            return []

    def get_product(self, product_id: int) -> Optional[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    'SELECT id, sku, name, description, price, category, stock, '
                    'requires_prescription, active FROM products WHERE id = ?',
                    (product_id,)).fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"[DB] get_product error: {e}")
            return None

    def get_orders(self, username: str) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute('''
                    SELECT o.id, o.product_id, o.quantity, o.unit_price, o.total,
                           o.status, o.created_at,
                           p.name AS product_name, p.sku AS product_sku
                    FROM orders o
                    LEFT JOIN products p ON p.id = o.product_id
                    WHERE o.username = ?
                    ORDER BY o.created_at DESC, o.id DESC
                ''', (username,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] get_orders error: {e}")
            return []

    def try_purchase(self, username: str, product_id: int, quantity: int,
                     max_per_product=None, check_stock: bool = True) -> Dict:
        """Attempt a purchase in a single transaction. Returns a result dict.
        max_per_product=None disables the per-user quota; check_stock=False disables
        the stock guard — both are the Phase-2 API6 hooks (Phase 1 passes secure values)."""
        if quantity is None:
            return {'ok': False, 'error': 'bad_quantity'}
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute('BEGIN IMMEDIATE')
                prod = conn.execute(
                    'SELECT id, name, price, stock, active FROM products WHERE id = ?',
                    (product_id,)).fetchone()
                if not prod or not prod['active']:
                    conn.rollback()
                    return {'ok': False, 'error': 'not_found'}
                if check_stock and prod['stock'] < quantity:
                    conn.rollback()
                    return {'ok': False, 'error': 'out_of_stock', 'stock': prod['stock']}
                if max_per_product is not None:
                    already = conn.execute(
                        'SELECT COALESCE(SUM(quantity), 0) FROM orders '
                        'WHERE username = ? AND product_id = ?',
                        (username, product_id)).fetchone()[0]
                    if already + quantity > max_per_product:
                        conn.rollback()
                        return {'ok': False, 'error': 'quota_exceeded',
                                'max_per_product': max_per_product, 'already': already}
                unit_price = prod['price']
                total = unit_price * quantity
                wallet = conn.execute(
                    'SELECT balance FROM wallets WHERE username = ?', (username,)).fetchone()
                if not wallet:
                    conn.rollback()
                    return {'ok': False, 'error': 'no_wallet'}
                if wallet['balance'] < total:
                    conn.rollback()
                    return {'ok': False, 'error': 'insufficient_funds',
                            'balance': wallet['balance'], 'total': total}
                if check_stock:
                    conn.execute('UPDATE products SET stock = stock - ? WHERE id = ?',
                                 (quantity, product_id))
                conn.execute(
                    'UPDATE wallets SET balance = balance - ?, '
                    'updated_at = CURRENT_TIMESTAMP WHERE username = ?', (total, username))
                cur = conn.execute(
                    'INSERT INTO orders (username, product_id, quantity, unit_price, total) '
                    'VALUES (?, ?, ?, ?, ?)',
                    (username, product_id, quantity, unit_price, total))
                order_id = cur.lastrowid
                conn.commit()
                return {'ok': True, 'order_id': order_id, 'product_id': product_id,
                        'product': prod['name'], 'quantity': quantity,
                        'unit_price': unit_price, 'total': total,
                        'balance': wallet['balance'] - total}
        except Exception as e:
            logger.error(f"[DB] try_purchase error: {e}")
            return {'ok': False, 'error': 'db_error'}

    # ── Teleconsultation appointments (API6 — sensitive business flow) ─────────
    # Raw persistence only; the per-patient booking-cap toggle lives in
    # services/appointment_service.py.

    def seed_appointment_slots(self) -> int:
        """Seed a scarce set of open slots if none exist. Idempotent. Returns count."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                n = conn.execute('SELECT COUNT(*) FROM appointment_slots').fetchone()[0]
                if n > 0:
                    return n
                base = (datetime.now().replace(minute=0, second=0, microsecond=0)
                        + timedelta(days=1, hours=1))
                roster = [('Dr. Marlowe Pike', 'Cardiology'),
                          ('Dr. Selma Okafor', 'Electrophysiology')]
                rows = []
                for clin_i, (clinician, specialty) in enumerate(roster):
                    for day in range(4):
                        t = base + timedelta(days=day, hours=clin_i * 2)
                        rows.append((clinician, specialty, t.isoformat()))
                conn.executemany(
                    'INSERT INTO appointment_slots (clinician, specialty, slot_time) '
                    'VALUES (?, ?, ?)', rows)
                conn.commit()
                logger.info(f"[DB] Seeded {len(rows)} appointment slots")
                return len(rows)
        except Exception as e:
            logger.error(f"[DB] seed_appointment_slots error: {e}")
            return 0

    def list_open_slots(self) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, clinician, specialty, slot_time FROM appointment_slots "
                    "WHERE status = 'open' ORDER BY slot_time, id").fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] list_open_slots error: {e}")
            return []

    def slots_for_user(self, username: str) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, clinician, specialty, slot_time, booked_at "
                    "FROM appointment_slots WHERE booked_by = ? AND status = 'booked' "
                    "ORDER BY slot_time, id", (username,)).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"[DB] slots_for_user error: {e}")
            return []

    def book_slot(self, username: str, slot_id: int, max_active=2) -> Dict:
        """Book a slot. The atomic claim (UPDATE … WHERE status='open') stops two patients
        double-booking the same slot in BOTH modes. max_active=None disables the per-patient
        cap (the API6 hook); a number enforces it (secure mode).

        The cap is checked against the denormalized users.active_appointments counter — NOT a
        live COUNT over appointment_slots. A successful booking increments that counter (and
        cancel_slot decrements it), so the column is the single source of truth for the cap."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                # Secure control: per-patient active-booking cap, read straight from the
                # users counter column (no row count over appointment_slots).
                if max_active is not None:
                    row = conn.execute(
                        "SELECT active_appointments FROM users WHERE username = ?",
                        (username,)).fetchone()
                    active = row['active_appointments'] if row else 0
                    if active >= max_active:
                        return {'ok': False, 'error': 'booking_limit_reached',
                                'max_active': max_active}
                # Atomic slot claim — succeeds only if the slot is still open.
                cur = conn.execute(
                    "UPDATE appointment_slots SET status = 'booked', booked_by = ?, "
                    "booked_at = ? WHERE id = ? AND status = 'open'",
                    (username, datetime.now().isoformat(), slot_id))
                if cur.rowcount != 1:
                    conn.rollback()
                    return {'ok': False, 'error': 'slot_taken'}
                # Keep the denormalized counter in lock-step with the new booking.
                conn.execute(
                    "UPDATE users SET active_appointments = active_appointments + 1 "
                    "WHERE username = ?", (username,))
                conn.commit()
                row = conn.execute(
                    "SELECT id, clinician, specialty, slot_time FROM appointment_slots "
                    "WHERE id = ?", (slot_id,)).fetchone()
                return {'ok': True, 'slot': dict(row)}
        except Exception as e:
            logger.error(f"[DB] book_slot error: {e}")
            return {'ok': False, 'error': 'db_error'}

    def cancel_slot(self, username: str, slot_id: int,
                    http_method: str = 'POST', vulnerable: bool = False) -> Dict:
        """Release one of the caller's booked slots and decrement the user's denormalized
        active_appointments counter.

        SECURE (vulnerable=False): the HTTP method is validated FIRST — only POST may mutate
        state — and then the slot release and the counter decrement happen together,
        atomically and owner-only. A non-POST request changes nothing and returns 405. The
        counter never drifts from the schedule.

        VULNERABLE (vulnerable=True) — INTENTIONAL business-logic flaw (API6 slot hoarding via
        an HTTP-method-confusion counter desync): the counter is decremented FIRST, for ANY
        method, and the method is only checked AFTERWARD. The endpoint is meant to accept POST
        only, but that is not verified until the counter has already been lowered. On a
        non-POST request (DELETE / GET) the function returns BEFORE releasing the slot — so the
        booking stays under the attacker while their counter drops, letting them re-book and
        accumulate slots past the per-patient cap (denial of care). Second vector: a POST for a
        slot they do NOT own also decrements the counter before the ownership check fails."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if not vulnerable:
                    # SECURE: reject any non-POST method before touching state.
                    if http_method != 'POST':
                        return {'ok': False, 'error': 'method_not_allowed',
                                'method': http_method}
                    cur = conn.execute(
                        "UPDATE appointment_slots SET status = 'open', booked_by = NULL, "
                        "booked_at = NULL WHERE id = ? AND booked_by = ? AND status = 'booked'",
                        (slot_id, username))
                    if cur.rowcount != 1:
                        conn.rollback()
                        return {'ok': False, 'error': 'not_your_booking'}
                    conn.execute(
                        "UPDATE users SET active_appointments = MAX(active_appointments - 1, 0) "
                        "WHERE username = ?", (username,))
                    conn.commit()
                    return {'ok': True, 'slot_id': slot_id}

                # VULNERABLE: decrement the counter BEFORE validating the request method.
                conn.execute(
                    "UPDATE users SET active_appointments = MAX(active_appointments - 1, 0) "
                    "WHERE username = ?", (username,))
                conn.commit()
                # The endpoint only means to accept POST — but it is checked too late, after
                # the counter was already lowered. Non-POST leaves the slot booked.
                if http_method != 'POST':
                    return {'ok': False, 'error': 'method_not_allowed', 'method': http_method}
                # POST path: actually release the slot (owner-only).
                cur = conn.execute(
                    "UPDATE appointment_slots SET status = 'open', booked_by = NULL, "
                    "booked_at = NULL WHERE id = ? AND booked_by = ? AND status = 'booked'",
                    (slot_id, username))
                conn.commit()
                if cur.rowcount != 1:
                    return {'ok': False, 'error': 'not_your_booking'}
                return {'ok': True, 'slot_id': slot_id}
        except Exception as e:
            logger.error(f"[DB] cancel_slot error: {e}")
            return {'ok': False, 'error': 'db_error'}
