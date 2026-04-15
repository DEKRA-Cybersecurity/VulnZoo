"""
database_service.py — Servicio de persistencia SQLite para CareOtter

Almacena lecturas de vitales, eventos del dispositivo y configuración
de forma persistente en una base de datos SQLite embebida.
"""

import sqlite3
import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseService:
    """
    Servicio de base de datos SQLite para almacenar datos del dispositivo CareOtter.
    """

    def __init__(self, db_path: str = None):
        """
        Inicializa el servicio de base de datos.
        
        Args:
            db_path: Ruta al archivo SQLite. Si es None, usa la variable
                    de entorno DB_PATH o default '/app/data/careotter.db'
        """
        self.db_path = db_path or os.getenv('DB_PATH', '/app/data/careotter.db')
        
        # Asegurar que el directorio existe
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
                logger.info(f"[DB] Created database directory: {db_dir}")
            except Exception as e:
                logger.error(f"[DB] Failed to create directory {db_dir}: {e}")
                # Fallback a directorio temporal si no podemos crear el directorio
                self.db_path = '/tmp/careotter.db'
                logger.warning(f"[DB] Falling back to: {self.db_path}")
        
        logger.info(f"[DB] Using database: {self.db_path}")
        
        # Verificar que podemos escribir
        try:
            self._init_db()
            logger.info("[DB] Database initialized successfully")
        except Exception as e:
            logger.error(f"[DB] Failed to initialize database: {e}")
            raise

    def _init_db(self):
        """Inicializa el esquema de la base de datos si no existe."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS vitals_readings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    bpm INTEGER,
                    spo2 INTEGER,
                    ir_raw INTEGER,
                    red_raw INTEGER,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_vitals_timestamp 
                    ON vitals_readings(timestamp);
                
                CREATE INDEX IF NOT EXISTS idx_vitals_created 
                    ON vitals_readings(created_at);
                
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
            ''')
            conn.commit()

    def store_vitals(self, data: dict) -> bool:
        """
        Almacena una lectura de vitales en la base de datos.
        
        Args:
            data: Diccionario con keys: timestamp, bpm, spo2, ir_raw, red_raw, source
            
        Returns:
            True si se almacenó correctamente, False en caso contrario
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO vitals_readings 
                    (timestamp, bpm, spo2, ir_raw, red_raw, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
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

    def get_vitals_history(self, hours: int = 24, limit: int = 1000) -> List[Dict]:
        """
        Obtiene el historial de lecturas de vitales.
        
        Args:
            hours: Número de horas hacia atrás para obtener datos
            limit: Límite máximo de registros a retornar
            
        Returns:
            Lista de diccionarios con las lecturas
        """
        since = (datetime.now() - timedelta(hours=hours)).timestamp()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT id, timestamp, bpm, spo2, ir_raw, red_raw, source, created_at
                    FROM vitals_readings 
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (since, limit))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"[DB] Error fetching history: {e}")
            return []

    def get_vitals_stats(self, hours: int = 24) -> Dict:
        """
        Obtiene estadísticas agregadas de las lecturas de vitales.
        
        Args:
            hours: Número de horas hacia atrás para calcular estadísticas
            
        Returns:
            Diccionario con estadísticas de BPM y SpO2
        """
        since = (datetime.now() - timedelta(hours=hours)).timestamp()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT 
                        AVG(bpm) as avg_bpm,
                        MIN(bpm) as min_bpm,
                        MAX(bpm) as max_bpm,
                        AVG(spo2) as avg_spo2,
                        MIN(spo2) as min_spo2,
                        MAX(spo2) as max_spo2,
                        COUNT(*) as total_readings,
                        COUNT(CASE WHEN bpm < 60 OR bpm > 100 THEN 1 END) as bpm_alerts,
                        COUNT(CASE WHEN spo2 < 95 THEN 1 END) as spo2_alerts
                    FROM vitals_readings 
                    WHERE timestamp >= ?
                ''', (since,))
                
                row = cursor.fetchone()
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
                        'bpm': row[7] or 0,
                        'spo2': row[8] or 0
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
        Obtiene el número total de lecturas en un período.
        
        Args:
            hours: Número de horas hacia atrás
            
        Returns:
            Número de lecturas
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
        Obtiene información sobre la base de datos para debugging.
        
        Returns:
            Diccionario con info de la BD
        """
        try:
            # Verificar que el archivo existe
            file_exists = os.path.exists(self.db_path)
            file_size = os.path.getsize(self.db_path) if file_exists else 0
            
            with sqlite3.connect(self.db_path) as conn:
                # Contar registros totales
                cursor = conn.execute('SELECT COUNT(*) FROM vitals_readings')
                total_records = cursor.fetchone()[0]
                
                # Obtener rango de fechas
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
        Registra un evento del dispositivo.
        
        Args:
            event_type: Tipo de evento (auth_success, auth_fail, etc.)
            details: Detalles adicionales del evento
            ip_address: Dirección IP del cliente
            
        Returns:
            True si se registró correctamente
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

    def cleanup_old_data(self, days: int = 30) -> int:
        """
        Elimina datos antiguos para mantener el tamaño de la base de datos.
        
        Args:
            days: Número de días a mantener
            
        Returns:
            Número de registros eliminados
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Eliminar lecturas antiguas
                cursor = conn.execute('''
                    DELETE FROM vitals_readings WHERE timestamp < ?
                ''', (cutoff.timestamp(),))
                vitals_deleted = cursor.rowcount
                
                # Eliminar eventos antiguos
                cursor = conn.execute('''
                    DELETE FROM device_events WHERE timestamp < ?
                ''', (cutoff,))
                events_deleted = cursor.rowcount
                
                conn.commit()
                return vitals_deleted + events_deleted
        except Exception as e:
            logger.error(f"[DB] Error cleaning up old data: {e}")
            return 0
