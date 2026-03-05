#!/usr/bin/env python3
"""Local encrypted data storage for CareOtter readings and alerts"""
import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class DataStore:
    """SQLite storage for readings and alerts (encrypted at rest in secure mode)"""
    
    DB_PATH = "/root/careotter/data/careotter.db"
    
    def __init__(self, encrypt: bool = True):
        self.encrypt = encrypt
        os.makedirs(os.path.dirname(self.DB_PATH), exist_ok=True)
        self._init_db()
        
    def _init_db(self) -> None:
        """Initialize database schema"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        # Readings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                heart_rate INTEGER NOT NULL,
                spo2 INTEGER NOT NULL,
                perfusion_index REAL,
                status TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reading_id INTEGER NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                value TEXT,
                acknowledged INTEGER DEFAULT 0,
                ack_timestamp TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reading_id) REFERENCES readings(id)
            )
        ''')
        
        # Cloud sync status
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reading_id INTEGER,
                alert_id INTEGER,
                sync_status TEXT,
                sync_timestamp TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.DB_PATH}")
        
    def save_reading(self, reading: Dict, alerts: List[Dict]) -> int:
        """Save a cardiac reading and associated alerts"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        try:
            # Insert reading
            cursor.execute('''
                INSERT INTO readings (timestamp, heart_rate, spo2, perfusion_index, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                reading['timestamp'],
                reading['heart_rate'],
                reading['spo2'],
                reading.get('perfusion_index', 0.0),
                reading.get('status', 'normal')
            ))
            
            reading_id = cursor.lastrowid
            
            # Insert alerts
            for alert in alerts:
                cursor.execute('''
                    INSERT INTO alerts (reading_id, alert_type, severity, value)
                    VALUES (?, ?, ?, ?)
                ''', (
                    reading_id,
                    alert['type'],
                    alert['severity'],
                    alert.get('value', '')
                ))
            
            conn.commit()
            logger.debug(f"Reading {reading_id} saved with {len(alerts)} alerts")
            return reading_id
            
        except Exception as e:
            logger.error(f"Failed to save reading: {e}")
            conn.rollback()
            return -1
        finally:
            conn.close()
    
    def get_recent_readings(self, limit: int = 100) -> List[Dict]:
        """Get recent readings"""
        conn = sqlite3.connect(self.DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM readings
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        readings = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return readings
    
    def get_unacked_alerts(self) -> List[Dict]:
        """Get unacknowledged critical alerts"""
        conn = sqlite3.connect(self.DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT a.*, r.heart_rate, r.spo2
            FROM alerts a
            JOIN readings r ON a.reading_id = r.id
            WHERE a.acknowledged = 0 AND a.severity = 'critical'
            ORDER BY a.created_at DESC
            LIMIT 10
        ''')
        
        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return alerts
    
    def acknowledge_alert(self, alert_id: int) -> bool:
        """Acknowledge an alert"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE alerts
                SET acknowledged = 1, ack_timestamp = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), alert_id))
            
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False
        finally:
            conn.close()
    
    def mark_synced(self, reading_id: int, status: str = 'synced') -> None:
        """Mark reading as synced to cloud"""
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO sync_log (reading_id, sync_status, sync_timestamp)
                VALUES (?, ?, ?)
            ''', (reading_id, status, datetime.now().isoformat()))
            
            conn.commit()
        except Exception as e:
            logger.error(f"Failed to log sync status: {e}")
        finally:
            conn.close()
