"""
auth_service.py — Operator authentication and database seeding

A single operator account (SQLite-backed) gates the control console with a
signed Flask session.
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config


class AuthService:
    """Manages the operator user table and credential verification."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or Config.DB_PATH

    def init_db(self):
        """Create the users table and seed the single operator account if empty."""
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        con = sqlite3.connect(self.db_path)
        con.execute('CREATE TABLE IF NOT EXISTS users '
                    '(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT)')
        if con.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            con.execute(
                'INSERT INTO users (username, pw_hash) VALUES (?, ?)',
                (Config.OPERATOR_USER,
                 generate_password_hash(Config.OPERATOR_PASSWORD, method='pbkdf2:sha256'))
            )
            con.commit()
        con.close()

    def verify_user(self, username: str, password: str) -> bool:
        """Check username/password against the stored hash."""
        con = sqlite3.connect(self.db_path)
        row = con.execute(
            'SELECT pw_hash FROM users WHERE username = ?', (username,)
        ).fetchone()
        con.close()
        return bool(row) and check_password_hash(row[0], password)
