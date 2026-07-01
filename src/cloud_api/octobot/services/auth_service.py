"""
auth_service.py — Operator authentication and database seeding

A single operator account (SQLite-backed) gates the control console with a
signed Flask session.

[Intentional vulnerability]
The login query is built with string formatting and a weak blacklist filter.
Common payloads using --, ;, UNION, OR, SELECT, etc. are rejected, but the
SQLite concatenation operator || and balanced-quote tricks still allow
authentication bypass. This is a lab-only weakness for the cloud console.
"""

import os
import re
import sqlite3
from config import Config


class AuthService:
    """Manages the operator user table and credential verification."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or Config.DB_PATH

    @staticmethod
    def _sanitize(value: str) -> str:
        """Weak blacklist that blocks the most obvious SQLi tokens.

        The filter is intentionally incomplete: it stops the normal tutorial
        payloads but misses SQLite-specific bypasses such as the || operator
        combined with <> or IS NOT.
        """
        lower = value.lower()

        # Punctuation-based tokens are blocked as substrings.
        for token in ('--', '/*', '*/', ';'):
            if token in lower:
                raise ValueError(f"Blocked token: {token}")

        # SQL keywords must appear as whole words, otherwise legitimate values
        # such as the username 'operator' would be rejected.
        keywords = ('union', 'select', 'insert', 'update', 'delete',
                    'drop', 'or', 'and', 'sleep', 'benchmark')
        for kw in keywords:
            if re.search(rf'\b{kw}\b', lower):
                raise ValueError(f"Blocked keyword: {kw}")
        return value

    def init_db(self):
        """Create the users table and seed the single operator account if empty."""
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        con = sqlite3.connect(self.db_path)

        # Migrate from any older schema (e.g. the previous pw_hash column) so
        # the vulnerable plaintext column is always present in lab containers.
        table_info = con.execute("PRAGMA table_info(users)").fetchall()
        if table_info and not any(col[1] == 'password' for col in table_info):
            con.execute('DROP TABLE users')
            con.commit()

        con.execute('CREATE TABLE IF NOT EXISTS users '
                    '(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)')
        if con.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            con.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (Config.OPERATOR_USER, Config.OPERATOR_PASSWORD)
            )
            con.commit()
        con.close()

    def verify_user(self, username: str, password: str) -> bool:
        """Check username/password against the stored plaintext password.

        Intentionally vulnerable to filter-bypass SQL injection. The username
        and password are filtered with a weak blacklist and then concatenated
        directly into the query.
        """
        try:
            safe_username = self._sanitize(username)
            safe_password = self._sanitize(password)
        except ValueError:
            return False

        con = sqlite3.connect(self.db_path)
        query = (
            f"SELECT username FROM users WHERE username = '{safe_username}' "
            f"AND password = '{safe_password}'"
        )
        row = con.execute(query).fetchone()
        con.close()
        return bool(row)
