import sqlite3
import hashlib
import re
import secrets
import string
from typing import Optional, Tuple, Dict, Any, Union, List
from datetime import datetime
import logging
from contextlib import contextmanager

logging.basicConfig(level=logging.INFO)

class UserManager:
    def __init__(self, db_name: str = 'secure_storage.db') -> None:
        self.db_name: str = db_name
        self.conn: Optional[sqlite3.Connection] = sqlite3.connect(self.db_name)
        self.cursor: Optional[sqlite3.Cursor] = self.conn.cursor()

        # Security parameters
        self.min_password_length: int = 7
        self.salt_length: int = 32
        self._hash_iterations: int = 100000
        self.hash_algorithm: str = 'sha256'

        self.current_user: Optional[Dict[str, Any]] = None
        self.session_token: Optional[str] = None

        self._initialize_db()

    def _initialize_db(self) -> None:
        """Initialize database and create tables if they don't exist."""
        queries = [
            '''CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL,
                   salt TEXT NOT NULL,
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   last_login TIMESTAMP,
                   failed_attempts INTEGER DEFAULT 0,
                   locked_until TIMESTAMP
               )''',
            '''CREATE TABLE IF NOT EXISTS password_reset_tokens (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   user_id INTEGER NOT NULL,
                   token TEXT NOT NULL,
                   expires_at TIMESTAMP NOT NULL,
                   used INTEGER DEFAULT 0,
                   FOREIGN KEY(user_id) REFERENCES users(id)
               )''',
            '''CREATE TABLE IF NOT EXISTS activity_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   user_id INTEGER,
                   activity_type TEXT NOT NULL,
                   timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                   ip_address TEXT,
                   details TEXT,
                   FOREIGN KEY(user_id) REFERENCES users(id)
               )'''
        ]
        for query in queries:
            self._execute(query)

    @contextmanager
    def _db_transaction(self):
        """
        Context manager to handle database transactions.
        Commits on successful exit; rolls back on exception.
        """
        try:
            yield
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()
            logging.error("Database error: %s", e)
            raise

    def _execute(self, query: str, params: Union[Tuple, List] = ()) -> None:
        """Execute a query within a transaction."""
        if self.cursor is None:
            raise RuntimeError("Database cursor not initialized")
        with self._db_transaction():
            self.cursor.execute(query, params)

    def _fetchone(self) -> Optional[Tuple]:
        """Fetch one row from the cursor."""
        if self.cursor is None:
            raise RuntimeError("Database cursor not initialized")
        return self.cursor.fetchone()

    def _log_activity(self, user_id: int, activity_type: str, ip_address: Optional[str] = None, details: Optional[str] = None) -> None:
        """Log user activity for auditing purposes."""
        try:
            self._execute(
                '''INSERT INTO activity_log (user_id, activity_type, ip_address, details)
                   VALUES (?, ?, ?, ?)''',
                (user_id, activity_type, ip_address, details)
            )
        except sqlite3.Error as e:
            logging.error("Failed to log activity: %s", e)

    def _generate_salt(self) -> str:
        """Generate a cryptographically secure random salt."""
        return secrets.token_hex(self.salt_length)

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash the password using PBKDF2-HMAC."""
        return hashlib.pbkdf2_hmac(
            self.hash_algorithm,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            self._hash_iterations
        ).hex()

    def _validate_username(self, username: str) -> Tuple[bool, str]:
        """Validate the username format and check for disallowed characters."""
        if not username:
            return False, "Username cannot be empty"
        if len(username) > 50:
            return False, "Username too long (max 50 characters)"
        if re.search(r'[\'\";\\]', username):
            return False, "Username contains invalid characters"
        return True, ""

    def _validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength."""
        if len(password) < self.min_password_length:
            return False, f"Password must be at least {self.min_password_length} characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        if not any(c in string.punctuation for c in password):
            return False, "Password must contain at least one special character"
        return True, ""

    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Register a new user with secure password storage."""
        valid, msg = self._validate_username(username)
        if not valid:
            return False, msg
        valid, msg = self._validate_password(password)
        if not valid:
            return False, msg

        with self._db_transaction():
            self.cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if self._fetchone():
                return False, "Username already exists"
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            self.cursor.execute(
                '''INSERT INTO users (username, password_hash, salt)
                   VALUES (?, ?, ?)''',
                (username, password_hash, salt)
            )
            user_id = self.cursor.lastrowid

        if user_id:
            self._log_activity(user_id, 'REGISTER')
        return True, "User registered successfully"

    def login(self, username: str, password: str, ip_address: Optional[str] = None) -> Tuple[bool, str]:
        """Authenticate a user with the given credentials."""
        with self._db_transaction():
            self.cursor.execute(
                '''SELECT id, password_hash, salt, failed_attempts, locked_until
                   FROM users WHERE username = ?''',
                (username,)
            )
            user_data = self._fetchone()

        if not user_data:
            return False, "Invalid username or password"

        user_id, stored_hash, salt, failed_attempts, locked_until = user_data

        if locked_until:
            if datetime.now() < datetime.strptime(locked_until, '%Y-%m-%d %H:%M:%S'):
                return False, "Account is temporarily locked due to too many failed attempts"
            else:
                self._execute('UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?', (user_id,))

        input_hash = self._hash_password(password, salt)
        if secrets.compare_digest(input_hash, stored_hash):
            self._execute('UPDATE users SET last_login = CURRENT_TIMESTAMP, failed_attempts = 0 WHERE id = ?', (user_id,))
            self.session_token = secrets.token_urlsafe(32)
            self.current_user = {'id': user_id, 'username': username, 'token': self.session_token}
            self._log_activity(user_id, 'LOGIN_SUCCESS', ip_address)
            return True, "Login successful"
        else:
            self._execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user_id,))
            if failed_attempts + 1 >= 5:
                self._execute('UPDATE users SET locked_until = datetime(CURRENT_TIMESTAMP, \'+30 minutes\') WHERE id = ?', (user_id,))
            self._log_activity(user_id, 'LOGIN_FAILURE', ip_address, "Invalid password")
            return False, "Invalid username or password"

    def logout(self) -> Tuple[bool, str]:
        """Log out the current user."""
        if self.current_user:
            user_id = self.current_user.get('id')
            if user_id:
                self._log_activity(user_id, 'LOGOUT')
            self.current_user = None
            self.session_token = None
            return True, "Logged out successfully"
        return False, "No user is currently logged in"

    def reset_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """Reset a user's password."""
        valid, msg = self._validate_password(new_password)
        if not valid:
            return False, msg

        with self._db_transaction():
            self.cursor.execute('SELECT id, salt FROM users WHERE username = ?', (username,))
            user_data = self._fetchone()
            if not user_data:
                return False, "User not found"
            user_id, salt = user_data
            new_hash = self._hash_password(new_password, salt)
            self.cursor.execute(
                '''UPDATE users
                   SET password_hash = ?, failed_attempts = 0, locked_until = NULL
                   WHERE id = ?''',
                (new_hash, user_id)
            )
        self._log_activity(user_id, 'PASSWORD_RESET')
        return True, "Password reset successfully"

    def generate_password_reset_token(self, username: str) -> Tuple[bool, str, Optional[str]]:
        """Generate a secure password reset token."""
        with self._db_transaction():
            self.cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            user_data = self._fetchone()
            if not user_data:
                return False, "User not found", None
            user_id = user_data[0]
            token = secrets.token_urlsafe(32)
            self.cursor.execute(
                '''INSERT INTO password_reset_tokens (user_id, token, expires_at)
                   VALUES (?, ?, datetime(CURRENT_TIMESTAMP, '+1 hour'))''',
                (user_id, token)
            )
        self._log_activity(user_id, 'PASSWORD_RESET_TOKEN_GENERATED')
        return True, "Token generated successfully", token

    def use_password_reset_token(self, token: str, new_password: str) -> Tuple[bool, str]:
        """Use a password reset token to set a new password."""
        valid, msg = self._validate_password(new_password)
        if not valid:
            return False, msg

        clean_token = token.strip()
        with self._db_transaction():
            self.cursor.execute(
                '''SELECT user_id, expires_at, used
                   FROM password_reset_tokens
                   WHERE token = ?''',
                (clean_token,)
            )
            token_data = self._fetchone()
            if not token_data:
                self._log_activity(-1, 'TOKEN_VALIDATION_FAILED', details="Token not found in database")
                return False, "Invalid or expired token"

            user_id, expires_at, used = token_data
            if used:
                self._log_activity(user_id, 'TOKEN_ALREADY_USED')
                return False, "This reset link has already been used"

            if datetime.utcnow() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S'):
                self._log_activity(user_id, 'TOKEN_EXPIRED')
                return False, "This reset link has expired"

            self.cursor.execute('SELECT salt FROM users WHERE id = ?', (user_id,))
            salt_data = self._fetchone()
            if not salt_data:
                return False, "User not found"
            salt = salt_data[0]
            new_hash = self._hash_password(new_password, salt)
            
            # Update user password and mark token as used within the same transaction
            self.cursor.execute(
                '''UPDATE users
                   SET password_hash = ?, failed_attempts = 0, locked_until = NULL
                   WHERE id = ?''',
                (new_hash, user_id)
            )
            self.cursor.execute(
                '''UPDATE password_reset_tokens
                   SET used = 1
                   WHERE token = ?''',
                (clean_token,)
            )
        self._log_activity(user_id, 'PASSWORD_RESET_VIA_TOKEN')
        return True, "Password reset successfully"

    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None