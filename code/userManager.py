import sqlite3
import hashlib
import re
import secrets
import string
import logging
from typing import Optional, Tuple, Dict, Any, Union, List, TypedDict, Protocol, Generator, Literal
from sqlite3.dbapi2 import Connection, Cursor
from datetime import datetime, timedelta
from contextlib import contextmanager

from .config import Config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DatabaseCursor(Protocol):
    def execute(self, query: str, params: Union[Tuple[Any, ...], Dict[str, Any]] = ...) -> Any: ...
    def fetchone(self) -> Optional[sqlite3.Row]: ...
    def fetchall(self) -> List[sqlite3.Row]: ...
    @property
    def lastrowid(self) -> int: ...

class DatabaseConnection(Protocol):
    def cursor(self) -> DatabaseCursor: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...
    def row_factory(self) -> Any: ...

class UserData(TypedDict):
    id: int
    username: str
    is_admin: bool
    password_hash: str
    salt: str
    failed_attempts: int
    locked_until: Optional[str]

class DatabaseError(Exception):
    pass

class UserManager:
    def __init__(self, db_name: str = Config.DATABASE_NAME) -> None:
        self.db_name: str = db_name
        self.min_password_length: int = Config.MIN_PASSWORD_LENGTH
        self.salt_length: int = 32
        self._hash_iterations: int = 100000
        self.hash_algorithm: str = 'sha256'
        self.current_user: Optional[Dict[str, Any]] = None
        self.session_token: Optional[str] = None
        self.connection: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
        self._connect_db()
        self._initialize_db()

    def _connect_db(self) -> None:
        try:
            self.connection = sqlite3.connect(
                self.db_name,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            self.connection.row_factory = sqlite3.Row
            self.cursor = self.connection.cursor()
        except sqlite3.Error as e:
            logging.error(f"Database connection error: {e}")
            raise DatabaseError(f"Failed to connect to database: {e}")

    # Context manager for database transactions
    @contextmanager
    def _transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        if not self.connection or not self.cursor:
            self._connect_db()
        try:
            yield self.cursor
            self.connection.commit()
        except sqlite3.Error as e:
            self.connection.rollback()
            logging.error(f"Transaction error: {e}")
            raise DatabaseError(f"Transaction failed: {e}")

    # Initialize database tables
    def _initialize_db(self) -> None:
        tables = [
            '''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,  -- Changed BOOLEAN to INTEGER
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )''',
            '''CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                encryption_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_id) REFERENCES users(id)
            )''',
            '''CREATE TABLE IF NOT EXISTS file_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                shared_with_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(file_id) REFERENCES files(id),
                FOREIGN KEY(shared_with_id) REFERENCES users(id)
            )''',
            '''CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                activity_type TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )''',
            '''CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )''',
            '''CREATE TABLE IF NOT EXISTS mfa_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )''',
            '''CREATE TABLE IF NOT EXISTS mfa_settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        secret_key TEXT NOT NULL,
                        email TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )'''
        ]

        try:
            with self._transaction() as cursor:
                for table in tables:
                    cursor.execute(table)
        except Exception as e:
            logging.error(f"Database initialization error: {e}")
            raise DatabaseError(f"Failed to initialize database: {e}")

    def get_current_user_id(self) -> Optional[int]:
        return self.current_user.get('id') if self.current_user else None

    def get_current_username(self) -> Optional[str]:
        return self.current_user.get('username') if self.current_user else None

    def _validate_username(self, username: str) -> Tuple[bool, str]:
        if not username:
            return False, "Username cannot be empty"
        if len(username) < 3 or len(username) > 30:
            return False, "Username must be between 3 and 30 characters"
        if not re.match("^[a-zA-Z0-9_]+$", username):
            return False, "Username can only contain letters, numbers, and underscores"

        return True, "Username is valid"

    def _validate_password(self, password: str) -> Tuple[bool, str]:
        if len(password) < self.min_password_length:
            return False, f"Password must be at least {self.min_password_length} characters"
        if not any(c.isupper() for c in password):
            return False, "Password must contain uppercase letters"
        if not any(c.islower() for c in password):
            return False, "Password must contain lowercase letters"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain numbers"
        if not any(c in string.punctuation for c in password):
            return False, "Password must contain special characters"
        return True, "Password is valid"

    # Generate a cryptographically secure salt
    def _generate_salt(self) -> str:
        return secrets.token_hex(self.salt_length)

    # Hash password using PBKDF2
    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            self.hash_algorithm,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            self._hash_iterations
        ).hex()

    def _log_activity(self, user_id: int, activity_type: str, details: Optional[str] = None) -> None:
        try:
            with self._transaction() as cursor:
                cursor.execute(
                    'INSERT INTO activity_log (user_id, activity_type, details) VALUES (?, ?, ?)',
                    (user_id, activity_type, details)
                )
        except sqlite3.Error as e:
            logging.error(f"Activity logging error: {e}")

    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        # Validate 
        valid_username, username_msg = self._validate_username(username)
        if not valid_username:
            return False, username_msg
        if self.cursor is None:
            raise DatabaseError("Database cursor not initialized")

        # Validate password
        valid, msg = self._validate_password(password)
        if not valid:
            return False, msg

        try:
            with self._transaction() as cursor:
                # Check if username exists
                cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if cursor.fetchone():
                    return False, "Username already exists"

                # Create new user
                salt = self._generate_salt()
                password_hash = self._hash_password(password, salt)
                cursor.execute(
                    'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                    (username, password_hash, salt)
                )
                user_id = cursor.lastrowid
                if user_id is None:
                    raise DatabaseError("Failed to get new user ID")
                self._log_activity(user_id, 'REGISTER', f"New user registration: {username}")
                return True, "Registration successful"

        except Exception as e:
            logging.error(f"Registration error: {e}")
            return False, "Registration failed"

    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[int]]:
        """Authenticate user"""
        if self.cursor is None:
            raise DatabaseError("Database cursor not initialized")

        try:
            with self._transaction() as cursor:
                cursor.execute(
                    '''SELECT id, username, password_hash, salt, failed_attempts,
                       locked_until, COALESCE(is_admin, 0) as is_admin
                    FROM users WHERE username = ?''',
                    (username,)
                )
                user = cursor.fetchone()

                if not user:
                    return False, "Invalid username or password", None

                user_dict = dict(user)

                # Check account lock
                locked_until = user_dict.get('locked_until')
                if locked_until is not None:
                    lock_time = datetime.fromisoformat(locked_until)
                    if datetime.now() < lock_time:
                        return False, "Account is locked. Please try again later", None

                # Verify password
                input_hash = self._hash_password(password, user['salt'])
                if secrets.compare_digest(input_hash, user['password_hash']):
                    # Check if MFA is enabled
                    cursor.execute(
                        'SELECT enabled FROM mfa_settings WHERE user_id = ?',
                        (user['id'],)
                    )
                    mfa_enabled = cursor.fetchone()

                    if mfa_enabled and mfa_enabled['enabled']:
                        return True, "MFA verification required", user['id']

                    # If MFA not enabled, complete login
                    self._complete_login(user_dict)
                    return True, "Login successful", None

                # Failed login handling
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= 5:
                    locked_until = datetime.now() + timedelta(minutes=30)
                    cursor.execute(
                        'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                        (failed_attempts, locked_until, user['id'])
                    )
                    return False, "Too many failed attempts. Account locked for 30 minutes", None

                cursor.execute(
                    'UPDATE users SET failed_attempts = ? WHERE id = ?',
                    (failed_attempts, user['id'])
                )
                return False, "Invalid username or password", None

        except Exception as e:
            logging.error(f"Login error: {e}")
            return False, "Login failed", None

    def _complete_login(self, user: Dict[str, Any]) -> None:
        """Complete the login process"""
        self.current_user = {
            'id': user['id'],
            'username': user['username'],
            'is_admin': bool(user['is_admin'])
        }
        self._log_activity(user['id'], 'LOGIN', "Successful login")

    def logout(self) -> Tuple[bool, str]:
        """Log out current user"""
        if self.current_user is None:
            return False, "No user is currently logged in"

        try:
            user_id = self.current_user['id']
            self._log_activity(user_id, 'LOGOUT', "User logged out")
            self.current_user = None
            self.session_token = None
            return True, "Logged out successfully"
        except Exception as e:
            logging.error(f"Logout error: {e}")
            return False, "Logout failed"

    def generate_password_reset_token(
        self,
        username: str
    ) -> Tuple[bool, str, Optional[str]]:
        """Generate a password reset token for a user"""
        if self.cursor is None:
            raise DatabaseError("Database cursor not initialized")

        try:
            with self._transaction() as cursor:
                cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
                user_data = cursor.fetchone()

                if not user_data:
                    return False, "User not found", None

                user_dict = dict(user_data)
                user_id = user_dict['id']
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)

                cursor.execute(
                    '''INSERT INTO password_reset_tokens
                    (user_id, token, expires_at) VALUES (?, ?, ?)''',
                    (user_id, token, expires_at)
                )

                self._log_activity(user_id, 'RESET_TOKEN_GENERATED')
                return True, "Reset token generated successfully", token

        except Exception as e:
            logging.error(f"Error generating reset token: {e}")
            return False, "Failed to generate reset token", None

    def use_password_reset_token(self, token: str, new_password: str) -> Tuple[bool, str]:
        # Validate new password
        valid, msg = self._validate_password(new_password)
        if not valid:
            return False, msg

        try:
            with self._transaction() as cursor:
                cursor.execute(
                    '''SELECT user_id, expires_at, used
                    FROM password_reset_tokens
                    WHERE token = ? AND used = 0''',
                    (token,)
                )
                token_data = cursor.fetchone()
                if not token_data:
                    return False, "Invalid or expired token"

                user_id = token_data['user_id']
                expires_at = token_data['expires_at']
                # Check if expires_at is already a datetime object
                if not isinstance(expires_at, datetime):
                    expires_at = datetime.fromisoformat(expires_at)

                if datetime.now() > expires_at:
                    return False, "Token has expired"

                cursor.execute('SELECT salt FROM users WHERE id = ?', (user_id,))
                salt_data = cursor.fetchone()
                if not salt_data:
                    return False, "User not found"

                new_password_hash = self._hash_password(new_password, salt_data['salt'])
                cursor.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (new_password_hash, user_id)
                )
                cursor.execute(
                    'UPDATE password_reset_tokens SET used = 1 WHERE token = ?',
                    (token,)
                )

                self._log_activity(user_id, 'PASSWORD_RESET_COMPLETE')
                return True, "Password reset successful"

        except Exception as e:
            logging.error(f"Error using reset token: {e}", exc_info=True)
            return False, "Failed to reset password"


    def reset_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """Reset user's password"""
        if self.cursor is None:
            raise DatabaseError("Database cursor not initialized")

        valid, msg = self._validate_password(new_password)
        if not valid:
            return False, msg

        try:
            with self._transaction() as cursor:
                cursor.execute('SELECT id, salt FROM users WHERE username = ?', (username,))
                user_data = cursor.fetchone()

                if not user_data:
                    return False, "User not found"

                new_password_hash = self._hash_password(new_password, user_data['salt'])
                cursor.execute(
                    '''UPDATE users
                    SET password_hash = ?,
                        failed_attempts = 0,
                        locked_until = NULL
                    WHERE id = ?''',
                    (new_password_hash, user_data['id'])
                )

                self._log_activity(user_data['id'], 'PASSWORD_RESET')
                return True, "Password reset successful"

        except Exception as e:
            logging.error(f"Password reset error: {e}")
            return False, "Failed to reset password"

    def is_admin(self, user_id: int) -> bool:
        """Check if user has admin privileges"""
        if self.cursor is None:
            return False

        try:
            with self._transaction() as cursor:
                cursor.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
                result = cursor.fetchone()
                return bool(result and result['is_admin'])
        except Exception as e:
            logging.error(f"Admin check error: {e}")
            return False

    def close(self) -> None:
        """Close database connection"""
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception as e:
                logging.error(f"Error closing database connection: {e}")
            finally:
                self.connection = None
                self.cursor = None

    def __enter__(self) -> 'UserManager':
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
