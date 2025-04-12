import hashlib
import re
import secrets
import string
import logging
from typing import Optional, Tuple, Dict, Any, Union, List, TypedDict, Protocol
from datetime import datetime, timedelta

from ..config import Config, DatabaseError
from ..db.db_manager import DbManager

logger = logging.getLogger(__name__)

class DatabaseCursor(Protocol):
    def execute(self, query: str, params: Union[Tuple[Any, ...], Dict[str, Any]] = ...) -> Any: ...
    def fetchone(self) -> Optional[Any]: ...
    def fetchall(self) -> List[Any]: ...
    @property
    def lastrowid(self) -> int: ...

class UserData(TypedDict):
    id: int
    username: str
    is_admin: bool
    password_hash: str
    salt: str
    failed_attempts: int
    locked_until: Optional[str]

class UserManager:
    def __init__(self, db_manager: DbManager) -> None:
        self.db = db_manager
        self.cursor: DatabaseCursor = db_manager.cursor
        self.min_password_length = Config.MIN_PASSWORD_LENGTH
        self.salt_length = 32
        self._hash_iterations = 100000
        self.hash_algorithm = 'sha256'
        self.current_user: Optional[Dict[str, Any]] = None
        self.session_token: Optional[str] = None

    def get_current_user_id(self) -> Optional[int]:
        return self.current_user.get('id') if self.current_user else None

    def get_current_username(self) -> Optional[str]:
        return self.current_user.get('username') if self.current_user else None

    def _validate_username(self, username: str) -> Tuple[bool, str]:
        if not username:
            return False, "Username cannot be empty"
        if len(username) < 3 or len(username) > 30:
            return False, "Username must be between 3 and 30 characters"
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
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

    def _generate_salt(self) -> str:
        return secrets.token_hex(self.salt_length)

    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            self.hash_algorithm,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            self._hash_iterations
        ).hex()

    def _log_activity(self, user_id: int, activity_type: str, details: Any = None) -> None:
        try:
            with self.db.transaction() as cur:
                cur.execute(
                    'INSERT INTO activity_log (user_id, activity_type, details) VALUES (?, ?, ?)',
                    (user_id, activity_type, details)
                )
        except Exception as e:
            logger.error(f"Activity logging error: {e}")

    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        valid_username, username_msg = self._validate_username(username)
        if not valid_username:
            return False, username_msg

        valid_pw, pw_msg = self._validate_password(password)
        if not valid_pw:
            return False, pw_msg

        try:
            with self.db.transaction() as cur:
                cur.execute('SELECT 1 FROM users WHERE username = ?', (username,))
                if cur.fetchone():
                    return False, "Username already exists"

                salt = self._generate_salt()
                password_hash = self._hash_password(password, salt)
                cur.execute(
                    'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                    (username, password_hash, salt)
                )
                user_id = cur.lastrowid
            self._log_activity(user_id, 'REGISTER', f"New user: {username}")
            return True, "Registration successful"
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False, "Registration failed"

    def login(self, username: str, password: str) -> Tuple[bool, str, Optional[int]]:
        """Authenticate user, enforce lockout, and trigger MFA if enabled."""
        try:
            # 1) Fetch the user row
            with self.db.transaction() as cur:
                cur.execute(
                    '''SELECT id, username, password_hash, salt,
                              failed_attempts, locked_until,
                              COALESCE(is_admin,0) as is_admin
                       FROM users WHERE username = ?''',
                    (username,)
                )
                row = cur.fetchone()

            if not row:
                return False, "Invalid username or password", None

            user = dict(row)

            # 2) Check lockout
            locked_until = user.get('locked_until')
            if locked_until:
                # If it's a string, parse it; if it's already datetime, use it directly
                if isinstance(locked_until, str):
                    lock_time = datetime.fromisoformat(locked_until)
                else:
                    lock_time = locked_until

                if datetime.now() < lock_time:
                    return False, f"Account is locked until {lock_time}", None

            # 3) Verify password
            hashed_input = self._hash_password(password, user['salt'])
            if secrets.compare_digest(hashed_input, user['password_hash']):
                # Reset failed attempts on successful password
                with self.db.transaction() as cur:
                    cur.execute(
                        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
                        (user['id'],)
                    )

                # 4) Check for MFA
                with self.db.transaction() as cur:
                    cur.execute(
                        'SELECT enabled FROM mfa_settings WHERE user_id = ?',
                        (user['id'],)
                    )
                    mfa_row = cur.fetchone()

                if mfa_row and mfa_row['enabled']:
                    return True, "MFA verification required", user['id']

                # 5) Complete login
                self._complete_login(user)
                return True, "Login successful", None

            # 6) Handle failed password
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= Config.MAX_LOGIN_ATTEMPTS:
                lock_time = datetime.now() + timedelta(minutes=Config.LOCKOUT_DURATION)
                with self.db.transaction() as cur:
                    cur.execute(
                        'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                        (user['failed_attempts'], lock_time, user['id'])
                    )
                return False, f"Too many failed attempts. Account locked until {lock_time}", None

            with self.db.transaction() as cur:
                cur.execute(
                    'UPDATE users SET failed_attempts = ? WHERE id = ?',
                    (user['failed_attempts'], user['id'])
                )
            return False, "Invalid username or password", None

        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            return False, "Login failed", None

    def _complete_login(self, user: Dict[str, Any]) -> None:
        self.current_user = {
            'id': user['id'],
            'username': user['username'],
            'is_admin': bool(user['is_admin'])
        }
        self._log_activity(user['id'], 'LOGIN', "Successful login")

    def logout(self) -> Tuple[bool, str]:
        if not self.current_user:
            return False, "No user is logged in"
        user_id = self.current_user['id']
        self._log_activity(user_id, 'LOGOUT', "User logged out")
        self.current_user = None
        return True, "Logged out successfully"

    def generate_password_reset_token(
        self, username: str
    ) -> Tuple[bool, str, Optional[str]]:
        try:
            with self.db.transaction() as cur:
                cur.execute('SELECT id FROM users WHERE username = ?', (username,))
                row = cur.fetchone()
                if not row:
                    return False, "User not found", None
                user_id = row['id']
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(minutes=Config.TOKEN_EXPIRY)
                cur.execute(
                    'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                    (user_id, token, expires_at)
                )
            self._log_activity(user_id, 'RESET_TOKEN_GENERATED')
            return True, "Reset token generated successfully", token
        except Exception as e:
            logger.error(f"Error generating reset token: {e}")
            return False, "Failed to generate reset token", None

    def use_password_reset_token(self, token: str, new_password: str) -> Tuple[bool, str]:
        valid, msg = self._validate_password(new_password)
        if not valid:
            return False, msg
        try:
            with self.db.transaction() as cur:
                cur.execute(
                    'SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = ? AND used = 0',
                    (token,)
                )
                row = cur.fetchone()
                if not row:
                    return False, "Invalid or expired token"
                user_id = row['user_id']
                expires_at = row['expires_at']
                if not isinstance(expires_at, datetime):
                    expires_at = datetime.fromisoformat(expires_at)
                if datetime.now() > expires_at:
                    return False, "Token has expired"
                cur.execute('SELECT salt FROM users WHERE id = ?', (user_id,))
                salt_row = cur.fetchone()
                if not salt_row:
                    return False, "User not found"
                salt = salt_row['salt']
                new_hash = self._hash_password(new_password, salt)
                cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
                cur.execute('UPDATE password_reset_tokens SET used = 1 WHERE token = ?', (token,))
            self._log_activity(user_id, 'PASSWORD_RESET_COMPLETE')
            return True, "Password reset successful"
        except Exception as e:
            logger.error(f"Error using reset token: {e}")
            return False, "Failed to reset password"

    def reset_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        valid, msg = self._validate_password(new_password)
        if not valid:
            return False, msg
        try:
            with self.db.transaction() as cur:
                cur.execute('SELECT id, salt FROM users WHERE username = ?', (username,))
                row = cur.fetchone()
                if not row:
                    return False, "User not found"
                user_id = row['id']
                salt = row['salt']
                new_hash = self._hash_password(new_password, salt)
                cur.execute(
                    'UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?',
                    (new_hash, user_id)
                )
            self._log_activity(user_id, 'PASSWORD_RESET')
            return True, "Password reset successful"
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return False, "Failed to reset password"

    def is_admin(self, user_id: int) -> bool:
        try:
            with self.db.transaction() as cur:
                cur.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
                row = cur.fetchone()
                return bool(row and row['is_admin'])
        except Exception as e:
            logger.error(f"Admin check error: {e}")
            return False

    def unlock_account(self, username: str) -> Tuple[bool, str]:
        try:
            with self.db.transaction() as cursor:
                cursor.execute('SELECT id, locked_until FROM users WHERE username = ?', (username,))
                user = cursor.fetchone()
                if not user:
                    return False, "User not found"

                if not user['locked_until']:
                    return False, "User account is not locked"

                cursor.execute(
                    'UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE username = ?',
                    (username,)
                )
            self._log_activity(user['id'], 'ADMIN_UNLOCK', f"Account for {username} was unlocked")
            return True, "Account unlocked successfully"
        except Exception as e:
            logger.error(f"Unlock error: {e}", exc_info=True)
            return False, "Failed to unlock account"


    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> 'UserManager':
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
