import sqlite3
import hashlib
import re
from getpass import getpass
import secrets
import string
from typing import Optional, Tuple, Dict, Any, Union, List
from datetime import datetime

class UserManager:
    def __init__(self, db_name: str = 'secure_storage.db') -> None:
        self.db_name: str = db_name
        self.conn: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None

        # Security parameters
        self.min_password_length: int = 7
        self.salt_length: int = 32
        self._hash_iterations: int = 100000
        self.hash_algorithm: str = 'sha256'

        self.current_user: Optional[Dict[str, Any]] = None
        self.session_token: Optional[str] = None

        self._initialize_db()

    def _ensure_connection(self) -> None:
        """Ensure database connection is active"""
        if self.conn is None or self.cursor is None:
            self._initialize_db()

    def _initialize_db(self) -> None:
        """Initialize database if they doesn't exist"""
        try:
            self.conn = sqlite3.connect(self.db_name)
            self.cursor = self.conn.cursor()

            # Create tables
            self._execute_sql('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL
                )
            ''')

            self._execute_sql('''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used INTEGER DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            self._execute_sql('''
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    activity_type TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    details TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            self._commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            raise

    def _execute_sql(self, query: str, params: Union[Tuple, List] = ()) -> None:
        """SQL with null checks"""
        if self.cursor is None:
            raise RuntimeError("Database cursor not initialized")
        self.cursor.execute(query, params)

    def _fetchone(self) -> Optional[Tuple]:
        """Fetch one row with null checks"""
        if self.cursor is None:
            raise RuntimeError("Database cursor not initialized")
        return self.cursor.fetchone()

    def _commit(self) -> None:
        """Commit with null checks"""
        if self.conn is None:
            raise RuntimeError("Database connection not initialized")
        self.conn.commit()

    def _rollback(self) -> None:
        """Rollback with null checks"""
        if self.conn is None:
            raise RuntimeError("Database connection not initialized")
        self.conn.rollback()

    def _generate_salt(self) -> str:
        """Generate a cryptographically secure random salt"""
        return secrets.token_hex(self.salt_length)

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash the password with PBKDF2-HMAC
        Combines password + salt, then hashes repeatedly (100,000 times) to make brute-force attacks slower.
        Returns a secure hexadecimal hash string.
        """
        return hashlib.pbkdf2_hmac(
            self.hash_algorithm,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            self._hash_iterations
        ).hex()

    def _validate_username(self, username: str) -> Tuple[bool, str]:
        """Validate username format and check for SQL injection"""
        if not username:
            return False, "Username cannot be empty"

        if len(username) > 50:
            return False, "Username too long (max 50 characters)"

        if re.search(r'[\'\";\\]', username):
            return False, "Username contains invalid characters"

        return True, ""

    def _validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
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

    def _log_activity(self, user_id: int, activity_type: str, ip_address: Optional[str] = None, details: Optional[str] = None) -> None:
        """Log user activity for auditing"""
        try:
            self._execute_sql('''
                INSERT INTO activity_log (user_id, activity_type, ip_address, details)
                VALUES (?, ?, ?, ?)
            ''', (user_id, activity_type, ip_address, details))
            self._commit()
        except sqlite3.Error as e:
            print(f"Failed to log activity: {e}")

    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Register a new user with secure password storage"""
        try:
            # Validate username
            valid, msg = self._validate_username(username)
            if not valid:
                return False, msg

            # Validate password
            valid, msg = self._validate_password(password)
            if not valid:
                return False, msg

            # Check if username exists
            self._execute_sql('SELECT id FROM users WHERE username = ?', (username,))
            if self._fetchone():
                return False, "Username already exists"

            # Generate salt and hash password
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)

            # Insert new user
            self._execute_sql('''
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            ''', (username, password_hash, salt))
            self._commit()

            # Log registration activity
            if self.cursor:
                user_id = self.cursor.lastrowid
                if user_id:
                    self._log_activity(user_id, 'REGISTER')

            return True, "User registered successfully"
        except sqlite3.Error as e:
            return False, f"Registration failed: {e}"

    def login(self, username: str, password: str, ip_address: Optional[str] = None) -> Tuple[bool, str]:
        """Authenticate a user"""
        try:
            # Check if account is locked
            self._execute_sql('''
                SELECT id, password_hash, salt, failed_attempts, locked_until
                FROM users
                WHERE username = ?
            ''', (username,))
            user_data = self._fetchone()

            if not user_data:
                return False, "Invalid username or password"

            user_id, stored_hash, salt, failed_attempts, locked_until = user_data

            # Check if account is locked
            if locked_until:
                if datetime.now() < datetime.strptime(locked_until, '%Y-%m-%d %H:%M:%S'):
                    return False, "Account is temporarily locked due to too many failed attempts"
                else:
                    # Unlock the account
                    self._execute_sql('''
                        UPDATE users
                        SET locked_until = NULL, failed_attempts = 0
                        WHERE id = ?
                    ''', (user_id,))
                    self._commit()

            # Verify password
            input_hash = self._hash_password(password, salt)
            if secrets.compare_digest(input_hash, stored_hash):
                # Successful login
                self._execute_sql('''
                    UPDATE users
                    SET last_login = CURRENT_TIMESTAMP, failed_attempts = 0
                    WHERE id = ?
                ''', (user_id,))
                self._commit()

                # Generate session token
                self.session_token = secrets.token_urlsafe(32)
                self.current_user = {
                    'id': user_id,
                    'username': username,
                    'token': self.session_token
                }

                # Log successful login
                self._log_activity(user_id, 'LOGIN_SUCCESS', ip_address)

                return True, "Login successful"
            else:
                # Failed login
                self._execute_sql('''
                    UPDATE users
                    SET failed_attempts = failed_attempts + 1
                    WHERE id = ?
                ''', (user_id,))

                # Lock account after 5 failed attempts for 30 minutes
                if failed_attempts + 1 >= 5:
                    self._execute_sql('''
                        UPDATE users
                        SET locked_until = datetime(CURRENT_TIMESTAMP, '+30 minutes')
                        WHERE id = ?
                    ''', (user_id,))

                self._commit()
                self._log_activity(user_id, 'LOGIN_FAILURE', ip_address, "Invalid password")
                return False, "Invalid username or password"
        except sqlite3.Error as e:
            return False, f"Login failed: {e}"

    def logout(self) -> Tuple[bool, str]:
        """Log out the current user"""
        if self.current_user:
            user_id = self.current_user.get('id')
            if user_id:
                self._log_activity(user_id, 'LOGOUT')
            self.current_user = None
            self.session_token = None
            return True, "Logged out successfully"
        return False, "No user is currently logged in"

    def reset_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """Reset a user's password"""
        try:
            # Validate new password
            valid, msg = self._validate_password(new_password)
            if not valid:
                return False, msg

            # Check if user exists
            self._execute_sql('SELECT id, salt FROM users WHERE username = ?', (username,))
            user_data = self._fetchone()

            if not user_data:
                return False, "User not found"

            user_id, salt = user_data

            # Generate new password hash
            new_hash = self._hash_password(new_password, salt)

            # Update password
            self._execute_sql('''
                UPDATE users
                SET password_hash = ?, failed_attempts = 0, locked_until = NULL
                WHERE id = ?
            ''', (new_hash, user_id))
            self._commit()

            # Log password reset
            self._log_activity(user_id, 'PASSWORD_RESET')

            return True, "Password reset successfully"
        except sqlite3.Error as e:
            return False, f"Password reset failed: {e}"

    def generate_password_reset_token(self, username: str) -> Tuple[bool, str, Optional[str]]:
        """Generate a secure password reset token"""
        try:
            # Check if user exists
            self._execute_sql('SELECT id FROM users WHERE username = ?', (username,))
            user_data = self._fetchone()

            if not user_data:
                return False, "User not found", None

            user_id = user_data[0]

            # Generate token (32 random bytes)
            token = secrets.token_urlsafe(32)

            # Set expiration (1 hour from now)
            self._execute_sql('''
                INSERT INTO password_reset_tokens (user_id, token, expires_at)
                VALUES (?, ?, datetime(CURRENT_TIMESTAMP, '+1 hour'))
            ''', (user_id, token))
            self._commit()

            # Log token generation
            self._log_activity(user_id, 'PASSWORD_RESET_TOKEN_GENERATED')

            return True, "Token generated successfully", token
        except sqlite3.Error as e:
            return False, f"Token generation failed: {e}", None

    def use_password_reset_token(self, token: str, new_password: str) -> Tuple[bool, str]:
        """Use a password reset token to set a new password"""
        try:
            # Validate new password
            valid, msg = self._validate_password(new_password)
            if not valid:
                return False, msg

            # Clean the input token
            clean_token = token.strip()

            # Check token validity
            self._execute_sql('''
                SELECT user_id, expires_at, used
                FROM password_reset_tokens
                WHERE token = ?
            ''', (clean_token,))
            token_data = self._fetchone()

            if not token_data:
                # Secure debugging - only log metadata, not actual tokens
                self._log_activity(-1, 'TOKEN_VALIDATION_FAILED',
                                   details="Token not found in database")
                return False, "Invalid or expired token"

            user_id, expires_at, used = token_data

            # Check if token is used or expired
            if used:
                self._log_activity(user_id, 'TOKEN_ALREADY_USED')
                return False, "This reset link has already been used"

            if datetime.utcnow() > datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S'):
                self._log_activity(user_id, 'TOKEN_EXPIRED')
                return False, "This reset link has expired"

            # Get user's salt
            self._execute_sql('SELECT salt FROM users WHERE id = ?', (user_id,))
            salt_data = self._fetchone()
            if not salt_data:
                return False, "User not found"
            salt = salt_data[0]

            # Generate new password hash
            new_hash = self._hash_password(new_password, salt)

            # Update password and mark token as used
            self._execute_sql('BEGIN TRANSACTION')
            self._execute_sql('''
                UPDATE users
                SET password_hash = ?, failed_attempts = 0, locked_until = NULL
                WHERE id = ?
            ''', (new_hash, user_id))

            self._execute_sql('''
                UPDATE password_reset_tokens
                SET used = 1
                WHERE token = ?
            ''', (clean_token,))

            self._commit()

            # Log password reset via token
            self._log_activity(user_id, 'PASSWORD_RESET_VIA_TOKEN')

            return True, "Password reset successfully"
        except sqlite3.Error as e:
            self._rollback()
            user_id = locals().get('user_id', -1)  # Use -1 instead of None
            self._log_activity(user_id, 'PASSWORD_RESET_ERROR', details=str(e))
            return False, "Password reset failed due to system error"

    def close(self) -> None:
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None

def main_menu():
    """Command line interface for user management"""
    user_manager = UserManager()

    while True:
        print("\nSecure Online Storage - User Management")
        print("1. Register")
        print("2. Login")
        print("3. Reset Password")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            # Registration
            username = input("Enter username: ")
            password = getpass("Enter password (requirements: 7+ chars with uppercase, lowercase, number & symbol): ")
            confirm_password = getpass("Confirm password: ")

            if password != confirm_password:
                print("Passwords do not match!")
                continue

            success, message = user_manager.register_user(username, password)
            print(message)

        elif choice == '2':
            # Login
            username = input("Enter username: ")
            password = getpass("Enter password: ")

            success, message = user_manager.login(username, password)
            if success:
                print(message)
                # Here you would typically enter the main application
                # For now, we'll just show a simple logged-in menu
                logged_in_menu(user_manager)
            else:
                print(message)

        elif choice == '3':
            # Password reset
            username = input("Enter username: ")
            success, message, token = user_manager.generate_password_reset_token(username)
            if success:
                print(f"{message}. Your reset token is: {token}")
                token_input = input("Enter the reset token you received: ")
                new_password = getpass("Enter new password: ")
                confirm_password = getpass("Confirm new password: ")

                if new_password != confirm_password:
                    print("Passwords do not match!")
                    continue

                success, message = user_manager.use_password_reset_token(token_input, new_password)
                print(message)
            else:
                print(message)

        elif choice == '4':
            # Exit
            user_manager.close()
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

def logged_in_menu(user_manager):
    """Menu for logged in users"""
    while True:
        print("\nWelcome to Secure Online Storage")
        print("1. Logout")
        print("2. Change Password")

        choice = input("Enter your choice: ")

        if choice == '1':
            success, message = user_manager.logout()
            print(message)
            break
        elif choice == '2':
            current_password = getpass("Enter current password: ")
            new_password = getpass("Enter new password: ")
            confirm_password = getpass("Confirm new password: ")

            if new_password != confirm_password:
                print("Passwords do not match!")
                continue

            # Verify current password first
            username = user_manager.current_user['username']
            success, message = user_manager.login(username, current_password)
            if not success:
                print("Current password is incorrect!")
                continue

            # Reset password
            success, message = user_manager.reset_password(username, new_password)
            print(message)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
