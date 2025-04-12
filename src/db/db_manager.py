# db_manager.py
import sqlite3
import logging
from contextlib import contextmanager
from ..config import Config, DatabaseError

logger = logging.getLogger(__name__)

class DbManager:
    def __init__(self, db_name: str = Config.DATABASE_NAME):
        self.db_name = db_name
        self.connection = None
        self.cursor = None
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
            logger.error(f"Database connection error: {e}")
            raise DatabaseError(f"Failed to connect to database: {e}")

    @contextmanager
    def transaction(self):
        """Context manager for a transaction. Commits on success, rollbacks on sqlite errors."""
        try:
            yield self.cursor
            self.connection.commit()
        except sqlite3.Error as e:
            self.connection.rollback()
            logger.error(f"Transaction error: {e}")
            raise DatabaseError(f"Transaction failed: {e}")

    def _initialize_db(self) -> None:
        tables = [
            '''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
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
            with self.transaction() as cur:
                for ddl in tables:
                    cur.execute(ddl)
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise DatabaseError(f"Failed to initialize database: {e}")

    def close(self) -> None:
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                logger.error(f"Error closing DB connection: {e}")
            finally:
                self.connection = None
                self.cursor = None
