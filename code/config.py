import logging

class Config:
    DATABASE_NAME = 'secure_storage.db'
    STORAGE_DIR = 'secure_storage'
    MIN_PASSWORD_LENGTH = 8
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 30  # minutes
    TOKEN_EXPIRY = 60  # minutes
    MFA_ENABLED = True

    KEY_LENGTH = 32       # 256 bits
    NONCE_LENGTH = 12     # 96 bits
    SALT_LENGTH = 16      # 128 bits
    ITERATIONS = 100000

    # Logging settings
    LOGGING_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOGGING_LEVEL = logging.INFO

def setup_logging() -> None:
    """Setup logging configuration once at application startup."""
    logging.basicConfig(level=Config.LOGGING_LEVEL, format=Config.LOGGING_FORMAT)