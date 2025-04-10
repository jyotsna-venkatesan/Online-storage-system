class Config:
    DATABASE_NAME = 'secure_storage.db'
    STORAGE_DIR = 'secure_storage'
    MIN_PASSWORD_LENGTH = 8
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 30  # minutes
    TOKEN_EXPIRY = 60  # minutes
    MFA_ENABLED = True
