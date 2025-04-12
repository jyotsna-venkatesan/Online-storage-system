import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from typing import Tuple, Optional

# Import encryption configuration from config
from .config import Config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """Custom exception for encryption operations."""
    pass

class Encryptor:
    def __init__(self):
        # Use configuration values so that they can be tuned externally.
        self.KEY_LENGTH = Config.KEY_LENGTH   # in bytes
        self.NONCE_LENGTH = Config.NONCE_LENGTH
        self.SALT_LENGTH = Config.SALT_LENGTH
        self.ITERATIONS = Config.ITERATIONS

    def generate_key(self) -> bytes:
        """Generate a new encryption key."""
        try:
            return AESGCM.generate_key(bit_length=self.KEY_LENGTH * 8)
        except Exception as e:
            logger.error(f"Key generation error: {e}", exc_info=True)
            raise EncryptionError("Failed to generate encryption key")

    def derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive an encryption key from the given password."""
        try:
            if salt is None:
                salt = os.urandom(self.SALT_LENGTH)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_LENGTH,
                salt=salt,
                iterations=self.ITERATIONS,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            return key, salt
        except Exception as e:
            logger.error(f"Key derivation error: {e}", exc_info=True)
            raise EncryptionError("Failed to derive key")

    def _encrypt_bytes(self, data: bytes, key: bytes) -> Tuple[str, bytes]:
        """
        Encrypt the provided bytes using AES-GCM.
        Returns a tuple of (encoded encrypted data, nonce).
        """
        try:
            aesgcm = AESGCM(key)
            nonce = os.urandom(self.NONCE_LENGTH)
            encrypted_data = aesgcm.encrypt(nonce, data, None)
            # Prepend nonce to the ciphertext for storage.
            complete_data = nonce + encrypted_data
            encoded_data = b64encode(complete_data).decode('utf-8')
            return encoded_data, nonce
        except Exception as e:
            logger.error(f"Encryption error: {e}", exc_info=True)
            raise EncryptionError(f"Failed to encrypt data: {e}")

    def encrypt_file(self, file_path: str, key: bytes) -> Tuple[str, bytes]:
        """
        Encrypt an entire file.
        Reads the file content and delegates encryption to _encrypt_bytes.
        Returns a tuple of (encoded encrypted data, nonce).
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            return self._encrypt_bytes(data, key)
        except Exception as e:
            logger.error(f"File encryption error: {e}", exc_info=True)
            raise EncryptionError(f"Failed to encrypt file: {e}")

    def encrypt_file_content(self, content: bytes, key: bytes) -> Tuple[str, bytes]:
        """
        Encrypt file content provided as bytes.
        Delegates encryption to _encrypt_bytes.
        Returns a tuple of (encoded encrypted data, nonce).
        """
        try:
            return self._encrypt_bytes(content, key)
        except Exception as e:
            logger.error(f"Content encryption error: {e}", exc_info=True)
            raise EncryptionError(f"Failed to encrypt content: {e}")

    def decrypt_file(self, encrypted_data: str, key: bytes) -> bytes:
        """
        Decrypt encrypted data using the provided key.
        Assumes the encrypted data was encoded with b64encode() after concatenating nonce and ciphertext.
        """
        try:
            complete_data = b64decode(encrypted_data.encode('utf-8'))
            nonce = complete_data[:self.NONCE_LENGTH]
            ciphertext = complete_data[self.NONCE_LENGTH:]
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_data
        except Exception as e:
            logger.error(f"File decryption error: {e}", exc_info=True)
            raise EncryptionError(f"Failed to decrypt file: {e}")
