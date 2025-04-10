import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from typing import Tuple, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class EncryptionError(Exception):
    """Custom exception for encryption operations"""
    pass

class Encryptor:
    def __init__(self):
        self.KEY_LENGTH = 32  # 256 bits
        self.NONCE_LENGTH = 12  # 96 bits
        self.SALT_LENGTH = 16  # 128 bits

    def generate_key(self) -> bytes:
        """Generate a new encryption key"""
        try:
            return AESGCM.generate_key(bit_length=256)
        except Exception as e:
            logging.error(f"Key generation error: {e}")
            raise EncryptionError("Failed to generate encryption key")

    def derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive encryption key from password"""
        try:
            if salt is None:
                salt = os.urandom(self.SALT_LENGTH)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_LENGTH,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            return key, salt
        except Exception as e:
            logging.error(f"Key derivation error: {e}")
            raise EncryptionError("Failed to derive key")

    def encrypt_file(self, file_path: str, key: bytes) -> Tuple[str, bytes]:
        """Encrypt a file and return the encrypted data and nonce"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            aesgcm = AESGCM(key)
            nonce = os.urandom(self.NONCE_LENGTH)
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            # Combine nonce and encrypted data
            complete_data = nonce + encrypted_data

            # Encode for storage
            encoded_data = b64encode(complete_data).decode('utf-8')
            return encoded_data, nonce

        except Exception as e:
            logging.error(f"File encryption error: {e}")
            raise EncryptionError(f"Failed to encrypt file: {e}")

    def decrypt_file(self, encrypted_data: str, key: bytes) -> bytes:
        """Decrypt encrypted data using the provided key"""
        try:
            # Decode from storage format
            complete_data = b64decode(encrypted_data.encode('utf-8'))

            # Split nonce and ciphertext
            nonce = complete_data[:self.NONCE_LENGTH]
            ciphertext = complete_data[self.NONCE_LENGTH:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_data

        except Exception as e:
            logging.error(f"File decryption error: {e}")
            raise EncryptionError(f"Failed to decrypt file: {e}")

    def encrypt_file_content(self, content: bytes, key: bytes) -> Tuple[str, bytes]:
            """Encrypt file content and return the encrypted data and nonce"""
            try:
                aesgcm = AESGCM(key)
                nonce = os.urandom(self.NONCE_LENGTH)
                encrypted_data = aesgcm.encrypt(nonce, content, None)

                # Combine nonce and encrypted data
                complete_data = nonce + encrypted_data

                # Encode for storage
                encoded_data = b64encode(complete_data).decode('utf-8')
                return encoded_data, nonce

            except Exception as e:
                logging.error(f"Content encryption error: {e}")
                raise EncryptionError(f"Failed to encrypt content: {e}")
