import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configure logging similar to userManager.py
logging.basicConfig(level=logging.INFO)

"""
encryption_module.py

This module provides functions for client-side encryption and decryption using AES-GCM.
It includes functions to generate, save, and load an AES key, as well as to encrypt and decrypt files.
The design is similar in style to userManager.py, with clear docstrings, logging, and error handling.
"""

# Constants for AES-GCM
NONCE_SIZE = 12  # 96 bits (recommended for AES-GCM)

def generate_key() -> bytes:
    """Generate a new 256-bit AES key."""
    try:
        key = AESGCM.generate_key(bit_length=256)
        logging.info("AES key generated successfully.")
        return key
    except Exception as e:
        logging.error("Failed to generate AES key: %s", e)
        raise

def save_key(key: bytes, filename: str) -> None:
    """
    Save the encryption key to a file.
    This file should be kept secure on the client machine.
    """
    try:
        with open(filename, "wb") as f:
            f.write(key)
        logging.info("Encryption key saved to %s", filename)
    except Exception as e:
        logging.error("Failed to save encryption key: %s", e)
        raise

def load_key(filename: str) -> bytes:
    """
    Load the encryption key from a file.
    Raises an exception if the file cannot be read.
    """
    try:
        with open(filename, "rb") as f:
            key = f.read()
        logging.info("Encryption key loaded from %s", filename)
        return key
    except Exception as e:
        logging.error("Failed to load encryption key: %s", e)
        raise

def encrypt_file(input_file: str, output_file: str, key: bytes) -> None:
    """
    Encrypt the contents of input_file using AES-GCM and write the result to output_file.
    A random nonce is generated and prepended to the ciphertext.
    """
    try:
        with open(input_file, "rb") as f:
            plaintext = f.read()
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        with open(output_file, "wb") as f:
            f.write(nonce + ciphertext)
        logging.info("File '%s' encrypted successfully to '%s'.", input_file, output_file)
    except Exception as e:
        logging.error("Encryption failed for file '%s': %s", input_file, e)
        raise

def decrypt_file(input_file: str, output_file: str, key: bytes) -> None:
    """
    Decrypt the contents of input_file (which should contain nonce + ciphertext)
    and write the plaintext to output_file.
    """
    try:
        with open(input_file, "rb") as f:
            data = f.read()
        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        with open(output_file, "wb") as f:
            f.write(plaintext)
        logging.info("File '%s' decrypted successfully to '%s'.", input_file, output_file)
    except Exception as e:
        logging.error("Decryption failed for file '%s': %s", input_file, e)
        raise
