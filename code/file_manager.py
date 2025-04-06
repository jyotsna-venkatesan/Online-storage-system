import os
import shutil
import logging
from encryption_module import generate_key, save_key, load_key, encrypt_file, decrypt_file

# Configure logging
logging.basicConfig(level=logging.INFO)

# Constants for the local encryption key file and simulated server storage directory.
KEY_FILE = "encryption_key.bin"
SERVER_STORAGE_DIR = "server_storage"

def init_encryption_key() -> bytes:
    """
    Load the local encryption key if available; otherwise, generate a new key and save it.
    """
    try:
        if not os.path.exists(KEY_FILE):
            key = generate_key()
            save_key(key, KEY_FILE)
            print("Encryption key generated and saved locally.")
        else:
            key = load_key(KEY_FILE)
            print("Encryption key loaded from local storage.")
        return key
    except Exception as e:
        logging.error("Error initializing encryption key: %s", e)
        raise Exception("Encryption key initialization failed.")

def ensure_server_storage():
    """
    Ensure that the simulated server storage directory exists.
    """
    if not os.path.exists(SERVER_STORAGE_DIR):
        os.makedirs(SERVER_STORAGE_DIR)

def upload_file(key: bytes) -> None:
    """
    Encrypt a file locally and simulate an upload by copying it into the server storage directory.
    """
    local_file = input("Enter the path of the file to upload: ").strip()
    if not os.path.isfile(local_file):
        print("File does not exist.")
        return

    encrypted_file = local_file + ".enc"
    try:
        encrypt_file(local_file, encrypted_file, key)
        print(f"File '{local_file}' encrypted as '{encrypted_file}'.")
    except Exception as e:
        logging.error("Encryption error: %s", e)
        print("Failed to encrypt file.")
        return

    ensure_server_storage()
    server_file_path = os.path.join(SERVER_STORAGE_DIR, os.path.basename(encrypted_file))
    try:
        shutil.copy(encrypted_file, server_file_path)
        print(f"Encrypted file uploaded to server storage as '{server_file_path}'.")
    except Exception as e:
        logging.error("Error uploading file: %s", e)
        print("Failed to upload file.")

def download_file(key: bytes) -> None:
    """
    Simulate downloading an encrypted file from server storage and decrypt it locally.
    """
    ensure_server_storage()
    try:
        files = os.listdir(SERVER_STORAGE_DIR)
    except Exception as e:
        logging.error("Error accessing server storage: %s", e)
        print("Failed to access server storage.")
        return

    if not files:
        print("No files available on the server.")
        return

    print("Files available on the server:")
    for idx, filename in enumerate(files):
        print(f"{idx + 1}. {filename}")

    try:
        choice = int(input("Enter the number of the file to download: ").strip())
        if choice < 1 or choice > len(files):
            print("Invalid selection.")
            return
    except ValueError:
        print("Invalid input.")
        return

    server_file_path = os.path.join(SERVER_STORAGE_DIR, files[choice - 1])
    downloaded_file = "downloaded_" + files[choice - 1]
    try:
        shutil.copy(server_file_path, downloaded_file)
        print(f"File downloaded locally as '{downloaded_file}'.")
    except Exception as e:
        logging.error("Error downloading file: %s", e)
        print("Failed to download file.")
        return

    # Decrypt the downloaded file.
    decrypted_file = downloaded_file.replace(".enc", "_decrypted")
    try:
        decrypt_file(downloaded_file, decrypted_file, key)
        print(f"File decrypted locally as '{decrypted_file}'.")
    except Exception as e:
        logging.error("Decryption error: %s", e)
        print("Failed to decrypt file.")
