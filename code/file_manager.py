import os
import logging
from typing import Tuple, List, Dict, Optional, Any
from base64 import b64encode, b64decode
from .config import Config
from .encryption_module import Encryptor
from .userManager import UserManager, DatabaseError

logger = logging.getLogger(__name__)

class FileOperationError(Exception):
    pass

class FileManager:
    def __init__(self, user_manager: UserManager, storage_dir: str = Config.STORAGE_DIR) -> None:
        self.storage_dir = storage_dir
        self.encryptor = Encryptor()
        self.user_manager = user_manager
        self._ensure_storage_dir()

    # Ensure storage directory exists
    def _ensure_storage_dir(self) -> None:
        try:
            if not os.path.exists(self.storage_dir):
                os.makedirs(self.storage_dir)
        except Exception as e:
            logger.error("Error creating storage directory: %s", e, exc_info=True)
            raise FileOperationError(f"Failed to create storage directory: {e}")

    # Validate filename for security
    def _validate_filename(self, filename: str) -> Tuple[bool, str]:
        if not filename:
            return False, "Filename cannot be empty"
        if any(seq in filename for seq in ('..', '/', '\\')):
            return False, "Invalid characters in filename"
        if any(filename.lower().endswith(ext) for ext in ('.exe', '.bat', '.cmd', '.sh', '.php')):
            return False, "File type not allowed"
        return True, "Filename is valid"

    # Upload and encrypt a file
    def upload_file(self, file_path: str, user_id: int) -> Tuple[bool, str]:
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"
            
            filename = os.path.basename(file_path)
            valid, msg = self._validate_filename(filename)
            if not valid:
                return False, msg

            # Generate encryption key and encrypt file
            key = self.encryptor.generate_key()            
            encrypted_data, _ = self.encryptor.encrypt_file(file_path, key)
            if not encrypted_data:
                return False, "Failed to encrypt file"

            if self.user_manager.cursor is None:
                raise DatabaseError("Database cursor not initialized")

            self.user_manager.cursor.execute(
                '''INSERT INTO files (owner_id, filename, file_path, encryption_key)
                   VALUES (?, ?, ?, ?)''',
                (user_id, filename, encrypted_data, b64encode(key).decode('utf-8'))
            )
            self.user_manager._log_activity(user_id, 'UPLOAD', f"File uploaded: {filename}")
            return True, "File uploaded successfully"
        except Exception as e:
            logger.error("File upload error: %s", e, exc_info=True)
            return False, f"Failed to upload file: {e}"

    # Download and decrypt a file
    def download_file(self, file_id: int, user_id: int) -> Tuple[bool, str, Optional[bytes]]:
        try:
            if self.user_manager.cursor is None:
                raise DatabaseError("Database cursor not initialized")

            self.user_manager.cursor.execute(
                '''SELECT f.*, fs.id as share_id
                   FROM files f
                   LEFT JOIN file_shares fs ON f.id = fs.file_id AND fs.shared_with_id = ?
                   WHERE f.id = ? AND (f.owner_id = ? OR fs.id IS NOT NULL)''',
                (user_id, file_id, user_id)
            )
            file_data = self.user_manager.cursor.fetchone()
            if not file_data:
                return False, "File not found or access denied", None

            # Retrieve and decode the encryption key.
            key = b64decode(file_data['encryption_key'])
            # Decrypt the file content stored in the 'encrypted_data' column.
            decrypted_data = self.encryptor.decrypt_file(file_data['file_path'], key)
            self.user_manager._log_activity(user_id, 'DOWNLOAD', f"File downloaded: {file_data['filename']}")
            return True, "File downloaded successfully", decrypted_data
        except Exception as e:
            logger.error("File download error: %s", e, exc_info=True)
            return False, f"Failed to download file: {e}", None

    # Share a file with another user
    def share_file(self, file_id: int, owner_id: int, shared_with_id: int) -> Tuple[bool, str]:
        try:
            if self.user_manager.cursor is None:
                raise DatabaseError("Database cursor not initialized")

            self.user_manager.cursor.execute(
                'SELECT 1 FROM files WHERE id = ? AND owner_id = ?',
                (file_id, owner_id)
            )
            if not self.user_manager.cursor.fetchone():
                return False, "File not found or you don't have permission"

            self.user_manager.cursor.execute(
                'INSERT INTO file_shares (file_id, shared_with_id) VALUES (?, ?)',
                (file_id, shared_with_id)
            )
            self.user_manager._log_activity(owner_id, 'SHARE', f"File {file_id} shared with user {shared_with_id}")
            return True, "File shared successfully"
        except Exception as e:
            logger.error("File sharing error: %s", e, exc_info=True)
            return False, f"Failed to share file: {e}"

    # List files owned by a user
    def list_user_files(self, user_id: int) -> List[Dict[str, Any]]:
        try:
            if self.user_manager.cursor is None:
                raise DatabaseError("Database cursor not initialized")

            self.user_manager.cursor.execute(
                '''SELECT id, filename, created_at
                   FROM files
                   WHERE owner_id = ?
                   ORDER BY created_at DESC''',
                (user_id,)
            )
            files = self.user_manager.cursor.fetchall()
            return [dict(f) for f in files] if files else []
        except Exception as e:
            logger.error("Error listing files: %s", e, exc_info=True)
            return []

    # List files shared with a user
    def list_shared_files(self, user_id: int) -> List[Dict[str, Any]]:
        try:
            if self.user_manager.cursor is None:
                raise DatabaseError("Database cursor not initialized")

            self.user_manager.cursor.execute(
                '''SELECT f.id, f.filename, u.username as owner, f.created_at
                   FROM files f
                   JOIN file_shares fs ON f.id = fs.file_id
                   JOIN users u ON f.owner_id = u.id
                   WHERE fs.shared_with_id = ?
                   ORDER BY f.created_at DESC''',
                (user_id,)
            )
            files = self.user_manager.cursor.fetchall()
            return [dict(f) for f in files] if files else []
        except Exception as e:
            logger.error("Error listing shared files: %s", e, exc_info=True)
            return []

    # Edit file content
    def edit_file(self, file_id: int, user_id: int, new_content: bytes) -> Tuple[bool, str]:
        try:
            # Use the shared UserManager instance directly.
            if self.user_manager.cursor is None:
                raise DatabaseError("Database cursor not initialized")

            # Check ownership
            self.user_manager.cursor.execute('SELECT encryption_key, owner_id FROM files WHERE id = ?', (file_id,))
            file_data = self.user_manager.cursor.fetchone()

            if not file_data:
                return False, "File not found"
            if file_data['owner_id'] != user_id:
                return False, "You don't have permission to edit this file"

            # Encrypt new content
            key = b64decode(file_data['encryption_key'])
            encrypted_data, _ = self.encryptor.encrypt_file_content(new_content, key)

            # Update file: use the correct column name "file_path" as defined in your schema.
            self.user_manager.cursor.execute('UPDATE files SET file_path = ? WHERE id = ?', (encrypted_data, file_id))
            self.user_manager._log_activity(user_id, 'EDIT', f"File {file_id} edited")

            return True, "File updated successfully"
        except Exception as e:
            logger.error(f"File edit error: {e}", exc_info=True)
            return False, f"Failed to edit file: {e}"

    # Delete a file
    def delete_file(self, file_id: int, user_id: int) -> Tuple[bool, str]:
        try:
            if self.user_manager.cursor is None:
                raise DatabaseError("Database cursor not initialized")

            self.user_manager.cursor.execute(
                'SELECT owner_id FROM files WHERE id = ?',
                (file_id,)
            )
            file_data = self.user_manager.cursor.fetchone()
            if not file_data:
                return False, "File not found"
            if file_data['owner_id'] != user_id:
                return False, "You don't have permission to delete this file!"

            self.user_manager.cursor.execute(
                'DELETE FROM file_shares WHERE file_id = ?',
                (file_id,)
            )
            self.user_manager.cursor.execute(
                'DELETE FROM files WHERE id = ?',
                (file_id,)
            )
            self.user_manager._log_activity(user_id, 'DELETE', f"File {file_id} deleted")
            return True, "File deleted successfully"
        except Exception as e:
            logger.error("File deletion error: %s", e, exc_info=True)
            return False, f"Failed to delete file: {e}"
