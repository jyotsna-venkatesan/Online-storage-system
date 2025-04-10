import os
import logging
from typing import Tuple, List, Dict, Optional
from base64 import b64encode, b64decode
from .encryption_module import Encryptor
from typing import Tuple, List, Dict, Optional, Any
from .userManager import UserManager, DatabaseError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FileOperationError(Exception):
    """Custom exception for file operations"""
    pass

class FileManager:
    def __init__(self, storage_dir: str = 'secure_storage'):
        self.storage_dir = storage_dir
        self.encryptor = Encryptor()
        self._ensure_storage_dir()

    def _ensure_storage_dir(self) -> None:
        """Ensure storage directory exists"""
        try:
            if not os.path.exists(self.storage_dir):
                os.makedirs(self.storage_dir)
        except Exception as e:
            logging.error(f"Error creating storage directory: {e}")
            raise FileOperationError(f"Failed to create storage directory: {e}")

    def _validate_filename(self, filename: str) -> Tuple[bool, str]:
        """Validate filename for security"""
        if not filename:
            return False, "Filename cannot be empty"

        # Check for path traversal attempts
        if '..' in filename or '/' in filename or '\\' in filename:
            return False, "Invalid characters in filename"

        # Check file extension
        forbidden_extensions = ['.exe', '.bat', '.cmd', '.sh', '.php']
        if any(filename.lower().endswith(ext) for ext in forbidden_extensions):
            return False, "File type not allowed"

        return True, "Filename is valid"

    def upload_file(self, file_path: str, user_id: int) -> Tuple[bool, str]:
        """Upload and encrypt a file"""
        try:
            # Validate file
            if not os.path.exists(file_path):
                return False, "File does not exist"

            filename = os.path.basename(file_path)
            valid, msg = self._validate_filename(filename)
            if not valid:
                return False, msg

            # Generate encryption key and encrypt file
            key = self.encryptor.generate_key()
            if not key:
                return False, "Failed to generate encryption key"

            encrypted_data, nonce = self.encryptor.encrypt_file(file_path, key)
            if not encrypted_data:
                return False, "Failed to encrypt file"

            # Store encrypted file
            try:
                with UserManager() as um:
                    if um.cursor is None:
                        raise DatabaseError("Database cursor not initialized")

                    um.cursor.execute(
                        '''INSERT INTO files (owner_id, filename, file_path, encryption_key)
                        VALUES (?, ?, ?, ?)''',
                        (user_id, filename, encrypted_data, b64encode(key).decode('utf-8'))
                    )
                    um._log_activity(user_id, 'UPLOAD', f"File uploaded: {filename}")

                return True, "File uploaded successfully"

            except DatabaseError as e:
                logging.error(f"Database error during file upload: {e}")
                return False, f"Database error: {e}"

        except Exception as e:
            logging.error(f"File upload error: {e}")
            return False, f"Failed to upload file: {e}"

    def download_file(self, file_id: int, user_id: int) -> Tuple[bool, str, Optional[bytes]]:
        """Download and decrypt a file"""
        try:
            with UserManager() as um:
                if um.cursor is None:
                    raise DatabaseError("Database cursor not initialized")

                # Check file access
                um.cursor.execute(
                    '''SELECT f.*, fs.id as share_id
                    FROM files f
                    LEFT JOIN file_shares fs ON f.id = fs.file_id AND fs.shared_with_id = ?
                    WHERE f.id = ? AND (f.owner_id = ? OR fs.id IS NOT NULL)''',
                    (user_id, file_id, user_id)
                )
                file_data = um.cursor.fetchone()

                if not file_data:
                    return False, "File not found or access denied", None

                try:
                    # Decrypt file
                    key = b64decode(file_data['encryption_key'])
                    decrypted_data = self.encryptor.decrypt_file(file_data['file_path'], key)

                    um._log_activity(user_id, 'DOWNLOAD', f"File downloaded: {file_data['filename']}")
                    return True, "File downloaded successfully", decrypted_data

                except Exception as e:
                    logging.error(f"Decryption error: {e}")
                    return False, "Failed to decrypt file", None

        except Exception as e:
            logging.error(f"File download error: {e}")
            return False, f"Failed to download file: {e}", None

    def share_file(self, file_id: int, owner_id: int, shared_with_id: int) -> Tuple[bool, str]:
        """Share a file with another user"""
        try:
            with UserManager() as um:
                if um.cursor is None:
                    raise DatabaseError("Database cursor not initialized")

                # Verify file ownership
                um.cursor.execute(
                    'SELECT 1 FROM files WHERE id = ? AND owner_id = ?',
                    (file_id, owner_id)
                )
                if not um.cursor.fetchone():
                    return False, "File not found or you don't have permission"

                # Add share record
                um.cursor.execute(
                    'INSERT INTO file_shares (file_id, shared_with_id) VALUES (?, ?)',
                    (file_id, shared_with_id)
                )
                um._log_activity(owner_id, 'SHARE', f"File {file_id} shared with user {shared_with_id}")
                return True, "File shared successfully"

        except Exception as e:
            logging.error(f"File sharing error: {e}")
            return False, f"Failed to share file: {e}"

    def list_user_files(self, user_id: int) -> List[Dict[str, Any]]:
        """List all files owned by a user"""
        try:
            with UserManager() as um:
                if um.cursor is None:
                    raise DatabaseError("Database cursor not initialized")

                um.cursor.execute(
                    '''SELECT id, filename, created_at
                    FROM files
                    WHERE owner_id = ?
                    ORDER BY created_at DESC''',
                    (user_id,)
                )
                files = um.cursor.fetchall()
                return [dict(f) for f in files] if files else []

        except Exception as e:
            logging.error(f"Error listing files: {e}")
            return []

    def list_shared_files(self, user_id: int) -> List[Dict[str, Any]]:
        """List all files shared with a user"""
        try:
            with UserManager() as um:
                if um.cursor is None:
                    raise DatabaseError("Database cursor not initialized")

                um.cursor.execute(
                    '''SELECT f.id, f.filename, u.username as owner, f.created_at
                    FROM files f
                    JOIN file_shares fs ON f.id = fs.file_id
                    JOIN users u ON f.owner_id = u.id
                    WHERE fs.shared_with_id = ?
                    ORDER BY f.created_at DESC''',
                    (user_id,)
                )
                files = um.cursor.fetchall()
                return [dict(f) for f in files] if files else []

        except Exception as e:
            logging.error(f"Error listing shared files: {e}")
            return []

    def edit_file(self, file_id: int, user_id: int, new_content: bytes) -> Tuple[bool, str]:
        """Edit a file's content"""
        try:
            with UserManager() as um:
                if um.cursor is None:
                    raise DatabaseError("Database cursor not initialized")

                # Check ownership
                um.cursor.execute(
                    'SELECT encryption_key, owner_id FROM files WHERE id = ?',
                    (file_id,)
                )
                file_data = um.cursor.fetchone()

                if not file_data:
                    return False, "File not found"

                if file_data['owner_id'] != user_id:
                    return False, "You don't have permission to edit this file"

                # Encrypt new content
                key = b64decode(file_data['encryption_key'])
                encrypted_data, _ = self.encryptor.encrypt_file_content(new_content, key)

                # Update file
                um.cursor.execute(
                    'UPDATE files SET file_path = ? WHERE id = ?',
                    (encrypted_data, file_id)
                )

                um._log_activity(user_id, 'EDIT', f"File {file_id} edited")
                return True, "File updated successfully"

        except Exception as e:
            logging.error(f"File edit error: {e}")
            return False, f"Failed to edit file: {e}"

    def delete_file(self, file_id: int, user_id: int) -> Tuple[bool, str]:
        """Delete a file"""
        try:
            with UserManager() as um:
                if um.cursor is None:
                    raise DatabaseError("Database cursor not initialized")

                # Check ownership
                um.cursor.execute(
                    'SELECT owner_id FROM files WHERE id = ?',
                    (file_id,)
                )
                file_data = um.cursor.fetchone()

                if not file_data:
                    return False, "File not found"

                if file_data['owner_id'] != user_id:
                    return False, "You don't have permission to delete this file"

                # Delete file shares first
                um.cursor.execute('DELETE FROM file_shares WHERE file_id = ?', (file_id,))

                # Delete file record
                um.cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))

                um._log_activity(user_id, 'DELETE', f"File {file_id} deleted")
                return True, "File deleted successfully"

        except Exception as e:
            logging.error(f"File deletion error: {e}")
            return False, f"Failed to delete file: {e}"
