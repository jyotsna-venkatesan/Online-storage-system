import os
import getpass
import logging
import sqlite3
from typing import Optional, TypedDict
from .userManager import UserManager
from .file_manager import FileManager
from .mfa import MFAManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UserDict(TypedDict):
    id: int
    username: str
    is_admin: bool

class ClientMenu:
    def __init__(self):
        # Create and use shared instances.
        self.user_manager = UserManager()
        self.file_manager = FileManager(self.user_manager)
        self.mfa_manager = MFAManager()
        self.current_user: Optional[UserDict] = None

    def display_menu(self):
        while True:
            try:
                if not self.user_manager.current_user:
                    self._show_auth_menu()
                else:
                    self._show_main_menu()
            except Exception as e:
                logger.error(f"Menu error: {e}", exc_info=True)
                print("An error occurred. Please try again.")

    def _show_auth_menu(self):
        print("\n=== Secure Storage System ===")
        print("1. Register")
        print("2. Login")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ").strip()
        if choice == "1":
            self._handle_registration()
        elif choice == "2":
            self._handle_login()
        elif choice == "3":
            self._handle_password_reset()
        elif choice == "4":
            print("Goodbye!")
            self.user_manager.close()
            exit(0)
        else:
            print("Invalid choice. Please try again.")

    def _show_main_menu(self):
        """Display and handle the main menu for logged-in users."""
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return

        try:
            # Check if user is admin
            if current_user.get('is_admin'):
                self._show_admin_menu()
                return

            # Regular user menu
            username = self.user_manager.get_current_username()
            print("\n=== Main Menu ===")
            print(f"Logged in as: {username}")
            print("1. Upload File")
            print("2. Download File")
            print("3. Share File")
            print("4. List My Files")
            print("5. List Shared Files")
            print("6. View File")
            print("7. Edit File")
            print("8. Delete File")
            print("9. Change Password")
            print("10. Logout")
            print("11. Exit")
            choice = input("Enter your choice (1-11): ").strip()
            menu_actions = {
                "1": self._handle_upload,
                "2": self._handle_download_file,
                "3": self._handle_share,
                "4": self._handle_list_files,
                "5": self._handle_list_shared,
                "6": self._handle_view_file,
                "7": self._handle_edit_file,
                "8": self._handle_delete_file,
                "9": self._handle_change_password,
                "10": self._handle_logout,
                "11": self._handle_exit
            }
            action = menu_actions.get(choice)
            if action and callable(action):
                try:
                    action()
                except Exception as e:
                    logger.error(f"Error executing menu action: {e}", exc_info=True)
                    print("An error occurred while processing your request.")
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            logger.error(f"Unexpected error in main menu: {e}", exc_info=True)
            print("An unexpected error occurred. Please try again.")

    def _handle_registration(self):
        print("\n=== User Registration ===")
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("Passwords do not match!")
            return
        success, message = self.user_manager.register_user(username, password)
        print(message)

    def _handle_login(self):
        print("\n=== Login ===")
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        try:
            success, message, user_id = self.user_manager.login(username, password)
            if success and user_id is not None:
                # MFA required
                print("Two-factor authentication required")
                mfa_success, mfa_message = self.mfa_manager.generate_and_send_otp(user_id)
                if not mfa_success:
                    print(f"Failed to send OTP: {mfa_message}")
                    return
                otp = input("Enter the OTP sent to your email: ").strip()
                if self.mfa_manager.verify_otp(user_id, otp):
                    with self.user_manager._transaction() as cursor:
                        cursor.execute(
                            '''SELECT id, username, is_admin FROM users WHERE id = ?''',
                            (user_id,)
                        )
                        user = cursor.fetchone()
                        if user:
                            self.user_manager._complete_login(dict(user))
                            print("Login successful")
                        else:
                            print("User not found")
                else:
                    print("Invalid OTP")
            else:
                print(message)

            if success and user_id is None:
                print("\nWould you like to enable Two-Factor Authentication?")
                if input("Enable MFA (y/n): ").strip().lower() == 'y':
                    email = input("Enter your email address: ").strip()
                    current_user_id = self.user_manager.get_current_user_id()
                    if current_user_id is not None:
                        success, message = self.mfa_manager.setup_mfa_for_user(current_user_id, email)
                        print(message)
                    else:
                        print("Error: No user ID available")
        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            print("An error occurred during login")

    def _handle_password_reset(self):
        print("\n=== Password Reset ===")
        username = input("Enter username: ").strip()

        # Generate a reset token for the user.
        success, message, token = self.user_manager.generate_password_reset_token(username)
        if not success or token is None:
            print(message)
            return

        # In a real system, the token would be emailed.
        # For testing, we print it so that the user can enter it.
        print(f"A password reset token has been sent to your registered email.")
        print(f"(For testing purposes, your token is: {token})")

        # Prompt the user to enter the token manually.
        user_token = input("Enter the password reset token: ").strip()
        if user_token != token:
            print("Invalid token entered!")
            return

        # Prompt for new password.
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        if new_password != confirm_password:
            print("Passwords do not match!")
            return

        # Use the provided token and new password to reset the user's password.
        success, message = self.user_manager.use_password_reset_token(token, new_password)
        print(message)


    def _handle_upload(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        try:
            print("\n=== Upload File ===")
            file_path = input("Enter file path: ").strip()
            if not os.path.exists(file_path):
                print("File does not exist!")
                return
            current_user_id = self.user_manager.get_current_user_id()
            if current_user_id is None:
                print("Error: No user ID available")
                return
            success, message = self.file_manager.upload_file(file_path, current_user_id)
            print(message)
        except ValueError as e:
            print(str(e))

    def _handle_download_file(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== Download File ===")
        self._handle_list_files()
        file_id_input = input("Enter file ID to download (or 0 to cancel): ").strip()
        if not file_id_input.isdigit():
            print("Invalid file ID!")
            return
        file_id = int(file_id_input)
        if file_id == 0:
            return
        current_user_id = self.user_manager.get_current_user_id()
        if current_user_id is None:
            print("Error: No user ID available")
            return
        success, message, data = self.file_manager.download_file(file_id, current_user_id)
        if success and data:
            output_path = input("Enter path to save file (include filename): ").strip()
            try:
                with open(output_path, 'wb') as f:
                    f.write(data)
                print(f"File saved to {output_path}")
            except Exception as e:
                print(f"Error saving file: {e}")
        else:
            print(message)

    def _handle_share(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== Share File ===")
        self._handle_list_files()
        file_id_input = input("Enter file ID to share (or 0 to cancel): ").strip()
        if not file_id_input.isdigit():
            print("Invalid file ID!")
            return
        file_id = int(file_id_input)
        if file_id == 0:
            return
        share_username = input("Enter username to share with: ").strip()
        if self.user_manager.cursor is None:
            print("Database connection error!")
            return
        self.user_manager.cursor.execute("SELECT id FROM users WHERE username = ?", (share_username,))
        user_data = self.user_manager.cursor.fetchone()
        if not user_data:
            print("User not found!")
            return
        target_user_id = user_data['id'] if isinstance(user_data, sqlite3.Row) else user_data[0]
        current_user_id = self.user_manager.get_current_user_id()
        if current_user_id is None:
            print("Error: No user ID available")
            return
        success, message = self.file_manager.share_file(file_id, current_user_id, target_user_id)
        print(message)

    def _handle_list_files(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== My Files ===")
        try:
            if self.user_manager.cursor is None:
                print("Database connection error!")
                return
            current_user_id = self.user_manager.get_current_user_id()
            if current_user_id is None:
                print("Error: No user ID available")
                return
            self.user_manager.cursor.execute(
                'SELECT id, filename, created_at FROM files WHERE owner_id = ? ORDER BY created_at DESC',
                (current_user_id,)
            )
            files = self.user_manager.cursor.fetchall()
            if not files:
                print("No files found.")
                return
            print("ID | Filename | Created At")
            print("-" * 50)
            for file in files:
                if isinstance(file, sqlite3.Row):
                    print(f"{file['id']} | {file['filename']} | {file['created_at']}")
                else:
                    print(f"{file[0]} | {file[1]} | {file[2]}")
        except Exception as e:
            logger.error(f"List files error: {e}", exc_info=True)
            print("Failed to list files")

    def _handle_list_shared(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== Shared With Me ===")
        try:
            if self.user_manager.cursor is None:
                print("Database connection error!")
                return
            current_user_id = self.user_manager.get_current_user_id()
            if current_user_id is None:
                print("Error: No user ID available")
                return
            self.user_manager.cursor.execute(
                '''SELECT f.id, f.filename, u.username as owner, f.created_at
                   FROM files f
                   JOIN file_shares fs ON f.id = fs.file_id
                   JOIN users u ON f.owner_id = u.id
                   WHERE fs.shared_with_id = ?
                   ORDER BY f.created_at DESC''',
                (current_user_id,)
            )
            files = self.user_manager.cursor.fetchall()
            if not files:
                print("No shared files found.")
                return
            print("ID | Filename | Owner | Shared At")
            print("-" * 60)
            for file in files:
                if isinstance(file, sqlite3.Row):
                    print(f"{file['id']} | {file['filename']} | {file['owner']} | {file['created_at']}")
                else:
                    print(f"{file[0]} | {file[1]} | {file[2]} | {file[3]}")
        except Exception as e:
            logger.error(f"List shared files error: {e}", exc_info=True)
            print("Failed to list shared files")

    def _handle_view_file(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== View File ===")
        self._handle_list_files()
        print("\nShared files:")
        self._handle_list_shared()
        file_id_input = input("\nEnter file ID to view (or 0 to cancel): ").strip()
        if not file_id_input.isdigit():
            print("Invalid file ID!")
            return
        file_id = int(file_id_input)
        if file_id == 0:
            return
        try:
            success, message, data = self.file_manager.download_file(
                file_id,
                current_user['id']
            )
            if success and data:
                print("\n=== File Content ===")
                print(data.decode('utf-8'))  # For text files
                print("=" * 50)
            else:
                print(message)
        except UnicodeDecodeError:
            print("This appears to be a binary file and cannot be displayed directly.")
        except Exception as e:
            print(f"Error viewing file: {e}")

    def _handle_edit_file(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== Edit File ===")
        self._handle_list_files()
        file_id_input = input("Enter file ID to edit (or 0 to cancel): ").strip()
        if not file_id_input.isdigit():
            print("Invalid file ID!")
            return
        file_id = int(file_id_input)
        if file_id == 0:
            return
        try:
            success, message, data = self.file_manager.download_file(
                file_id,
                current_user['id']
            )
            if not success or not data:
                print("Failed to access file:", message)
                return
            temp_path = f"temp_edit_{file_id}.txt"
            with open(temp_path, 'wb') as f:
                f.write(data)
            print("\nCurrent content:")
            print(data.decode('utf-8'))
            print("\nEnter new content (press Ctrl+D or Ctrl+Z when done):")
            new_content = []
            try:
                while True:
                    line = input()
                    new_content.append(line)
            except EOFError:
                pass
            new_content_bytes = '\n'.join(new_content).encode('utf-8')
            success, message = self.file_manager.edit_file(
                file_id,
                current_user['id'],
                new_content_bytes
            )
            print(message)
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception as e:
            logger.error(f"Edit error: {e}", exc_info=True)
            print(f"Error editing file: {e}")

    def _handle_delete_file(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== Delete File ===")
        self._handle_list_files()
        file_id_input = input("Enter file ID to delete (or 0 to cancel): ").strip()
        if not file_id_input.isdigit():
            print("Invalid file ID!")
            return
        file_id = int(file_id_input)
        if file_id == 0:
            return
        confirm = input("Are you sure you want to delete this file? (y/n): ").lower()
        if confirm != 'y':
            print("Deletion cancelled.")
            return
        success, message = self.file_manager.delete_file(
            file_id,
            current_user['id']
        )
        print(message)

    def _handle_change_password(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== Change Password ===")
        current_password = getpass.getpass("Enter current password: ")
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        if new_password != confirm_password:
            print("New passwords do not match!")
            return
        try:
            success, message, _ = self.user_manager.login(
                current_user['username'],
                current_password
            )
            if not success:
                print("Current password is incorrect!")
                return
            success, message = self.user_manager.reset_password(
                current_user['username'],
                new_password
            )
            print(message)
        except Exception as e:
            logger.error(f"Password change error: {e}", exc_info=True)
            print("Failed to change password")

    def _handle_logout(self):
        success, message = self.user_manager.logout()
        print(message)

    def _handle_exit(self):
        self.user_manager.logout()
        self.user_manager.close()
        print("Goodbye!")
        exit(0)

    def _show_admin_menu(self):
        current_user = self.user_manager.current_user
        if not current_user or not current_user.get('is_admin'):
            print("Unauthorized access!")
            return
        try:
            username = self.user_manager.get_current_username()
            print("\n=== Admin Menu ===")
            print(f"Logged in as: {username} (Administrator)")
            print("1. View Activity Logs")
            print("2. List All Users")
            print("3. View System Statistics")
            print("4. Manage Files")
            print("5. Regular User Menu")
            print("6. Logout")
            print("7. Exit")
            try:
                choice = input("Enter your choice (1-7): ").strip()
                menu_actions = {
                    "1": self._handle_view_logs,
                    "2": self._handle_list_users,
                    "3": self._handle_system_stats,
                    "4": self._handle_manage_files,
                    "5": self._show_main_menu,
                    "6": self._handle_logout,
                    "7": self._handle_exit
                }
                action = menu_actions.get(choice)
                if action and callable(action):
                    action()
                else:
                    print("Invalid choice. Please try again.")
            except KeyboardInterrupt:
                print("\nOperation cancelled by user.")
            except Exception as e:
                logger.error(f"Error processing menu choice: {e}", exc_info=True)
                print("An error occurred while processing your input.")
        except Exception as e:
            logger.error(f"Admin menu error: {e}", exc_info=True)
            print("An error occurred. Please try again.")

    def _handle_view_logs(self):
        print("\n=== Activity Logs ===")
        try:
            with self.user_manager._transaction() as cursor:
                cursor.execute('''
                    SELECT al.timestamp, u.username, al.activity_type, al.details
                    FROM activity_log al
                    LEFT JOIN users u ON al.user_id = u.id
                    ORDER BY al.timestamp DESC
                    LIMIT 50
                ''')
                logs = cursor.fetchall()
                if not logs:
                    print("No activity logs found.")
                    return
                print("Timestamp | Username | Activity | Details")
                print("-" * 80)
                for log in logs:
                    print(f"{log['timestamp']} | {log['username'] or 'System'} | {log['activity_type']} | {log['details']}")
        except Exception as e:
            logger.error(f"Error viewing logs: {e}", exc_info=True)
            print("Failed to retrieve activity logs")

    def _handle_list_users(self):
        print("\n=== User List ===")
        try:
            with self.user_manager._transaction() as cursor:
                cursor.execute('''
                    SELECT username, created_at, last_login,
                           failed_attempts, locked_until
                    FROM users
                    ORDER BY created_at DESC
                ''')
                users = cursor.fetchall()
                if not users:
                    print("No users found.")
                    return
                print("Username | Created | Last Login | Status")
                print("-" * 80)
                for user in users:
                    status = "Locked" if user['locked_until'] else "Active"
                    print(f"{user['username']} | {user['created_at']} | {user['last_login'] or 'Never'} | {status}")
        except Exception as e:
            logger.error(f"Error listing users: {e}", exc_info=True)
            print("Failed to retrieve user list")

    def _handle_system_stats(self):
        print("\n=== System Statistics ===")
        try:
            with self.user_manager._transaction() as cursor:
                cursor.execute('SELECT COUNT(*) as count FROM users')
                user_count = cursor.fetchone()['count']
                cursor.execute('SELECT COUNT(*) as count FROM files')
                file_count = cursor.fetchone()['count']
                cursor.execute('SELECT COUNT(*) as count FROM file_shares')
                share_count = cursor.fetchone()['count']
                print(f"Total Users: {user_count}")
                print(f"Total Files: {file_count}")
                print(f"Total Shares: {share_count}")
        except Exception as e:
            logger.error(f"Error getting statistics: {e}", exc_info=True)
            print("Failed to retrieve system statistics")

    def _handle_manage_files(self):
        print("\n=== File Management ===")
        try:
            with self.user_manager._transaction() as cursor:
                cursor.execute('''
                    SELECT f.id, f.filename, u.username as owner, f.created_at
                    FROM files f
                    JOIN users u ON f.owner_id = u.id
                    ORDER BY f.created_at DESC
                ''')
                files = cursor.fetchall()
                if not files:
                    print("No files found in the system.")
                    return
                print("ID | Filename | Owner | Created At")
                print("-" * 80)
                for file in files:
                    print(f"{file['id']} | {file['filename']} | {file['owner']} | {file['created_at']}")
        except Exception as e:
            logger.error(f"Error managing files: {e}", exc_info=True)
            print("Failed to retrieve file list")

    def _handle_change_password(self):
        current_user = self.user_manager.current_user
        if not current_user:
            print("No user is currently logged in!")
            return
        print("\n=== Change Password ===")
        current_password = getpass.getpass("Enter current password: ")
        new_password = getpass.getpass("Enter new password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        if new_password != confirm_password:
            print("New passwords do not match!")
            return
        try:
            success, message, _ = self.user_manager.login(
                current_user['username'],
                current_password
            )
            if not success:
                print("Current password is incorrect!")
                return
            success, message = self.user_manager.reset_password(
                current_user['username'],
                new_password
            )
            print(message)
        except Exception as e:
            logger.error(f"Password change error: {e}", exc_info=True)
            print("Failed to change password")

    def _handle_logout(self):
        success, message = self.user_manager.logout()
        print(message)

    def _handle_exit(self):
        self.user_manager.logout()
        self.user_manager.close()
        print("Goodbye!")
        exit(0)

def main():
    client = ClientMenu()
    client.display_menu()

if __name__ == "__main__":
    main()
