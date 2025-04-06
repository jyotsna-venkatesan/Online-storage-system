import logging
from getpass import getpass
from userManager import UserManager
from file_manager import init_encryption_key, upload_file, download_file

# Configure logging
logging.basicConfig(level=logging.INFO)

def client_menu():
    key = init_encryption_key()
    user_manager = UserManager()

    while True:
        if not user_manager.current_user:
            # Not authorized: show Register, Login, Reset Password, and Exit.
            print("\n--- Secure Online Storage Client Menu (Not Authorized) ---")
            print("1. Register")
            print("2. Login")
            print("3. Reset Password")
            print("4. Exit")
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                username = input("Enter username: ").strip()
                password = getpass("Enter password (requirements: 7+ chars with uppercase, lowercase, number & symbol): ")
                confirm_password = getpass("Confirm password: ")
                if password != confirm_password:
                    print("Passwords do not match!")
                    continue
                success, message = user_manager.register_user(username, password)
                print(message)

            elif choice == "2":
                username = input("Enter username: ").strip()
                password = getpass("Enter password: ")
                success, message = user_manager.login(username, password)
                print(message)

            elif choice == "3":
                username = input("Enter username: ").strip()
                # Generate a reset token
                success, message, token = user_manager.generate_password_reset_token(username)
                if success:
                    print(f"{message}. Your reset token is: {token}")
                    token_input = input("Enter the reset token you received: ").strip()
                    new_password = getpass("Enter password (requirements: 7+ chars with uppercase, lowercase, number & symbol): ")
                    confirm_password = getpass("Confirm new password: ")
                    if new_password != confirm_password:
                        print("Passwords do not match!")
                        continue
                    success, message = user_manager.use_password_reset_token(token_input, new_password)
                    print(message)
                else:
                    print(message)

            elif choice == "4":
                user_manager.close()
                print("Exiting client program.")
                break

            else:
                print("Invalid choice. Please try again.")

        else:
            # Authorized: user is logged in; show additional options.
            print("\n--- Secure Online Storage Client Menu (Authorized) ---")
            print("1. Upload File")
            print("2. Download File")
            print("3. Change Password")
            print("4. Logout")
            print("5. Exit")
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                upload_file(key)

            elif choice == "2":
                download_file(key)

            elif choice == "3":
                # Change password flow: verify current password then update.
                current_password = getpass("Enter current password: ")
                # Verify the current password by attempting to log in again.
                username = user_manager.current_user["username"]
                success, message = user_manager.login(username, current_password)
                if not success:
                    print("Current password is incorrect!")
                    continue
                new_password = getpass("Enter password (requirements: 7+ chars with uppercase, lowercase, number & symbol):")
                confirm_password = getpass("Confirm new password: ")
                if new_password != confirm_password:
                    print("Passwords do not match!")
                    continue
                success, message = user_manager.reset_password(username, new_password)
                print(message)

            elif choice == "4":
                success, message = user_manager.logout()
                print(message)

            elif choice == "5":
                user_manager.close()
                print("Exiting client program.")
                break

            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    client_menu()
