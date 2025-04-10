import os
import pyotp
import yagmail
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Tuple, Optional
from .userManager import DatabaseError

class MFAManager:
    def __init__(self, db_name: str = 'secure_storage.db'):
        self.db_name = db_name
        self.totp = pyotp.TOTP(pyotp.random_base32())
        self.test_mode = True  # Enable test mode
        self.last_otp = None   # Store last generated OTP for testing

        # Get email credentials from environment variables
        self.email_sender = os.getenv('EMAIL_SENDER')
        self.email_password = os.getenv('EMAIL_PASSWORD')

    def setup_mfa_for_user(self, user_id: int, email: str) -> Tuple[bool, str]:
        """Setup MFA for a user"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                # Check if MFA is already set up
                cursor.execute(
                    'SELECT 1 FROM mfa_settings WHERE user_id = ?',
                    (user_id,)
                )
                if cursor.fetchone():
                    return False, "MFA is already set up for this user"

                secret = pyotp.random_base32()
                cursor.execute(
                    '''INSERT INTO mfa_settings (user_id, secret_key, email, enabled)
                    VALUES (?, ?, ?, 1)''',
                    (user_id, secret, email)
                )
                conn.commit()
                return True, "MFA setup successful"
        except Exception as e:
            logging.error(f"MFA setup error: {e}")
            return False, "Failed to setup MFA"

    def send_otp_email(self, email: str, otp: str) -> bool:
        """Send OTP via email"""
        try:
            if self.test_mode:
                print(f"\n[TEST MODE] OTP for {email}: {otp}")
                return True

            if not self.email_sender or not self.email_password:
                logging.warning("Email credentials not configured. Using test mode.")
                print(f"\n[TEST MODE] OTP for {email}: {otp}")
                return True

            yag = yagmail.SMTP(self.email_sender, self.email_password)
            subject = "Your Secure Storage System OTP"
            content = f"Your OTP is: {otp}\nThis code will expire in 5 minutes."
            yag.send(email, subject, content)
            return True
        except Exception as e:
            logging.error(f"Email sending error: {e}")
            return False

    def generate_and_send_otp(self, user_id: int) -> Tuple[bool, str]:
        """Generate OTP and send it to user's email"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT email, secret_key FROM mfa_settings WHERE user_id = ?',
                    (user_id,)
                )
                result = cursor.fetchone()
                if not result:
                    return False, "MFA not setup for user"

                email, secret = result
                totp = pyotp.TOTP(secret, interval=300)  # 5 minutes validity
                otp = totp.now()
                self.last_otp = otp  # Store for verification

                if self.send_otp_email(email, otp):
                    return True, "OTP sent successfully"
                return False, "Failed to send OTP"

        except Exception as e:
            logging.error(f"OTP generation error: {e}")
            return False, "Failed to generate OTP"

    def verify_otp(self, user_id: int, otp: str) -> bool:
        """Verify the OTP provided by user"""
        try:
            # For test mode, compare with stored OTP
            if self.test_mode and otp == self.last_otp:
                return True

            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT secret_key FROM mfa_settings WHERE user_id = ?',
                    (user_id,)
                )
                result = cursor.fetchone()
                if not result:
                    return False

                secret = result[0]
                totp = pyotp.TOTP(secret, interval=300)  # 5 minutes validity
                return totp.verify(otp)

        except Exception as e:
            logging.error(f"OTP verification error: {e}")
            return False
