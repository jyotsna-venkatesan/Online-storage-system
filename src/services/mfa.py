import logging
import secrets
from datetime import datetime, timedelta
from typing import Tuple

import yagmail

from ..config import Config, DatabaseError
from ..db.db_manager import DbManager

class MFAManager:
    def __init__(self, db_manager: DbManager, test_mode: bool = False):
        """
        :param db_manager: shared DBManager instance
        :param test_mode: if True, OTPs are printed instead of emailed
        """
        self.db = db_manager
        self.test_mode = test_mode
        self.logger = logging.getLogger(__name__)

        # email credentials
        self.email_sender   = Config.EMAIL_SENDER if hasattr(Config, 'EMAIL_SENDER') else None
        self.email_password = Config.EMAIL_PASSWORD if hasattr(Config, 'EMAIL_PASSWORD') else None

    def setup_mfa_for_user(self, user_id: int, email: str) -> Tuple[bool, str]:
        """Enable MFA for a user by storing their email."""
        try:
            with self.db.transaction() as cursor:
                cursor.execute(
                    "SELECT 1 FROM mfa_settings WHERE user_id = ?",
                    (user_id,)
                )
                if cursor.fetchone():
                    return False, "MFA is already set up for this user"

                cursor.execute(
                    """INSERT INTO mfa_settings
                       (user_id, secret_key, email, enabled)
                       VALUES (?, '', ?, 1)""",
                    (user_id, email)
                )
            self.logger.info(f"MFA enabled for user {user_id}")
            return True, "MFA setup successful"
        except Exception as e:
            self.logger.error(f"MFA setup error: {e}", exc_info=True)
            return False, "Failed to setup MFA"

    def _send_email(self, to: str, code: str) -> bool:
        """Internal: send the OTP or print it if in test mode."""
        if self.test_mode or not (self.email_sender and self.email_password):
            # test mode fallback
            print(f"\n[TEST MODE] OTP for {to}: {code}")
            return True

        try:
            mailer = yagmail.SMTP(self.email_sender, self.email_password)
            subject = "Your Secure Storage System One‑Time Code"
            body    = (
                f"Your login code is: {code}\n\n"
                f"It will expire in {Config.TOKEN_EXPIRY} minutes."
            )
            mailer.send(to, subject, body)
            return True
        except Exception as e:
            self.logger.error(f"Failed to send OTP email: {e}", exc_info=True)
            return False

    def generate_and_send_otp(self, user_id: int) -> Tuple[bool, str]:
        """
        Create a new 6‑digit code, store it in mfa_tokens with expiry,
        then email (or print) it.
        """
        try:
            with self.db.transaction() as cursor:
                # fetch email & ensure MFA is enabled
                cursor.execute(
                    "SELECT email FROM mfa_settings WHERE user_id = ? AND enabled = 1",
                    (user_id,)
                )
                row = cursor.fetchone()
                if not row:
                    return False, "MFA not set up for this user"

                email = row["email"]

                # generate a fresh 6‑digit numeric code
                code = f"{secrets.randbelow(10**6):06d}"
                expires_at = datetime.utcnow() + timedelta(minutes=Config.TOKEN_EXPIRY)

                # store in mfa_tokens
                cursor.execute(
                    """INSERT INTO mfa_tokens
                       (user_id, token, expires_at, used, created_at)
                       VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP)""",
                    (user_id, code, expires_at)
                )

            # send or print
            if self._send_email(email, code):
                self.logger.info(f"OTP generated for user {user_id}, emailed to {email}")
                return True, "OTP sent successfully"
            else:
                return False, "Failed to send OTP"
        except Exception as e:
            self.logger.error(f"OTP generation error: {e}", exc_info=True)
            return False, "Failed to generate OTP"

    def verify_otp(self, user_id: int, code: str) -> bool:
        """
        Check the code against mfa_tokens, ensure it’s unexpired and unused,
        then mark it used.
        """
        try:
            now = datetime.utcnow()
            with self.db.transaction() as cursor:
                cursor.execute(
                    """SELECT id, expires_at, used
                    FROM mfa_tokens
                    WHERE user_id = ? AND token = ?""",
                    (user_id, code)
                )
                row = cursor.fetchone()
                if not row:
                    return False

                token_id   = row["id"]
                expires_at = row["expires_at"]
                used       = bool(row["used"])

                # parse expires_at if it's a string
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)

                # reject if already used or expired
                if used or now > expires_at:
                    return False

                # mark as used
                cursor.execute(
                    "UPDATE mfa_tokens SET used = 1 WHERE id = ?",
                    (token_id,)
                )

            self.logger.info(f"OTP for user {user_id} verified")
            return True

        except Exception as e:
            self.logger.error(f"OTP verification error: {e}", exc_info=True)
            return False