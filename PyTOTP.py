import pyotp
import qrcode
import json
import os
import logging
import base64
import time
import hashlib
import secrets
from cryptography.fernet import Fernet
from typing import Optional, Dict, List, Tuple


class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts: Dict[str, List[float]] = {}

    def is_allowed(self, key: str) -> bool:
        current_time = time.time()
        if key not in self.attempts:
            self.attempts[key] = []

        self.attempts[key] = [
            t for t in self.attempts[key] if current_time - t <= self.window_seconds
        ]

        if len(self.attempts[key]) >= self.max_attempts:
            return False

        self.attempts[key].append(current_time)
        return True


class TwoFactorAuthApp:
    SESSION_DURATION = 3600  # 1 hour

    def __init__(
        self,
        storage_file: str = "accounts.json",
        key_file: str = "secret.key",
        user_file: str = "users.json",
    ) -> None:
        self.storage_file = storage_file
        self.user_file = user_file
        self.key_file = key_file
        self.key = self.load_key(key_file)
        self.cipher = Fernet(self.key)
        self.accounts: Dict[str, str] = self.load_accounts()
        self.users: Dict[str, str] = self.load_users()
        self.sessions: Dict[
            str, Tuple[str, float]
        ] = {}  # session_token -> (username, expiry_time)
        self.rate_limiter = RateLimiter(max_attempts=5, window_seconds=60)

    def load_key(self, key_file: str) -> bytes:
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            return self.generate_key(key_file)

    def generate_key(self, key_file: str) -> bytes:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        logging.info(f"New key generated and saved to {key_file}")
        return key

    def encrypt(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, data: str) -> str:
        return self.cipher.decrypt(data.encode()).decode()

    def load_accounts(self) -> Dict[str, str]:
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    encrypted_data = f.read()
                    decrypted_data = self.decrypt(encrypted_data)
                    return json.loads(decrypted_data)
            except Exception as e:
                logging.error(f"Error loading accounts: {e}")
        return {}

    def save_accounts(self) -> None:
        try:
            encrypted_data = self.encrypt(json.dumps(self.accounts))
            with open(self.storage_file, "w") as f:
                f.write(encrypted_data)
        except Exception as e:
            logging.error(f"Error saving accounts: {e}")

    def load_users(self) -> Dict[str, str]:
        if os.path.exists(self.user_file):
            try:
                with open(self.user_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading users: {e}")
        return {}

    def save_users(self) -> None:
        try:
            with open(self.user_file, "w") as f:
                json.dump(self.users, f)
        except Exception as e:
            logging.error(f"Error saving users: {e}")

    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def add_user(self, username: str, password: str) -> None:
        if username in self.users:
            logging.warning(f"User '{username}' already exists.")
            return

        self.users[username] = self.hash_password(password)
        self.save_users()
        logging.info(f"User '{username}' added.")

    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        if username not in self.users:
            logging.warning(f"User '{username}' not found.")
            return None

        if self.users[username] == self.hash_password(password):
            session_token = secrets.token_hex(16)
            expiry_time = time.time() + self.SESSION_DURATION
            self.sessions[session_token] = (username, expiry_time)
            logging.info(f"User '{username}' authenticated.")
            return session_token
        else:
            logging.warning("Invalid password.")
            return None

    def validate_session(self, session_token: str) -> bool:
        if session_token in self.sessions:
            username, expiry_time = self.sessions[session_token]
            if time.time() < expiry_time:
                return True
            else:
                logging.warning("Session expired.")
                del self.sessions[session_token]
        else:
            logging.warning("Invalid session token.")
        return False

    def renew_session(self, session_token: str) -> None:
        if session_token in self.sessions:
            username, _ = self.sessions[session_token]
            new_expiry_time = time.time() + self.SESSION_DURATION
            self.sessions[session_token] = (username, new_expiry_time)
            logging.info(f"Session for user '{username}' renewed.")

    def add_account(self, account_name: str, session_token: str) -> None:
        if not self.validate_session(session_token):
            logging.warning("Authentication required.")
            return

        if account_name in self.accounts:
            logging.warning(f"Account '{account_name}' already exists.")
            return

        secret: str = pyotp.random_base32()
        self.accounts[account_name] = secret
        self.save_accounts()
        logging.info(f"Account '{account_name}' added.")

        uri: str = pyotp.totp.TOTP(secret).provisioning_uri(
            name=account_name, issuer_name="Custom2FAApp"
        )
        qr = qrcode.make(uri)
        qr_path: str = f"{account_name}_qrcode.png"
        qr.save(qr_path)
        logging.info(f"QR Code for '{account_name}' generated and saved as '{qr_path}'")

        self.renew_session(session_token)

    def generate_totp(self, account_name: str, session_token: str) -> Optional[str]:
        if not self.validate_session(session_token):
            logging.warning("Authentication required.")
            return None

        if account_name not in self.accounts:
            logging.warning(f"No account found with the name '{account_name}'")
            return None

        if not self.rate_limiter.is_allowed(f"generate:{account_name}"):
            logging.warning(
                f"Rate limit exceeded for generating TOTP for '{account_name}'"
            )
            return None

        totp: pyotp.TOTP = pyotp.TOTP(self.accounts[account_name])
        self.renew_session(session_token)
        return totp.now()

    def verify_totp(self, account_name: str, code: str, session_token: str) -> bool:
        if not self.validate_session(session_token):
            logging.warning("Authentication required.")
            return False

        if account_name not in self.accounts:
            logging.warning(f"No account found with the name '{account_name}'")
            return False

        if not self.rate_limiter.is_allowed(f"verify:{account_name}"):
            logging.warning(
                f"Rate limit exceeded for verifying TOTP for '{account_name}'"
            )
            return False

        totp: pyotp.TOTP = pyotp.TOTP(self.accounts[account_name])
        if totp.verify(code):
            self.renew_session(session_token)
            return True
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    app = TwoFactorAuthApp()

    session_token: Optional[str] = None

    while True:
        print("\nMenu:")
        print("1. Register User")
        print("2. Login")
        print("3. Add Account")
        print("4. Generate TOTP Code")
        print("5. Verify TOTP Code")
        print("6. Exit")

        try:
            choice: str = input("Enter your choice: ").strip()

            if choice == "1":
                username: str = input("Enter username: ").strip()
                password: str = input("Enter password: ").strip()
                if username and password:
                    app.add_user(username, password)
                else:
                    print("Username and password cannot be empty.")
            elif choice == "2":
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                if username and password:
                    session_token = app.authenticate_user(username, password)
                    if session_token:
                        print("Login successful!")
                    else:
                        print("Invalid username or password.")
                else:
                    print("Username and password cannot be empty.")
            elif choice == "3":
                account_name: str = input("Enter account name: ").strip()
                if account_name and session_token:
                    app.add_account(account_name, session_token)
                else:
                    print("Account name and valid session token are required.")
            elif choice == "4":
                account_name = input("Enter account name: ").strip()
                if account_name and session_token:
                    code: Optional[str] = app.generate_totp(account_name, session_token)
                    if code:
                        print(f"TOTP Code for '{account_name}': {code}")
                    else:
                        print(
                            "Rate limit exceeded, account not found, or not authenticated."
                        )
                else:
                    print("Account name and valid session token are required.")
            elif choice == "5":
                account_name = input("Enter account name: ").strip()
                code = input("Enter TOTP code: ").strip()
                if account_name and code and session_token:
                    if app.verify_totp(account_name, code, session_token):
                        print("TOTP Code is valid!")
                    else:
                        print(
                            "TOTP Code is invalid, rate limit exceeded, or not authenticated."
                        )
                else:
                    print(
                        "Account name, TOTP code, and valid session token are required."
                    )
            elif choice == "6":
                break
            else:
                print("Invalid choice! Please try again.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            print("An unexpected error occurred. Please try again.")
