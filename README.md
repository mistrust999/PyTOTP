# PyTOTP Two-Factor Authentication (2FA) App

This is a simple Two-Factor Authentication (2FA) application written in Python. It allows users to register, login, add accounts, generate TOTP codes, and verify TOTP codes. The application uses session tokens to manage user sessions and rate limiting to prevent abuse.

## Features

- User registration and login
- Secure password storage with hashing
- Account management with TOTP generation and verification
- Session management with token expiry and renewal
- Rate limiting for TOTP generation and verification

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/mistrust999/PyTOTP.git
    cd PyTOTP
    ```

2. **Create and activate a virtual environment (optional but recommended):**

    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate.bat`
    ```

3. **Install the required dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. **Run the application:**

    ```sh
    python PyTOTP.py
    ```

2. **Follow the on-screen menu to register a user, login, add accounts, generate TOTP codes, and verify TOTP codes.**

## Requirements

The required dependencies are listed in `requirements.txt`.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.
