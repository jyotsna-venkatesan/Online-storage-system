# Secure Online Storage System

## Overview

Our secure online storage system enables users to securely store, access, and share files while protecting data confidentiality and integrity. The system follows a client-server architecture where all sensitive data is encrypted on the client side before transmission, ensuring that even the server cannot access unencrypted content.

## Key Features

- **Strong User Authentication**: Secure registration, login, and password reset with PBKDF2 hashing
- **Two-Factor Authentication**: Additional security layer using time-based one-time passwords (TOTP)
- **End-to-End Encryption**: AES-GCM 256-bit encryption for all stored files
- **Secure File Sharing**: Share files with other users while maintaining encryption
- **Access Control**: Strict permission model for file operations
- **Comprehensive Audit Logging**: Track all critical operations for accountability
- **Administrative Dashboard**: System monitoring and management capabilities

## Client-Server Architecture

Our system implements a clear separation between client and server components:

### Client Program
The client program handles all user interaction, file encryption/decryption, and communication with the server:

- **User Interface**: Command-line menu system for all operations (`client_menu.py`)
- **Encryption Engine**: Encrypts files before upload and decrypts after download (`encryption_module.py`)
- **Authentication Client**: Handles user credentials and session management locally
- **File Processing**: Prepares files for secure transmission to server

The client ensures that:
- Encryption keys are generated and stored locally, never shared with the server
- Files are encrypted before leaving the user's device
- Authentication tokens are properly managed

### Server Program
The server program manages data storage, authentication verification, and access control:

- **Database Management**: Stores user accounts, file metadata, and audit logs (`db_manager.py`)
- **Authentication Server**: Verifies credentials and manages sessions
- **Storage Management**: Stores encrypted files without ability to decrypt them
- **Access Control**: Enforces permissions for file operations
- **Audit Logging**: Records all critical operations for accountability

The server has been designed to operate as a "semi-trusted" entity that:
- Never sees unencrypted files or encryption keys
- Cannot access user data even with full database access
- Maintains secure logs of all operations for accountability

## Threat Model

Our system protects against:
- **Passive Server Adversaries**: Even with full access to the database and stored files, server operators cannot decrypt user data
- **Unauthorized Access**: Strong authentication prevents unauthorized users from accessing files, even if they gain physical access to a legitimate user's computer
- **SQL Injection**: Parameterized queries protect against database attacks
- **Path Traversal**: Filename validation prevents directory traversal attacks
- **Password Attacks**: Password policies, salted hashing, and account lockouts mitigate brute force attacks

## Installation

### Prerequisites

- Python 3.8 or higher
- SQLite3

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/jyotsna-venkatesan/Online-storage-system.git
   cd Online-storage-system
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`

4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Initialize the database with admin user:
   ```
   python src/db/setup_admin.py
   ```

## Usage

### Starting the Application

```
python main.py
```

This launches the command-line interface with options for authentication and file operations.

### User Authentication

1. **Register**:
   - Create a new account with a unique username
   - Password must include uppercase, lowercase, numbers, and special characters

2. **Login**:
   - Authenticate using username and password
   - Complete two-factor authentication if enabled

3. **Reset Password**:
   - Request a reset token
   - Use the token to set a new password

### File Operations

1. **Upload**:
   - Select a file from your local system
   - File is encrypted before transmission to server

2. **Download**:
   - Select a file from your storage or shared files
   - File is automatically decrypted upon download

3. **Share**:
   - Choose a file to share
   - Enter the username of the recipient

4. **View/Edit/Delete**:
   - Access or modify your files
   - Changes are encrypted before saving

### Administrator Functions

Login with admin credentials (default: username `admin`, password `AdminPass123!`) to access:

1. **Activity Logs**:
   - View detailed system logs of all user actions

2. **User Management**:
   - List all users
   - Unlock locked accounts

3. **System Statistics**:
   - Monitor overall system usage

## Security Implementation

### Password Security
- PBKDF2-HMAC-SHA256 with 100,000 iterations and unique salt per user
- Minimum length and complexity requirements
- Account lockout after consecutive failed attempts

### File Encryption
- AES-GCM with 256-bit keys for authenticated encryption
- Unique encryption key per file, stored locally
- Secure key derivation for all cryptographic operations

### Multi-Factor Authentication
- Time-based one-time passwords (TOTP)
- Email delivery of verification codes
- 5-minute validity window for enhanced security

### Database Security
- Parameterized queries to prevent SQL injection
- Transaction-based operations with proper error handling
- Secure connection management

## Project Structure

```
secure-storage/
├── src/
│   ├── controllers/
│   │   └── client_menu.py     # User interface and command handling
│   ├── db/
│   │   ├── db_manager.py      # Database connection and schema
│   │   └── setup_admin.py     # Admin user initialization
│   ├── services/
│   │   ├── file_manager.py    # File operations
│   │   ├── mfa.py             # Multi-factor authentication
│   │   └── userManager.py     # User authentication and management
│   ├── config.py              # System configuration
│   └── encryption_module.py   # Encryption/decryption services
├── requirements.txt           # Python dependencies
├── main.py                    # Application entry point
└── README.md                  # Documentation
```

## Testing & Security Verification

We conducted security testing to verify our system's resistance to various attacks:

1. **Unauthorized Access Test**:
   - Attempted to access encrypted files without proper authentication
   - Result: Files remained securely encrypted and inaccessible

2. **SQL Injection Test**:
   - Attempted to inject malicious SQL via login form
   - Result: Parameterized queries prevented execution of injected code

3. **Path Traversal Test**:
   - Attempted to upload files with path traversal characters (../file.txt)
   - Result: Validation controls rejected malicious filenames

4. **Encryption Verification**:
   - Examined stored files on server without authentication
   - Result: Files were stored in encrypted format only, with no cleartext data

## Future Work

- **End-to-End Encrypted Messaging**: Direct secure communication between users
- **File Versioning**: Track changes and maintain history of file modifications
- **Offline Access**: Support for encrypted offline file access with synchronization
- **Group Sharing**: Simplified sharing to predefined groups of users
- **Mobile Application**: Extend access to mobile platforms with the same security guarantees
