# Secure Online Storage System

A secure online storage system with robust user authentication, file encryption, access control, and activity auditing features.

## Core Functionalities

### 1. User Management
- User registration with unique username requirement
- Secure password hashing using PBKDF2
- User authentication system
- Password reset functionality
- Account locking after multiple failed login attempts
- Multi-Factor Authentication (MFA) support

### 2. Data Encryption
- File encryption using AES-GCM
- Secure key generation and management
- Client-side encryption before upload
- Secure file decryption for authorized users

### 3. Access Control
- Role-based access control (Admin/Regular users)
- File ownership management
- File sharing capabilities
- Permission-based file access

### 4. Activity Auditing
- Comprehensive logging of critical operations:
  - Login/Logout events
  - File operations (upload, download, share, delete)
  - Password resets
  - Administrative actions
- Secure audit trail maintenance

### 5. Security Features
- SQL injection prevention
- File path validation
- Session management
- Secure password policies
- Account lockout protection

## Extended Functionalities

### 1. Multi-Factor Authentication (MFA)
- Email-based OTP verification
- TOTP (Time-based One-Time Password) support
- MFA setup and management

### 2. Efficient File Updates
- Partial file update support
- Optimized file modification process

## Technical Details

### Database Schema
- Users table
- Files table
- File shares table
- Activity logs table
- Password reset tokens table
- MFA settings table

### Security Measures
- Password hashing using PBKDF2-HMAC-SHA256
- AES-GCM for file encryption
- Secure random number generation
- Input validation and sanitization

### Dependencies
- Python 3.x
- SQLite3
- Cryptography library
- PyOTP for MFA
- Yagmail for email notifications

## Setup Instructions

1. Clone the repository
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database:
   ```bash
   python setup_admin.py
   ```
4. Configure environment variables:
   ```
   EMAIL_SENDER=your_email@example.com
   EMAIL_PASSWORD=your_email_password
   ```
5. Run the application:
   ```bash
   python -m client_menu
   ```

## Usage

### Regular User Operations
1. Register/Login
2. Upload/Download files
3. Share files with other users
4. View and manage owned files
5. Change password
6. Enable/Disable MFA

### Administrator Operations
1. View system logs
2. Monitor user activities
3. View system statistics
4. Manage user files
5. Access control management

## Security Considerations
- All passwords must meet minimum complexity requirements
- Files are encrypted before storage
- Access controls are strictly enforced
- Activity logging for security auditing
- Protection against common attacks (SQL injection, path traversal)

## Project Structure
```
secure_storage/
├── code/
│   ├── client_menu.py
│   ├── encryption_module.py
│   ├── file_manager.py
│   ├── mfa.py
│   ├── setup_admin.py
│   └── userManager.py
├── requirements.txt
└── README.md
```
