import sqlite3
import hashlib
import secrets

def create_admin():
    conn = sqlite3.connect('secure_storage.db')
    cursor = conn.cursor()

    # Admin credentials
    username = 'admin'
    password = 'AdminPass123!'
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()

    # Insert admin user
    cursor.execute(
        'INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, 1)',
        (username, password_hash, salt)
    )
    conn.commit()
    conn.close()
    print("Admin user created successfully")

if __name__ == "__main__":
    create_admin()
