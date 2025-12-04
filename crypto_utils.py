import os
import base64
import bcrypt
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_user_salt(username: str) -> bytes:
    """
    Generates a deterministic salt based on the username.
    This ensures we can derive the same key for a user every time 
    they log in, provided they type the correct username.
    """
    # Pad or slice to ensure 16 bytes
    return username.encode().ljust(16, b'0')[:16]

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a safe url-encoded base64 key for Fernet"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_data(data: str, master_password: str, salt: bytes) -> str:
    """Encrypts string data using the master password"""
    if not data:
        return ""
    key = derive_key(master_password, salt)
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, master_password: str, salt: bytes) -> str:
    """Decrypts string data using the master password"""
    if not encrypted_data:
        return ""
    try:
        key = derive_key(master_password, salt)
        f = Fernet(key)
        return f.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return "[Decryption Failed]"

def hash_password(password: str) -> str:
    """Hashes password using Bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed_password: str) -> bool:
    """Verifies a password against a Bcrypt hash"""
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def get_searchable_hash(text: str) -> str:
    """
    Creates a deterministic hash (SHA256) of a string.
    Used for looking up users in the DB without storing the plaintext username.
    """
    return hashlib.sha256(text.lower().encode()).hexdigest()