import base64
import os
import bcrypt
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from contextlib import contextmanager

# --- Core Crypto Primitives ---

def get_salt(username: str) -> bytes:
    """Deterministic salt for user (16 bytes)"""
    return username.encode().ljust(16, b'0')[:16]

def derive_kek(master_password: str, salt: bytes) -> bytes:
    """
    Derive Key Encryption Key (KEK).
    Used ONLY to unwrap the Data Encryption Key (DEK).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000, 
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def generate_dek() -> bytes:
    """Generates a random 32-byte Data Encryption Key"""
    return Fernet.generate_key()

def encrypt_dek(dek: bytes, kek: bytes) -> str:
    """Wrap the Data Key with the Password-Derived Key"""
    f = Fernet(kek)
    return f.encrypt(dek).decode()

def decrypt_dek(encrypted_dek: str, kek: bytes) -> bytes:
    """Unwrap the Data Key"""
    f = Fernet(kek)
    return f.decrypt(encrypted_dek.encode())

# --- Memory Guard (XOR Obfuscation) ---

class SafeSession:
    """
    Stores the Data Key in an obfuscated state (XORed with random noise).
    """
    def __init__(self, raw_dek: bytes):
        self._nonce = os.urandom(len(raw_dek))
        self._obfuscated = self._xor_bytes(raw_dek, self._nonce)
        # Verify integrity immediately
        assert self._xor_bytes(self._obfuscated, self._nonce) == raw_dek
        del raw_dek

    def _xor_bytes(self, b1: bytes, b2: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(b1, b2))

    @contextmanager
    def access_key(self):
        """Context manager to briefly reconstruct the key."""
        temp_key = self._xor_bytes(self._obfuscated, self._nonce)
        try:
            yield temp_key
        finally:
            del temp_key

# --- Data Operations ---

def encrypt_string(data: str, safe_session: SafeSession) -> str:
    if not data: return ""
    with safe_session.access_key() as key:
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()

def decrypt_string(encrypted_data: str, safe_session: SafeSession) -> str:
    if not encrypted_data: return ""
    try:
        with safe_session.access_key() as key:
            f = Fernet(key)
            return f.decrypt(encrypted_data.encode()).decode()
    except Exception:
        return "[Decryption Failed]"

# --- Auth Helpers ---

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def get_blind_index(text: str) -> str:
    """SHA-256 hash for database lookups"""
    return hashlib.sha256(text.lower().encode()).hexdigest()