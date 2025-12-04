import sqlite3
from datetime import datetime
import crypto_utils as crypto

DB_PATH = "password_manager.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Updated Schema: name and username are now encrypted. 
    # username_hash is used for the UNIQUE constraint and lookups.
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  encrypted_name TEXT NOT NULL,
                  encrypted_username TEXT NOT NULL,
                  username_hash TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  reveal_key TEXT DEFAULT 'v',
                  hide_key TEXT DEFAULT 'h',
                  exit_key TEXT DEFAULT 'esc')''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS credentials
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  encrypted_website TEXT NOT NULL,
                  encrypted_custom_name TEXT,
                  encrypted_username TEXT NOT NULL,
                  encrypted_password TEXT NOT NULL,
                  is_private INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# --- User Management ---

def create_user(name: str, username: str, password: str) -> bool:
    """
    Creates a user with full encryption for name and username.
    """
    salt = crypto.get_user_salt(username)
    
    # Encrypt PII
    enc_name = crypto.encrypt_data(name, password, salt)
    enc_username = crypto.encrypt_data(username, password, salt)
    
    # Create blind index for lookup
    username_hash = crypto.get_searchable_hash(username)
    
    # Hash password
    pw_hash = crypto.hash_password(password)

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (encrypted_name, encrypted_username, username_hash, password_hash) VALUES (?, ?, ?, ?)",
            (enc_name, enc_username, username_hash, pw_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username: str, password: str) -> tuple:
    """
    Verifies user login. Returns (user_id, decrypted_username) or (None, None).
    """
    username_hash = crypto.get_searchable_hash(username)
    
    conn = get_db_connection()
    user = conn.execute("SELECT id, password_hash FROM users WHERE username_hash = ?", (username_hash,)).fetchone()
    conn.close()
    
    if user and crypto.check_password(password, user['password_hash']):
        return user['id'], username
    return None, None

def get_user_keys(user_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT reveal_key, hide_key, exit_key FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return tuple(row) if row else ('v', 'h', 'esc')

def update_user_keys(user_id: int, reveal: str, hide: str, exit_k: str):
    conn = get_db_connection()
    conn.execute("UPDATE users SET reveal_key = ?, hide_key = ?, exit_key = ? WHERE id = ?",
                 (reveal, hide, exit_k, user_id))
    conn.commit()
    conn.close()

def delete_user_account(user_id: int):
    conn = get_db_connection()
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

# --- Credential Management ---

def add_credential(user_id, enc_web, enc_custom, enc_user, enc_pass, is_private):
    conn = get_db_connection()
    conn.execute("""INSERT INTO credentials 
                    (user_id, encrypted_website, encrypted_custom_name, encrypted_username, 
                     encrypted_password, is_private) VALUES (?, ?, ?, ?, ?, ?)""",
                 (user_id, enc_web, enc_custom, enc_user, enc_pass, is_private))
    conn.commit()
    conn.close()

def get_credentials(user_id):
    conn = get_db_connection()
    creds = conn.execute("SELECT * FROM credentials WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    return creds

def update_credential(cred_id, enc_web, enc_custom, enc_user, enc_pass, is_private):
    conn = get_db_connection()
    conn.execute("""UPDATE credentials 
                    SET encrypted_website = ?, encrypted_custom_name = ?, 
                        encrypted_username = ?, encrypted_password = ?, 
                        is_private = ?, updated_at = ? 
                    WHERE id = ?""",
                 (enc_web, enc_custom, enc_user, enc_pass, is_private, datetime.now(), cred_id))
    conn.commit()
    conn.close()

def delete_credential(cred_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    conn.commit()
    conn.close()