import sqlite3
from datetime import datetime

DB_PATH = "password_manager.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  encrypted_name TEXT NOT NULL,
                  encrypted_username TEXT NOT NULL,
                  username_hash TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  encrypted_dek TEXT NOT NULL, 
                  reveal_key TEXT DEFAULT 'v',
                  hide_key TEXT DEFAULT 'h',
                  exit_key TEXT DEFAULT 'esc')''')
    
    conn.execute('''CREATE TABLE IF NOT EXISTS credentials
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  encrypted_website TEXT NOT NULL,
                  encrypted_custom_name TEXT,
                  encrypted_username TEXT NOT NULL,
                  encrypted_password TEXT NOT NULL,
                  is_private INTEGER DEFAULT 0,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    conn.commit()
    conn.close()

# --- User Ops ---

def create_user(enc_name, enc_user, user_hash, pw_hash, enc_dek):
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO users (encrypted_name, encrypted_username, 
               username_hash, password_hash, encrypted_dek) 
               VALUES (?, ?, ?, ?, ?)""",
            (enc_name, enc_user, user_hash, pw_hash, enc_dek)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def fetch_user_by_hash(user_hash):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username_hash = ?", (user_hash,)).fetchone()
    conn.close()
    return user

def update_password_and_key(user_id, pw_hash, new_enc_dek):
    conn = get_db()
    conn.execute("UPDATE users SET password_hash = ?, encrypted_dek = ? WHERE id = ?",
                 (pw_hash, new_enc_dek, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = get_db()
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def get_user_keys(user_id):
    conn = get_db()
    row = conn.execute("SELECT reveal_key, hide_key, exit_key FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return tuple(row) if row else ('v', 'h', 'esc')

def update_user_keys(user_id: int, reveal: str, hide: str, exit_k: str):
    conn = get_db()
    conn.execute("UPDATE users SET reveal_key = ?, hide_key = ?, exit_key = ? WHERE id = ?",
                 (reveal, hide, exit_k, user_id))
    conn.commit()
    conn.close()

# --- Credential Ops ---

def add_credential(user_id, e_web, e_cust, e_user, e_pass, is_priv):
    conn = get_db()
    conn.execute("""INSERT INTO credentials 
        (user_id, encrypted_website, encrypted_custom_name, encrypted_username, 
         encrypted_password, is_private) VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, e_web, e_cust, e_user, e_pass, is_priv))
    conn.commit()
    conn.close()

def get_credentials(user_id):
    conn = get_db()
    rows = conn.execute("SELECT * FROM credentials WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()
    return rows

def update_credential(cred_id, e_web, e_cust, e_user, e_pass, is_priv):
    conn = get_db()
    conn.execute("""UPDATE credentials SET encrypted_website=?, encrypted_custom_name=?, 
        encrypted_username=?, encrypted_password=?, is_private=?, updated_at=? WHERE id=?""",
        (e_web, e_cust, e_user, e_pass, is_priv, datetime.now(), cred_id))
    conn.commit()
    conn.close()

def delete_credential(cred_id):
    conn = get_db()
    conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    conn.commit()
    conn.close()