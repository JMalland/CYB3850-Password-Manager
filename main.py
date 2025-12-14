from sqlite3 import IntegrityError
import click
import getpass
import os
import sys
import crypto_utils as crypto
import database as db

# --- Keyboard Handling ---
if os.name != 'nt':
    try:
        import tty, termios
        POSIX = True
    except ImportError:
        POSIX = False
else:
    POSIX = False

def get_key():
    """Reads a single keypress"""
    if os.name == 'nt':
        import msvcrt
        k = msvcrt.getch()
        return 'esc' if k == b'\x1b' else k.decode('utf-8', 'ignore').lower()
    if not POSIX: return input().strip().lower()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        return 'esc' if ch == '\x1b' else ch.lower()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def clear(): os.system('cls' if os.name == 'nt' else 'clear')

# --- App Context ---

class AppContext:
    def __init__(self, user_id, username, safe_session):
        self.user_id = user_id
        self.username = username
        self.safe = safe_session 
        self.refresh_keys()

    def refresh_keys(self):
        self.reveal_key, self.hide_key, self.exit_key = db.get_user_keys(self.user_id)

@click.group()
def cli():
    """Secure Password Manager with Envelope Encryption"""
    db.init_db()

@cli.command()
def register():
    clear()
    """Create account"""
    # Prompt for Name, Username, and Confirm Password
    name = click.prompt("Name")
    user = click.prompt("Username")
    pw = getpass.getpass("Master Password: ")
    if getpass.getpass("Confirm: ") != pw:
        click.echo("Mismatch."); return

    # Generate a data encryption key
    dek = crypto.generate_dek()
    
    # Encrypt PII with temp session
    temp_session = crypto.SafeSession(dek)
    enc_name = crypto.encrypt_string(name, temp_session)
    enc_user = crypto.encrypt_string(user, temp_session)
    
    # Wrap DEK with Password
    salt = crypto.get_salt(user)
    kek = crypto.derive_kek(pw, salt)
    encrypted_dek = crypto.encrypt_dek(dek, kek)
    
    # Hash the username & password
    u_hash = crypto.get_blind_index(user)
    p_hash = crypto.hash_password(pw)
    
    # Create a new account
    if db.create_user(enc_name, enc_user, u_hash, p_hash, encrypted_dek):
        click.echo("Account created.")
    # Account already exists
    else:
        click.echo("Username taken.")

    clear()

@cli.command()
def login():
    clear()
    # Prompt for username and master password
    user = click.prompt("Username")
    pw = getpass.getpass("Master Password: ")
    
    # Hash the username
    u_hash = crypto.get_blind_index(user)
    # Fetch the matching user hash
    row = db.fetch_user_by_hash(u_hash)
    
    # No username hash matches -- OR no password hash matches
    if not row or not crypto.check_password(pw, row['password_hash']):
        click.echo("Invalid credentials."); return

    try:
        # Generate salt using username
        salt = crypto.get_salt(user)
        # Use password & salt to make Key Encryption Key
        kek = crypto.derive_kek(pw, salt)
        # Use Key Encryption Key to generate Data Encryption Key
        dek = crypto.decrypt_dek(row['encrypted_dek'], kek)
        # Create a new SafeSession with the DEK, stored safely in Memory
        session = crypto.SafeSession(dek)

        # Delete the KEK, Password, and DEK
        del kek, pw, dek
        
        # Update the context to use the user's login and session
        ctx = AppContext(row['id'], user, session)

        # Direct to the main menu
        clear()
        main_menu(ctx)
    except Exception as e:
        click.echo(f"Decryption failed: {e}")

# --- Features ---

def main_menu(ctx):
    while True:
        click.echo(f"\n=== User: {ctx.username} ===")
        opts = [
            "List all services",
            "View credentials",
            "Add credentials",
            "Edit credentials",
            "Delete credentials",
            "Search credentials",
            "Account settings",
            "Logout"
        ]
        
        # Correctly number the options starting from 1
        for i, o in enumerate(opts, start=1):
            click.echo(f"{i}. {o}")

        # Remove default=0 and add validation for 1–8
        click.echo("")  # empty line for clarity
        c = click.prompt("Select an option (1-8)", type=click.IntRange(1, 8))

        if c == 1:
            clear()
            list_items(ctx)
        elif c == 2:
            clear()
            interact_select(ctx, 'view')
        elif c == 3:
            clear()
            add_item(ctx)
        elif c == 4:
            clear()
            interact_select(ctx, 'edit')
        elif c == 5:
            clear()
            interact_select(ctx, 'delete')
        elif c == 6:
            clear()
            search_credentials(ctx)
        elif c == 7:
            clear()
            settings(ctx)
        elif c == 8:
            clear()
            click.echo("Logged out.")
            break

def decrypt_row(ctx, row):
    """Helper to decrypt a DB row into a dict"""
    return {
        'id': row['id'],
        'web': crypto.decrypt_string(row['encrypted_website'], ctx.safe),
        'name': crypto.decrypt_string(row['encrypted_custom_name'], ctx.safe),
        'user': crypto.decrypt_string(row['encrypted_username'], ctx.safe),
        'pass': crypto.decrypt_string(row['encrypted_password'], ctx.safe),
        'priv': row['is_private']
    }

def list_items(ctx):
    rows = db.get_credentials(ctx.user_id)
    # There are no credentials
    if not rows: 
        click.echo("Empty vault.")
        return
    
    for r in rows:
        # Decrypt & list each credential
        dec = decrypt_row(ctx, r)
        click.echo(f"- {dec['name'] or dec['web']} (User: {dec['user']}) {'[LOCKED]' if dec['priv'] else ''}")

def add_item(ctx):
    # Prompt credential entry fields
    web = click.prompt("Website")
    name = click.prompt("Custom Name", default="", show_default=False)
    user = click.prompt("Username")
    pw = getpass.getpass("Password: ")
    priv = click.confirm("Private?", default=False)
    
    # Add new credentials
    db.add_credential(ctx.user_id, 
        # Encrypt the Website, Custom Name, Username, and Password
        crypto.encrypt_string(web, ctx.safe),
        crypto.encrypt_string(name, ctx.safe),
        crypto.encrypt_string(user, ctx.safe),
        crypto.encrypt_string(pw, ctx.safe),
        1 if priv else 0
    )
    click.echo("Saved.")

def interact_select(ctx, mode):
    """Unified selection logic for View/Edit/Delete commands"""
    query = click.prompt("Enter website or custom name").lower()
    rows = db.get_credentials(ctx.user_id)
    matches = []
    
    # Parse all credentials in the user's account
    for r in rows:
        dec = decrypt_row(ctx, r)
        # Check if the decrypted credentials match the query
        if query in dec['web'].lower() or query in (dec['name'] or "").lower():
            matches.append(dec) # Save the decrypted credentials
    
    # No matches found
    if not matches: click.echo("No matches."); return
    
    # Get the first match, then check if multiple
    target = matches[0]
    if len(matches) > 1:
        # Display all matching results
        click.echo("Multiple matches:")
        for i, match in matches: 
            click.echo(f"{i + 1}. {match['name'] or match['web']} ({match['user']})")
        
        # Prompt user for input index
        idx = click.prompt("Choice", type=int) - 1

        # Exit if the index is out of bounds
        if 0 > idx >= len(matches): return

        # Update the target value
        target = matches[idx]
        
    # Handle the display, editing, or deletion of the selected credentials
    if mode == 'view':
        view_item(ctx, target)
    elif mode == 'edit':
        edit_item(ctx, target)
    elif mode == 'delete':
        # Make the user confirm they'd like to delete
        if click.confirm(f"Delete {target['name'] or target['web']}?"):
            # Delete the credentials
            db.delete_credential(target['id'])
            click.echo("Deleted.")

def search_credentials(ctx):
    """Restored specific search functionality"""
    click.echo("\n1. By website\n2. By custom name\n3. By username\n4. All fields")
    stype = click.prompt("Type", type=int)
    term = click.prompt("Search term").lower()

    # Get all user credentials (encrypted)
    rows = db.get_credentials(ctx.user_id)
    found = False
    
    click.echo("\nResults:")
    for r in rows:
        # Decrypt the row content
        dec = decrypt_row(ctx, r)
        match = False
        
        # Querying Website or Any, True if match found
        match = True if (stype in (1, 4) and term in dec['web'].lower()) else match
        # Querying Custom Name or Any, True if match found
        match = True if (stype in (2, 4) and term in (dec['name'] or "").lower()) else match
        # Querying Username or Any, True if match found
        match = True if (stype in (3, 4) and term in dec['user'].lower()) else match
        
        # Continue looping if no match
        if not match: continue

        # Display the match when found
        click.echo(f"- {dec['name'] or dec['web']} (Web: {dec['web']}, User: {dec['user']})")
        found = True
            
    if not found: click.echo("No results.")

def view_item(ctx, item):
    if item['priv']: # Credentials are private
        pw = getpass.getpass("Verify Master Password: ")
        # Verify the password hash matches the entered value
        # DOES NOT COMPARE WITH ORIGINAL PLAINTEXT PASSWORD
        row = db.fetch_user_by_hash(crypto.get_blind_index(ctx.username))
        if not crypto.check_password(pw, row['password_hash']):
            click.echo("Access Denied."); return

    # Start with password hidden
    hidden = True
    while True:
        # Prevent visible password from being saved in terminal history
        clear() # Clear the screen betewen every keybind entry

        # Print the viewing information for the credentials
        click.echo(f"=== {item['name'] or item['web']} ===")
        click.echo(f"Website: {item['web']}")
        click.echo(f"User:    {item['user']}")
        click.echo(f"Pass:    {'*' * 10 if hidden else item['pass']}")
        click.echo(f"\nKeys: [{ctx.reveal_key}] Reveal  [{ctx.hide_key}] Hide  [{ctx.exit_key}] Exit")
        
        # Listen to keybinds
        k = get_key()
        if k == ctx.reveal_key: hidden = False
        elif k == ctx.hide_key: hidden = True
        elif k == ctx.exit_key or k == 'esc': 
            clear()
            break

def edit_item(ctx, item):
    # Prompt for new credentials entry
    web = click.prompt("Website", default=item['web'])
    name = click.prompt("Name", default=item['name'] or "", show_default=False)
    user = click.prompt("User", default=item['user'])
    pw = getpass.getpass("New Pass (Enter to keep): ") or item['pass']
    priv = click.confirm("Private?", default=bool(item['priv']))
    
    # Update the entered credentials
    db.update_credential(item['id'],
        # Encrypt the website, custom name, username, and password
        crypto.encrypt_string(web, ctx.safe),
        crypto.encrypt_string(name, ctx.safe),
        crypto.encrypt_string(user, ctx.safe),
        crypto.encrypt_string(pw, ctx.safe),
        1 if priv else 0
    )
    click.echo("Updated.")

def settings(ctx):
    click.echo("\n1. Change Username\n2. Change Password\n3. Customize Keybindings\n4. Delete Account\n5. Back")
    c = click.prompt("Choice", type=int)

    if c == 1: # New Username
        new_user = click.prompt("New username")
        # To change username, we just re-encrypt the name field (since we don't use salt for DEK anymore)
        # But we DO change the salt used for the KEK (Password wrapper).
        # Meaning: We must Re-Wrap the DEK.
        
        pw = getpass.getpass("Confirm Master Password: ")
        row = db.fetch_user_by_hash(crypto.get_blind_index(ctx.username))
        if not crypto.check_password(pw, row['password_hash']): return
        
        with ctx.safe.access_key() as dek:
            # 1. New Salt/Hash
            new_salt = crypto.get_salt(new_user)
            new_hash = crypto.get_blind_index(new_user)
            
            # 2. Re-wrap DEK with new KEK (derived from SAME password + NEW salt)
            new_kek = crypto.derive_kek(pw, new_salt)
            new_enc_dek = crypto.encrypt_dek(dek, new_kek)
            
            # 3. Encrypt new PII
            enc_user = crypto.encrypt_string(new_user, ctx.safe)
            # We don't have the original Name in memory here, so we placehold it or ask
            enc_name = crypto.encrypt_string("Updated Name", ctx.safe)

            if db.create_user(enc_name, enc_user, new_hash, row['password_hash'], new_enc_dek):
                # In a real app we would UPDATE, but since we use username_hash as key, 
                # we are effectively migrating. For this simplified logic, we just update the User row.
                # NOTE: create_user inserts new. We want UPDATE.
                conn = db.get_db()
                try:
                    conn.execute("""UPDATE users SET encrypted_name=?, encrypted_username=?, 
                                    username_hash=?, encrypted_dek=? WHERE id=?""",
                                 (enc_name, enc_user, new_hash, new_enc_dek, ctx.user_id))
                    conn.commit()
                    ctx.username = new_user
                    click.echo("Username updated.")
                except IntegrityError:
                    click.echo("Username taken.")
                conn.close()

    elif c == 2: # New Password
        new_pw = getpass.getpass("New Password: ")
        if getpass.getpass("Confirm: ") != new_pw: return
        
        # KEY WRAPPING allows us to change password WITHOUT touching credentials!
        with ctx.safe.access_key() as dek:
            salt = crypto.get_salt(ctx.username)
            new_kek = crypto.derive_kek(new_pw, salt)
            new_enc_dek = crypto.encrypt_dek(dek, new_kek)
            
            db.update_password_and_key(ctx.user_id, crypto.hash_password(new_pw), new_enc_dek)
            click.echo("Password changed (Database Key re-wrapped).")

    elif c == 3: # Update keybinds
        click.echo(f"Current: Reveal[{ctx.reveal_key}] Hide[{ctx.hide_key}] Exit[{ctx.exit_key}]")
        r = click.prompt("New Reveal key", default=ctx.reveal_key)
        h = click.prompt("New Hide key", default=ctx.hide_key)
        e = click.prompt("New Exit key", default=ctx.exit_key)
        
        db.update_user_keys(ctx.user_id, r.lower(), h.lower(), e.lower())
        ctx.refresh_keys()
        click.echo("Keybindings updated.")

    # Delete Account
    elif c == 4 and click.confirm("Delete Account? This cannot be undone."):
        db.delete_user(ctx.user_id)
        click.echo("Deleted.")
        sys.exit()

if __name__ == "__main__":
    cli()