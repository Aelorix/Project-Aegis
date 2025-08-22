import os
import json
import base64
import getpass
from cryptography.fernet import Fernet
from hashlib import sha256
import random
import string

VAULT_DIR = r"C:\Nyx (python)\Aegis"
VAULT_FILE = os.path.join(VAULT_DIR, "vault.json")
MASTER_FILE = os.path.join(VAULT_DIR, "master.hash")

os.makedirs(VAULT_DIR, exist_ok=True)

# Helper: generate a random password
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Helper: derive Fernet key from password
def derive_key(password):
    hash_bytes = sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash_bytes)

# Load encrypted vault
def load_vault(master_password):
    if not os.path.exists(VAULT_FILE):
        return {}
    key = derive_key(master_password)
    fernet = Fernet(key)
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted)
    except Exception:
        print("Incorrect master password or vault corrupted.")
        return None

# Save encrypted vault
def save_vault(vault, master_password):
    key = derive_key(master_password)
    fernet = Fernet(key)
    data = json.dumps(vault, indent=2).encode()
    encrypted = fernet.encrypt(data)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

# First-time setup
def setup_master_password():
    print("=== First-Time Setup: Create Master Password ===")
    while True:
        pwd = getpass.getpass("Enter new master password: ").strip()
        pwd_confirm = getpass.getpass("Confirm master password: ").strip()
        if pwd == pwd_confirm and pwd:
            hashed = sha256(pwd.encode()).hexdigest()
            with open(MASTER_FILE, "w") as f:
                f.write(hashed)
            print("Master password set successfully!\n")
            return pwd
        print("Passwords do not match or empty. Try again.")

# Verify master password
def authenticate():
    if not os.path.exists(MASTER_FILE):
        return setup_master_password()

    with open(MASTER_FILE, "r") as f:
        saved_hash = f.read().strip()

    for _ in range(3):
        pwd = getpass.getpass("Enter Master Password: ").strip()
        if sha256(pwd.encode()).hexdigest() == saved_hash:
            print("Access Granted.\n")
            return pwd
        print("Incorrect password.")
    print("Too many failed attempts. Exiting.")
    return None

# Vault operations
def add_entry(vault):
    name = input("Account name: ").strip()
    if not name:
        print("Account name cannot be empty.")
        return
    user = input("Username (leave blank if none): ").strip()
    password = input("Password (type 'auto' to generate): ").strip()
    if password.lower() == "auto" or password == "":
        password = generate_password()
        print(f"Generated password: {password}")
    vault[name] = {"user": user, "password": password}
    print(f"Saved {name} successfully!\n")

def view_vault(vault):
    if not vault:
        print("Vault is empty.\n")
        return
    for name, data in vault.items():
        user = data.get("user", "<unknown>")
        password = data.get("password", "<unknown>")
        print(f"Account: {name}")
        print(f"Username: {user}")
        print(f"Password: {password}\n")

def remove_entry(vault):
    if not vault:
        print("Vault is empty, nothing to remove.\n")
        return
    name = input("Enter the account name to remove: ").strip()
    if name in vault:
        del vault[name]
        print(f"Removed {name} successfully!\n")
    else:
        print(f"No entry found for {name}.\n")

def search_entry(vault):
    query = input("Enter account name to search: ").strip().lower()
    results = {k: v for k, v in vault.items() if query in k.lower()}
    if results:
        print("\nSearch Results:")
        for name, data in results.items():
            print(f"Account: {name}")
            print(f"Username: {data.get('user', '<unknown>')}")
            print(f"Password: {data.get('password', '<unknown>')}\n")
    else:
        print("No matches found.\n")

def main():
    master_password = authenticate()
    if not master_password:
        return

    vault = load_vault(master_password)
    if vault is None:  # failed to decrypt
        return

    while True:
        print("\nOptions: [1] Add Entry  [2] View Vault  [3] Remove Entry  [4] Search  [5] Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            add_entry(vault)
        elif choice == "2":
            view_vault(vault)
        elif choice == "3":
            remove_entry(vault)
        elif choice == "4":
            search_entry(vault)
        elif choice == "5":
            save_vault(vault, master_password)
            print("Exiting Aegis. Vault saved securely!")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main()
