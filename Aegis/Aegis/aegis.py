import os
import json
import random
import string
import getpass
from cryptography.fernet import Fernet

VAULT_DIR = r"C:\Nyx (python)\Aegis"
VAULT_FILE = os.path.join(VAULT_DIR, "vault.json")
KEY_FILE = os.path.join(VAULT_DIR, "key.key")

# Ensure vault directory exists
os.makedirs(VAULT_DIR, exist_ok=True)

# --- Encryption utilities ---
def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

fernet = Fernet(load_key())

def save_vault(vault):
    encrypted_data = fernet.encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)

def load_vault():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as f:
            try:
                data = fernet.decrypt(f.read())
                vault = json.loads(data)
                if not isinstance(vault, dict):
                    return {}
                return vault
            except Exception:
                print("Vault file corrupted or invalid. Starting empty vault.")
                return {}
    return {}

vault = load_vault()

# --- Utility functions ---
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def add_entry():
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
    save_vault(vault)
    print(f"Saved {name} successfully!\n")

def view_vault():
    if not vault:
        print("Vault is empty.\n")
        return
    for name, data in vault.items():
        user = data.get("user", "<unknown>")
        password = data.get("password", "<unknown>")
        print(f"Account: {name}")
        print(f"Username: {user}")
        print(f"Password: {password}\n")

def remove_entry():
    if not vault:
        print("Vault is empty, nothing to remove.\n")
        return
    name = input("Enter the account name to remove: ").strip()
    if name in vault:
        del vault[name]
        save_vault(vault)
        print(f"Removed {name} successfully!\n")
    else:
        print(f"No entry found for {name}.\n")

def search_entry():
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

# --- Master password ---
MASTER_PASSWORD_FILE = os.path.join(VAULT_DIR, "master.txt")

def authenticate():
    if not os.path.exists(MASTER_PASSWORD_FILE):
        # First-time setup
        print("=== First-time Setup ===")
        pwd1 = getpass.getpass("Set your master password: ").strip()
        pwd2 = getpass.getpass("Confirm master password: ").strip()
        if pwd1 != pwd2 or not pwd1:
            print("Passwords did not match or empty. Exiting.")
            return False
        with open(MASTER_PASSWORD_FILE, "w") as f:
            f.write(pwd1)
        print("Master password set. Access Granted.\n")
        return True
    else:
        # Existing setup
        with open(MASTER_PASSWORD_FILE, "r") as f:
            master_pwd = f.read().strip()
        print("=== Aegis Password Manager ===")
        for _ in range(3):
            pwd = getpass.getpass("Enter Master Password: ").strip()
            if pwd == master_pwd:
                print("Access Granted.\n")
                return True
            else:
                print("Incorrect password.")
        print("Too many failed attempts. Exiting.")
        return False

# --- Main loop ---
def main():
    if not authenticate():
        return
    while True:
        print("\nOptions: [1] Add Entry  [2] View Vault  [3] Remove Entry  [4] Search  [5] Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            add_entry()
        elif choice == "2":
            view_vault()
        elif choice == "3":
            remove_entry()
        elif choice == "4":
            search_entry()
        elif choice == "5":
            print("Exiting Aegis. Stay safe!")
            break
        else:
            print("Invalid option, try again.")

if __name__ == "__main__":
    main()
