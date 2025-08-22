import os
import json
import random
import string
import getpass
from cryptography.fernet import Fernet

VAULT_DIR = r"C:\Nyx (python)\Aegis"
VAULT_FILE = os.path.join(VAULT_DIR, "vault.json")
BACKUP_FILE = os.path.join(VAULT_DIR, "vault_backup.json")
MASTER_FILE = os.path.join(VAULT_DIR, "master.key")

# Ensure vault directory exists
os.makedirs(VAULT_DIR, exist_ok=True)

def generate_key(password: str) -> bytes:
    # Simple key derivation for Fernet from password
    return Fernet(Fernet.generate_key())

def save_master_password(password: str):
    with open(MASTER_FILE, "w") as f:
        f.write(password)

def load_master_password():
    if os.path.exists(MASTER_FILE):
        with open(MASTER_FILE, "r") as f:
            return f.read().strip()
    return None

def encrypt_vault(data, fernet: Fernet):
    with open(VAULT_FILE, "wb") as f:
        f.write(fernet.encrypt(json.dumps(data).encode()))

def decrypt_vault(fernet: Fernet):
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as f:
            try:
                return json.loads(fernet.decrypt(f.read()).decode())
            except:
                print("⚠️ Vault corrupted or wrong master password.")
                return {}
    return {}

def save_backup(data):
    with open(BACKUP_FILE, "w") as f:
        json.dump(data, f, indent=2)

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def first_time_setup():
    print("🛡️ First-time setup: Create your master password")
    while True:
        pwd = getpass.getpass("Enter a master password: ").strip()
        pwd_confirm = getpass.getpass("Confirm master password: ").strip()
        if pwd and pwd == pwd_confirm:
            save_master_password(pwd)
            print("✅ Master password saved!\n")
            return pwd
        print("❌ Passwords do not match or empty. Try again.")

def authenticate():
    master_pwd = load_master_password() or first_time_setup()
    for _ in range(3):
        attempt = getpass.getpass("Enter Master Password: ").strip()
        if attempt == master_pwd:
            print("🔑 Access Granted!\n")
            return master_pwd
        print("❌ Incorrect password.")
    print("⛔ Too many failed attempts. Exiting.")
    exit()

def add_entry(vault, fernet):
    name = input("Account name: ").strip()
    if not name:
        print("❌ Account name cannot be empty.")
        return
    user = input("Username (leave blank if none): ").strip()
    password = input("Password (type 'auto' to generate): ").strip()
    if password.lower() == "auto" or not password:
        password = generate_password()
        print(f"🔑 Generated password: {password}")
    vault[name] = {"user": user, "password": password}
    encrypt_vault(vault, fernet)
    print(f"💾 Saved {name} successfully!\n")

def view_vault(vault):
    if not vault:
        print("📭 Vault is empty.\n")
        return
    for name, data in vault.items():
        print(f"📝 Account: {name}")
        print(f"👤 Username: {data.get('user', '<unknown>')}")
        print(f"🔑 Password: {data.get('password', '<unknown>')}\n")

def remove_entry(vault, fernet):
    if not vault:
        print("📭 Vault empty. Nothing to remove.\n")
        return
    name = input("Enter the account name to remove: ").strip()
    if name in vault:
        del vault[name]
        encrypt_vault(vault, fernet)
        print(f"🗑️ Removed {name} successfully!\n")
    else:
        print(f"❌ No entry found for {name}.\n")

def search_entry(vault):
    query = input("Enter account name to search: ").strip().lower()
    results = {k: v for k, v in vault.items() if query in k.lower()}
    if results:
        print("🔍 Search Results:")
        for name, data in results.items():
            print(f"📝 Account: {name}")
            print(f"👤 Username: {data.get('user', '<unknown>')}")
            print(f"🔑 Password: {data.get('password', '<unknown>')}\n")
    else:
        print("❌ No matches found.\n")

def change_master_password(vault, fernet):
    print("⚠️ Changing master password will clear the vault for safety.")
    backup = vault.copy()
    save_backup(backup)
    print(f"💾 Vault backup saved at {BACKUP_FILE}")
    new_pwd = first_time_setup()
    fernet = Fernet(generate_key(new_pwd))
    encrypt_vault({}, fernet)
    print("✅ Master password changed, vault cleared.")

def main():
    master_password = authenticate()
    fernet = Fernet(generate_key(master_password))
    vault = decrypt_vault(fernet)

    while True:
        print("\nOptions: [1] Add Entry  [2] View Vault  [3] Remove Entry  [4] Search  [5] Change Master Password  [6] Exit")
        choice = input("Select an option: ").strip()
        if choice == "1":
            add_entry(vault, fernet)
        elif choice == "2":
            view_vault(vault)
        elif choice == "3":
            remove_entry(vault, fernet)
        elif choice == "4":
            search_entry(vault)
        elif choice == "5":
            change_master_password(vault, fernet)
            vault = {}
        elif choice == "6":
            print("👋 Exiting Aegis. Stay safe!")
            break
        else:
            print("❌ Invalid option, try again.")

if __name__ == "__main__":
    main()
