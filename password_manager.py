
import os
import json
import base64
import getpass
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


VAULT_FILE = Path("vault.json")
SALT_SIZE = 16
NONCE_SIZE = 12


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the master password."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_vault(data: dict, key: bytes) -> dict:
    """Encrypt vault data with AES-GCM."""
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_vault(encrypted_data: dict, key: bytes) -> dict:
    """Decrypt the vault and authenticate its contents."""
    nonce = base64.b64decode(
        encrypted_data["nonce"], validate=True
    )
    ciphertext = base64.b64decode(
        encrypted_data["ciphertext"], validate=True
    )

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid nonce length")

    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    data = json.loads(plaintext.decode("utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Invalid vault data")

    return data


def save_vault(data: dict, key: bytes, salt: bytes) -> None:
    """Encrypt and save the vault, preserving its salt."""
    encrypted_data = encrypt_vault(data, key)
    encrypted_data["salt"] = base64.b64encode(salt).decode("ascii")

    temporary_file = VAULT_FILE.with_suffix(".tmp")

    try:
        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(encrypted_data, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary_file, VAULT_FILE)
    finally:
        if temporary_file.exists():
            temporary_file.unlink()


def add_account(vault: dict, key: bytes, salt: bytes) -> None:
    """Add an account without displaying its password."""
    site = input("Website or service: ").strip()
    username = input("Username or email: ").strip()
    password = getpass.getpass("Account password: ")

    if not site or not username or not password:
        print("All fields are required.")
        return

    account_id = uuid.uuid4().hex

    vault[account_id] = {
        "site": site,
        "username": username,
        "password": password,
    }

    try:
        save_vault(vault, key, salt)
    except OSError:
        del vault[account_id]
        print("Could not save the vault. Check file permissions and disk space.")
        return

    print("Account saved successfully.")


def list_accounts(vault: dict) -> None:
    """List account names and usernames, never passwords."""
    if not vault:
        print("Your vault is empty.")
        return

    print("\nSaved accounts:")
    for account_id, account in vault.items():
        print(
            f"ID: {account_id[:8]} | "
            f"Site: {account['site']} | "
            f"Username: {account['username']}"
        )


def find_accounts(vault: dict) -> None:
    """Search accounts by website or username."""
    query = input("Search website or username: ").strip().casefold()

    if not query:
        print("Search cannot be empty.")
        return

    matches = [
        (account_id, account)
        for account_id, account in vault.items()
        if query in account["site"].casefold()
        or query in account["username"].casefold()
    ]

    if not matches:
        print("No matching accounts found.")
        return

    for account_id, account in matches:
        print(
            f"ID: {account_id[:8]} | "
            f"Site: {account['site']} | "
            f"Username: {account['username']}"
        )


def reveal_password(vault: dict) -> None:
    """Reveal a password only when explicitly requested."""
    account_id = input("Enter the account ID shown in the list: ").strip()

    matches = [
        (full_id, account)
        for full_id, account in vault.items()
        if full_id.startswith(account_id)
    ]

    if not account_id or len(matches) != 1:
        print("Account ID not found or ambiguous.")
        return

    _, account = matches[0]
    print(f"Website: {account['site']}")
    print(f"Username: {account['username']}")
    print(f"Password: {account['password']}")


def delete_account(vault: dict, key: bytes, salt: bytes) -> None:
    """Delete an account after explicit confirmation."""
    account_id = input("Enter the account ID to delete: ").strip()

    matches = [
        full_id
        for full_id in vault
        if full_id.startswith(account_id)
    ]

    if not account_id or len(matches) != 1:
        print("Account ID not found or ambiguous.")
        return

    full_id = matches[0]
    confirmation = input("Type DELETE to confirm: ")

    if confirmation != "DELETE":
        print("Deletion cancelled.")
        return

    removed = vault.pop(full_id)

    try:
        save_vault(vault, key, salt)
    except OSError:
        vault[full_id] = removed
        print("Could not save changes. The account was restored in memory.")
        return

    print("Account deleted.")


def run_menu(vault: dict, key: bytes, salt: bytes) -> None:
    while True:
        print(
            "\n=== Password Manager ===\n"
            "1. Add account\n"
            "2. List accounts\n"
            "3. Search accounts\n"
            "4. Reveal account password\n"
            "5. Delete account\n"
            "6. Lock and exit"
        )

        choice = input("Choose an option: ").strip()

        if choice == "1":
            add_account(vault, key, salt)
        elif choice == "2":
            list_accounts(vault)
        elif choice == "3":
            find_accounts(vault)
        elif choice == "4":
            reveal_password(vault)
        elif choice == "5":
            delete_account(vault, key, salt)
        elif choice == "6":
            print("Vault locked. Goodbye.")
            return
        else:
            print("Invalid choice. Enter a number from 1 to 6.")


def main() -> None:
    print("=== Secure Password Manager ===")

    if VAULT_FILE.exists():
        print("Existing vault found.")

        try:
            with VAULT_FILE.open("r", encoding="utf-8") as file:
                encrypted_data = json.load(file)

            if not isinstance(encrypted_data, dict):
                raise ValueError("Invalid vault format")

            salt = base64.b64decode(
                encrypted_data["salt"], validate=True
            )

            if len(salt) != SALT_SIZE:
                raise ValueError("Invalid salt length")

            master_password = getpass.getpass("Master password: ")
            key = derive_key(master_password, salt)
            vault = decrypt_vault(encrypted_data, key)

            for account in vault.values():
                if (
                    not isinstance(account, dict)
                    or not all(
                        isinstance(account.get(field), str)
                        for field in ("site", "username", "password")
                    )
                ):
                    raise ValueError("Invalid account data")

        except (InvalidTag, ValueError, KeyError, TypeError, OSError,
                json.JSONDecodeError) as exc:
            print(
                "Could not unlock vault. Check the password or vault file."
            )
            return

        print(f"Vault unlocked. Saved entries: {len(vault)}")

    else:
        print("No vault found. Creating a new vault.")

        master_password = getpass.getpass("Create master password: ")
        confirmation = getpass.getpass("Confirm master password: ")

        if len(master_password) < 12:
            print("Use a master password with at least 12 characters.")
            return

        if master_password != confirmation:
            print("Passwords do not match.")
            return

        salt = os.urandom(SALT_SIZE)
        key = derive_key(master_password, salt)
        vault = {}

        try:
            save_vault(vault, key, salt)
        except OSError:
            print("Could not create the vault. Check file permissions.")
            return

        print("New encrypted vault created successfully.")

    run_menu(vault, key, salt)


if __name__ == "__main__":
    main()
