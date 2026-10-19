
import os
import json
import base64
import getpass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


VAULT_FILE = Path("vault.json")
SALT_SIZE = 16
NONCE_SIZE = 12


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key from the master password."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_vault(data: dict, key: bytes) -> dict:
    """Encrypt vault data and return a JSON-compatible structure."""
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_vault(encrypted_data: dict, key: bytes) -> dict:
    """Decrypt the vault and verify its authentication tag."""
    nonce = base64.b64decode(encrypted_data["nonce"], validate=True)
    ciphertext = base64.b64decode(
        encrypted_data["ciphertext"], validate=True
    )

    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def save_vault(data: dict, key: bytes) -> None:
    """Encrypt and save the vault to disk."""
    encrypted_data = encrypt_vault(data, key)
    temporary_file = VAULT_FILE.with_suffix(".tmp")

    try:
        with temporary_file.open("x", encoding="utf-8") as file:
            json.dump(encrypted_data, file, indent=2)
        os.replace(temporary_file, VAULT_FILE)
    finally:
        if temporary_file.exists():
            temporary_file.unlink()


def main():
    print("=== Secure Password Manager ===")

    if VAULT_FILE.exists():
        print("Existing vault found.")
        master_password = getpass.getpass("Master password: ")

        try:
            with VAULT_FILE.open("r", encoding="utf-8") as file:
                encrypted_data = json.load(file)

            salt = base64.b64decode(
                encrypted_data["salt"], validate=True
            )
            key = derive_key(master_password, salt)
            vault = decrypt_vault(encrypted_data, key)

        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            print("Could not unlock vault. Check the password or vault file.")
            return
        except Exception as exc:
            from cryptography.exceptions import InvalidTag

            if isinstance(exc, InvalidTag):
                print("Could not unlock vault. Check the password or vault file.")
                return
            raise

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

        encrypted_data = encrypt_vault(vault, key)
        encrypted_data["salt"] = base64.b64encode(salt).decode("ascii")

        with VAULT_FILE.open("x", encoding="utf-8") as file:
            json.dump(encrypted_data, file, indent=2)

        print("New encrypted vault created successfully.")

    print("Prototype ready. Account management comes next.")


if __name__ == "__main__":
    main()
