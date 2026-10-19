# Syntecxhub Password Manager

A Python-based password manager developed as part of the Syntecxhub Cybersecurity Internship.

The project demonstrates password-based key derivation, authenticated encryption, and secure local storage concepts.

## Features

- Derives a 256-bit encryption key from a master password using Scrypt.
- Encrypts vault data using AES-256-GCM.
- Uses a random salt and nonce.
- Stores encrypted vault data locally in JSON format.
- Requests passwords through a hidden terminal prompt.
- Verifies vault integrity during decryption.

## Technologies

- Python 3.13
- `cryptography`
- Scrypt key derivation
- AES-GCM authenticated encryption
- JSON

## Requirements

- Python 3.10 or later
- pip

## Installation

Clone the repository:

```powershell
git clone https://github.com/HazemAboelkhier7/Syntecxhub_Password_Manager.git
cd Syntecxhub_Password_Manager
```

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependency:

```powershell
python -m pip install cryptography
```

## Usage

Run the application:

```powershell
python password_manager.py
```

On the first run, the application prompts you to create and confirm a master password and creates a local encrypted vault.

On subsequent runs, enter the master password to unlock the existing vault.

## Security Notes

- The master password is not stored directly in the vault.
- The vault file contains encrypted data, a salt, and a nonce.
- Keep `vault.json` private and do not commit it to Git.
- Keep `.venv/` out of version control.
- If the master password is lost, the vault cannot be unlocked through the current application.
- This project is an educational prototype and has not been independently security-audited. Do not rely on it to protect important real-world credentials yet.

## Planned Improvements

- Add, view, search, update, and delete saved accounts.
- Add a cryptographically secure password generator.
- Add automated tests for incorrect passwords and modified vault data.
- Improve error handling and file protection.

## Responsible Use

Use this project for educational purposes and protect all stored credentials.