"""
Run once to generate your MASTER_PASSWORD_HASH and SECRET_KEY for .env
"""
import hashlib
import secrets
from getpass import getpass

password = getpass("Choose your master password: ")
confirm  = getpass("Confirm master password: ")

if password != confirm:
    print("Passwords do not match.")
    raise SystemExit(1)

pw_hash   = hashlib.sha256(password.encode()).hexdigest()
secret_key = secrets.token_hex(32)

print("\nAdd these to your .env file:\n")
print(f"MASTER_PASSWORD_HASH={pw_hash}")
print(f"SECRET_KEY={secret_key}")
