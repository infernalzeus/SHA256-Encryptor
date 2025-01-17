import csv
import hashlib
import os
from cryptography.fernet import Fernet
from getpass import getpass


# Configuration Constants
STATIC_PASSWORD = "infohygiene7"  # Change this to your password
KEY_FILE = 'encryption_key.key'


# File Operations
def load_csv(filename: str) -> list:
    """Load data from a CSV file."""
    try:
        with open(filename, 'r', newline='', encoding='utf-8') as file:
            return list(csv.DictReader(file))
    except FileNotFoundError:
        return []


def save_csv(filename: str, data: list, fieldnames: list):
    """Save data to a CSV file."""
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


# Encryption Utilities
def load_or_generate_key() -> bytes:
    """Load the encryption key from file or generate a new one."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as file:
            file.write(key)
        return key


def encrypt(value: str, key: bytes) -> str:
    """Encrypt a string using the provided encryption key."""
    return Fernet(key).encrypt(value.encode()).decode()


def decrypt(value: str, key: bytes) -> str:
    """Decrypt a string using the provided encryption key."""
    try:
        return Fernet(key).decrypt(value.encode()).decode()
    except Exception as e:
        print(f"Error decrypting value: {e}")
        return None


def generate_sha256_key(user: str, acc: str, info: str) -> str:
    """Generate a SHA-256 hash based on user, account, and info."""
    return hashlib.sha256(f"{user}{acc}{info}".encode()).hexdigest()


# User Authentication
def verify_password() -> bool:
    """Prompt user to verify the password."""
    entered_password = getpass("Enter the password: ")
    return entered_password == STATIC_PASSWORD


# Data Management
def display_data(data: list, encryption_key: bytes, search_info: str = ''):
    """Display decrypted data, including password only if search info is provided and matches."""
    entries_found = False  # Flag to track if any matching entries are found
    
    for entry in data:
        decrypted_info = decrypt(entry['info'], encryption_key)

        # Skip entry if decryption fails or if 'info' doesn't match search criteria
        if not decrypted_info:
            continue
        
        # Exact match search (case-insensitive), for 'info' field
        if search_info and search_info.strip().lower() != decrypted_info.strip().lower():
            continue
        
        decrypted_user = decrypt(entry['user'], encryption_key)
        decrypted_acc = decrypt(entry['acc#'], encryption_key)
        print(f"\nUser: {decrypted_user} | Acc#: {decrypted_acc} | Info: {decrypted_info}")
        
        # Display password if search_info is provided
        if search_info:
            display_password(decrypted_user, decrypted_acc, decrypted_info, encryption_key)

        entries_found = True  # Mark that at least one entry has been found

    # If no entries matched the search, print a message indicating no match
    if not entries_found:
        print("\nNo entries found matching the given info.")



def display_password(user: str, acc: str, info: str, encryption_key: bytes):
    """Fetch and display the password from the passbook."""
    sha256_key = generate_sha256_key(user, acc, info)
    password = get_password_from_passbook(sha256_key, encryption_key)
    if password:
        print(f"Password: {password}")
    else:
        print("Password not found in passbook.")


def get_password_from_passbook(sha256_key: str, encryption_key: bytes) -> str:
    """Retrieve the decrypted password from the passbook CSV."""
    passbook_data = load_csv('./passbook.csv')
    for entry in passbook_data:
        if entry['key'] == sha256_key:
            return decrypt(entry['pass'], encryption_key)
    return None


def write_data(data: list, encryption_key: bytes):
    """Prompt user to write new data and save it."""
    user = input("Enter user: ").strip()
    acc = input("Enter account number: ").strip()
    info = input("Enter info: ").strip()

    # Prevent saving entries with blank values
    if not all([user, acc, info]):
        print("User, account number, and info cannot be blank.")
        return

    # Prompt for the password once
    password = getpass("Enter password for this account: ").strip()

    # Prevent empty passwords
    if not password:
        print("Password cannot be empty.")
        return

    # Encrypt the data
    encrypted_user = encrypt(user, encryption_key)
    encrypted_acc = encrypt(acc, encryption_key)
    encrypted_info = encrypt(info, encryption_key)

    # Append the entry to the data
    data.append({'user': encrypted_user, 'acc#': encrypted_acc, 'info': encrypted_info})
    save_csv('./data.csv', data, ['user', 'acc#', 'info'])

    # Save the password to the passbook
    save_password_to_passbook(user, acc, info, password, encryption_key)

    print("\nData and password saved successfully.")


def save_password_to_passbook(user: str, acc: str, info: str, password: str, encryption_key: bytes):
    """Save the password to the passbook."""
    sha256_key = generate_sha256_key(user, acc, info)

    # Encrypt the password and store it in the passbook
    encrypted_password = encrypt(password, encryption_key)

    # Load existing passbook data
    passbook_data = load_csv('./passbook.csv')
    passbook_data.append({'key': sha256_key, 'pass': encrypted_password})

    # Save the passbook data
    save_csv('./passbook.csv', passbook_data, ['key', 'pass'])


def edit_data(data: list, encryption_key: bytes):
    """Allow the user to edit existing data or delete an entry."""
    search_info = input("Enter 'info' of the entry you want to edit: ").strip()
    found_entries = [entry for entry in data if search_info.strip().lower() == decrypt(entry['info'], encryption_key).strip().lower()]

    if not found_entries:
        print("\nNo entries found.")
        return

    print("\nFound entries:")
    for idx, entry in enumerate(found_entries, 1):
        print(f"{idx}. User: {decrypt(entry['user'], encryption_key)} | "
              f"Acc#: {decrypt(entry['acc#'], encryption_key)} | "
              f"Info: {decrypt(entry['info'], encryption_key)}")

    try:
        entry_idx = int(input("\nSelect entry to edit (enter number) or 0 to delete: ")) - 1
        if entry_idx == -1:
            delete_entry(found_entries, data, encryption_key)
        elif 0 <= entry_idx < len(found_entries):
            edit_entry(found_entries[entry_idx], data, encryption_key)
        else:
            print("\nInvalid entry number.")
    except ValueError:
        print("\nInvalid input. Please enter a valid number.")


def delete_entry(found_entries: list, data: list, encryption_key: bytes):
    """Delete an entry from data and passbook."""
    entry_to_delete = found_entries[int(input("\nEnter the number of the entry to delete: ")) - 1]
    data.remove(entry_to_delete)
    save_csv('./data.csv', data, ['user', 'acc#', 'info'])

    sha256_key = generate_sha256_key(decrypt(entry_to_delete['user'], encryption_key),
                                      decrypt(entry_to_delete['acc#'], encryption_key),
                                      decrypt(entry_to_delete['info'], encryption_key))
    passbook_data = load_csv('./passbook.csv')
    passbook_data = [entry for entry in passbook_data if entry['key'] != sha256_key]
    save_csv('./passbook.csv', passbook_data, ['key', 'pass'])

    print("\nEntry deleted successfully from both data and passbook.")

def edit_entry(entry: dict, data: list, encryption_key: bytes):
    """Edit a specific entry in the data."""
    print("\nWhich field would you like to edit?")
    print("1. User")
    print("2. Account Number")
    print("3. Info")
    print("4. Password")
    field_choice = input("Enter choice (1-4): ").strip()

    # Decrypt original entry values and get original SHA256 key
    original_user = decrypt(entry['user'], encryption_key)
    original_acc = decrypt(entry['acc#'], encryption_key)
    original_info = decrypt(entry['info'], encryption_key)
    sha256_key = generate_sha256_key(original_user, original_acc, original_info)

    if field_choice == '1':
        new_value = input(f"New user (current: {original_user}): ").strip()
        if new_value:
            entry['user'] = encrypt(new_value, encryption_key)
        else:
            print("User cannot be blank.")
            return
    elif field_choice == '2':
        new_value = input(f"New account (current: {original_acc}): ").strip()
        if new_value:
            entry['acc#'] = encrypt(new_value, encryption_key)
        else:
            print("Account number cannot be blank.")
            return
    elif field_choice == '3':
        new_value = input(f"New info (current: {original_info}): ").strip()
        if new_value:
            entry['info'] = encrypt(new_value, encryption_key)
        else:
            print("Info cannot be blank.")
            return
    elif field_choice == '4':
        # Handle password update
        update_status = update_password_in_passbook(entry, encryption_key)
        if not update_status:  # If password update was cancelled
            print("\nPassword update cancelled. No changes made.")
            return
    else:
        print("\nInvalid choice. Please select a valid field (1-4).")
        return

    # After editing, re-calculate SHA256 and update passbook if necessary
    new_user = decrypt(entry['user'], encryption_key)
    new_acc = decrypt(entry['acc#'], encryption_key)
    new_info = decrypt(entry['info'], encryption_key)
    new_sha256_key = generate_sha256_key(new_user, new_acc, new_info)

    if sha256_key != new_sha256_key:
        # Update the SHA256 key in passbook
        update_sha256_key_in_passbook(sha256_key, new_sha256_key)

    save_csv('./data.csv', data, ['user', 'acc#', 'info'])
    print("\nEntry updated successfully.")  # Only show this if a valid update was made.

def update_password_in_passbook(entry: dict, encryption_key: bytes):
    """Update the password for the selected entry."""
    sha256_key = generate_sha256_key(decrypt(entry['user'], encryption_key),
                                      decrypt(entry['acc#'], encryption_key),
                                      decrypt(entry['info'], encryption_key))
    password = get_password_from_passbook(sha256_key, encryption_key)
    if not password:
        print("Password not found in passbook.")
        return None  # Return None if no password found

    new_password = getpass(f"New password (current: {password}): ").strip()
    if not new_password:
        print("Password cannot be empty. Update cancelled.")
        return None  # Return None to indicate the update was cancelled

    encrypted_password = encrypt(new_password, encryption_key)
    passbook_data = load_csv('./passbook.csv')
    for passbook_entry in passbook_data:
        if passbook_entry['key'] == sha256_key:
            passbook_entry['pass'] = encrypted_password
            break
    save_csv('./passbook.csv', passbook_data, ['key', 'pass'])
    print("Password updated successfully.")
    return True  # Return True to indicate successful update



def update_sha256_key_in_passbook(old_key: str, new_key: str):
    """Update the SHA256 key in the passbook."""
    passbook_data = load_csv('./passbook.csv')
    for entry in passbook_data:
        if entry['key'] == old_key:
            entry['key'] = new_key
            break
    save_csv('./passbook.csv', passbook_data, ['key', 'pass'])


# Main Interactive Function
def interact_with_csv():
    """Main interaction with user for managing CSV data."""
    if not verify_password():
        print("\nInvalid password. Exiting...\n")
        return

    encryption_key = load_or_generate_key()  # Load or generate the encryption key
    data = load_csv('./data.csv')

    while True:
        print("\n1. Read data")
        print("2. Write data")
        print("3. Edit data")
        print("4. Exit")

        choice = input("\nEnter choice: ").strip()

        if choice == '1':
            search_info = input("\nEnter 'info' to search (or leave blank to display all): ").strip()
            display_data(data, encryption_key, search_info)
        elif choice == '2':
            write_data(data, encryption_key)
        elif choice == '3':
            edit_data(data, encryption_key)
        elif choice == '4':
            print("\nExiting...\n")
            break
        else:
            print("\nInvalid choice. Try again.")


if __name__ == "__main__":
    interact_with_csv()
