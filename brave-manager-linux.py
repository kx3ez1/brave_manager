#!/usr/bin/env python3

import os
import sys
sys.path.insert(0,os.path.expanduser("~/.local_packages"))
import argparse
import subprocess
import getpass
import shutil
import tarfile
import io
import signal
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Configuration ---
# Base directory for the profile manager
BASE_DIR = os.path.expanduser("~/.brave_manager")

# Directory to store encrypted profile files
PROFILES_DIR = os.path.join(BASE_DIR, "profiles")

# Directory for temporary, decrypted (active) profiles
TEMP_DIR = os.path.join(BASE_DIR, "tmp")
PROFILE_EXT = ".bprof"

# Command to launch Brave Browser. This may need to be adjusted for your OS.
# Linux: 'brave-browser'
# macOS: '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser'
# Windows: 'brave' (ensure it's in your PATH)
BRAVE_COMMAND = "brave-browser-nightly"

# --- Encryption/Decryption Functions (Provided) ---

def encrypt_with_password(password: str, data: bytes) -> bytes:
    """
    Encrypts data using a password. The password is required for both
    encryption and decryption.
    """
    password_bytes = password.encode('utf-8')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = kdf.derive(password_bytes)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + encrypted_data

def decrypt_with_password(password: str, combined_data: bytes) -> bytes or None:
    """
    Decrypts the combined data block using the password.
    """
    try:
        password_bytes = password.encode('utf-8')
        salt = combined_data[:16]
        nonce = combined_data[16:28]
        encrypted_data = combined_data[28:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(password_bytes)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        return decrypted_data
    except Exception:
        # Decryption will fail if the password is wrong or the data is corrupt
        return None

# --- Helper Functions ---

def archive_directory_to_bytes(dir_path: str) -> bytes:
    """Creates a gzipped tarball of a directory in memory and returns its bytes."""
    bytes_io = io.BytesIO()
    with tarfile.open(fileobj=bytes_io, mode='w:gz') as tar:
        tar.add(dir_path, arcname='.')
    return bytes_io.getvalue()

def extract_archive_from_bytes(archive_bytes: bytes, extract_path: str):
    """Extracts a gzipped tarball from bytes into a specified directory."""
    bytes_io = io.BytesIO(archive_bytes)
    with tarfile.open(fileobj=bytes_io, mode='r:gz') as tar:
        tar.extractall(path=extract_path)

def save_and_cleanup(profile_name: str, password: str):
    """
    Archives the active profile directory, encrypts it, saves it to permanent
    storage, and cleans up all temporary files.
    """
    active_profile_dir = os.path.join(TEMP_DIR, profile_name)
    encrypted_path = os.path.join(PROFILES_DIR, f"{profile_name}{PROFILE_EXT}")
    pid_file = os.path.join(TEMP_DIR, f"{profile_name}.pid")

    if not os.path.isdir(active_profile_dir):
        print(f"Error: Active profile directory for '{profile_name}' not found. Cannot save state.")
        return

    print(f"Securing and saving profile '{profile_name}'...")
    try:
        archive_bytes = archive_directory_to_bytes(active_profile_dir)
        encrypted_blob = encrypt_with_password(password, archive_bytes)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_blob)
        print("Profile saved successfully.")
    except Exception as e:
        print(f"FATAL: An error occurred while saving the profile: {e}")
        print(f"The temporary data has NOT been deleted to prevent data loss.")
        print(f"You can find it at: {active_profile_dir}")
        sys.exit(1)

    print("Cleaning up session...")
    shutil.rmtree(active_profile_dir)
    if os.path.exists(pid_file):
        os.remove(pid_file)
    print("Cleanup complete.")

def get_running_profiles() -> list:
    """Scans the temp directory and returns a list of active profile names."""
    running = []
    if not os.path.isdir(TEMP_DIR):
        return []
    for f in os.listdir(TEMP_DIR):
        if f.endswith(".pid"):
            profile_name = f.replace(".pid", "")
            # Also check if the corresponding data directory exists
            if os.path.isdir(os.path.join(TEMP_DIR, profile_name)):
                running.append(profile_name)
    return sorted(running)

# --- Core Command Functions ---

def launch_profile(profile_name: str):
    """Handles the creation or launching of a profile."""
    encrypted_path = os.path.join(PROFILES_DIR, f"{profile_name}{PROFILE_EXT}")
    active_profile_dir = os.path.join(TEMP_DIR, profile_name)
    pid_file = os.path.join(TEMP_DIR, f"{profile_name}.pid")
    password = "" # Define password in this scope

    # --- NEW: Interactive recovery for dirty state ---
    if os.path.exists(active_profile_dir) or os.path.exists(pid_file):
        print(f"Warning: Profile '{profile_name}' appears to be running or was not cleaned up properly.")
        print("This can happen if the browser crashed or was not closed correctly.")
        confirm = input("Would you like to attempt to recover and lock the session now? [y/N]: ")
        if confirm.lower() == 'y':
            print(f"Please enter the password for '{profile_name}' to secure its data.")
            password = getpass.getpass("Enter password: ")
            save_and_cleanup(profile_name, password)
            print(f"Profile '{profile_name}' has been successfully locked. Proceeding to launch...")
        else:
            print("Operation cancelled. Please manually clean up the following to proceed:")
            if os.path.isdir(active_profile_dir):
                print(f" - Directory: {active_profile_dir}")
            if os.path.exists(pid_file):
                print(f" - Lock file: {pid_file}")
            sys.exit(1)

    profile_exists = os.path.exists(encrypted_path)

    if profile_exists:
        print(f"Unlocking profile '{profile_name}'...")
        # Only ask for password if we don't already have it from the recovery step
        if not password:
            password = getpass.getpass("Enter password: ")

        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_archive = decrypt_with_password(password, encrypted_data)

        if decrypted_archive is None:
            print("Decryption failed. Incorrect password or corrupt profile.")
            sys.exit(1)

        os.makedirs(active_profile_dir)
        extract_archive_from_bytes(decrypted_archive, active_profile_dir)
        print("Profile unlocked successfully.")

    else:
        # --- New Profile ---
        print(f"Profile '{profile_name}' does not exist. Creating new one.")
        password = getpass.getpass("Enter a new password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Passwords do not match.")
            sys.exit(1)
        if not password:
            print("Error: Password cannot be empty.")
            sys.exit(1)
            
        os.makedirs(active_profile_dir)
        print(f"A new Brave window will open to initialize the profile.")
        print("Set up your profile as desired, then CLOSE THE BROWSER to save and encrypt it.")
        input("Press Enter to continue...")

    # --- Launch Brave ---
    print(f"Launching Brave with profile '{profile_name}'...")
    try:
        proc = subprocess.Popen([BRAVE_COMMAND, f"--user-data-dir={active_profile_dir}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(pid_file, 'w') as f:
            f.write(str(proc.pid))
    except FileNotFoundError:
        print(f"Error: Could not find Brave command '{BRAVE_COMMAND}'.")
        print("Please ensure Brave Browser is installed and the command is correct for your OS.")
        shutil.rmtree(active_profile_dir) # Clean up created temp dir
        sys.exit(1)

    print(f"Brave is running (PID: {proc.pid}). This terminal will now wait.")
    print("Close the Brave window to automatically save and encrypt your session.")

    proc.wait() # Block until the user closes Brave

    save_and_cleanup(profile_name, password)

def list_profiles():
    """Lists all available encrypted profiles."""
    print("Available Brave profiles:")
    try:
        profiles = [f.replace(PROFILE_EXT, '') for f in os.listdir(PROFILES_DIR) if f.endswith(PROFILE_EXT)]
        if not profiles:
            print("  (No profiles found)")
        else:
            for profile in sorted(profiles):
                print(f"  - {profile}")
    except FileNotFoundError:
        print("  (Profile directory does not exist. Create a profile to get started.)")

def lock_profile(profile_name: str, forceful: bool = False):
    """Terminates a running Brave instance for a profile and cleans up."""
    pid_file = os.path.join(TEMP_DIR, f"{profile_name}.pid")

    if not os.path.exists(pid_file):
        print(f"Profile '{profile_name}' is not running (no PID file found).")
        active_profile_dir = os.path.join(TEMP_DIR, profile_name)
        if os.path.isdir(active_profile_dir):
            print(f"Warning: A temporary directory exists at {active_profile_dir}, but no PID file.")
            print("This may indicate an improper shutdown. Manual cleanup may be required.")
        sys.exit(1)

    with open(pid_file, 'r') as f:
        pid = int(f.read())

    action_word = "Terminating" if forceful else "Closing"
    print(f"{action_word} process {pid} for profile '{profile_name}'...")
    try:
        os.kill(pid, signal.SIGTERM)
        print("Termination signal sent. Waiting a moment...")
        time.sleep(2)
    except ProcessLookupError:
        print(f"Process {pid} was not found. It may have already been closed.")
    except Exception as e:
        print(f"An error occurred while trying to kill the process: {e}")

    print("To save the session data, please enter the profile password.")
    password = getpass.getpass("Enter password: ")
    save_and_cleanup(profile_name, password)

def lock_profile_interactive():
    """Shows a menu of running profiles to lock."""
    running_profiles = get_running_profiles()
    if not running_profiles:
        print("No profiles are currently running.")
        return

    print("Select a running profile to lock:")
    for i, name in enumerate(running_profiles, 1):
        print(f"  {i}. {name}")
    print("  0. Cancel")

    while True:
        try:
            choice_str = input("Enter number: ")
            choice = int(choice_str)
            if 0 <= choice <= len(running_profiles):
                break
            else:
                print("Invalid number. Please try again.")
        except ValueError:
            print("Please enter a valid number.")

    if choice == 0:
        print("Operation cancelled.")
        return

    profile_to_lock = running_profiles[choice - 1]
    lock_profile(profile_to_lock)

def delete_profile(profile_name: str):
    """Permanently deletes an encrypted profile."""
    encrypted_path = os.path.join(PROFILES_DIR, f"{profile_name}{PROFILE_EXT}")
    
    if profile_name in get_running_profiles():
        print(f"Error: Profile '{profile_name}' appears to be active.")
        print("Please lock or kill the session before deleting it.")
        sys.exit(1)

    if not os.path.exists(encrypted_path):
        print(f"Error: Profile '{profile_name}' not found.")
        sys.exit(1)

    confirm = input(f"Are you sure you want to permanently delete the profile '{profile_name}'? [y/N]: ")
    if confirm.lower() != 'y':
        print("Deletion cancelled.")
        return

    try:
        os.remove(encrypted_path)
        print(f"Profile '{profile_name}' has been deleted successfully.")
    except Exception as e:
        print(f"An error occurred while trying to delete the profile: {e}")
        sys.exit(1)

def update_password(profile_name: str):
    """Changes the password for an existing profile."""
    encrypted_path = os.path.join(PROFILES_DIR, f"{profile_name}{PROFILE_EXT}")
    
    if profile_name in get_running_profiles():
        print(f"Error: Profile '{profile_name}' appears to be active.")
        print("Please lock or kill the session before changing its password.")
        sys.exit(1)
        
    if not os.path.exists(encrypted_path):
        print(f"Error: Profile '{profile_name}' not found.")
        sys.exit(1)

    print(f"Updating password for profile '{profile_name}'.")
    current_password = getpass.getpass("Enter current password: ")

    try:
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
    except Exception as e:
        print(f"Error reading profile file: {e}")
        sys.exit(1)
    
    decrypted_archive = decrypt_with_password(current_password, encrypted_data)
    
    if decrypted_archive is None:
        print("Decryption failed. Incorrect password.")
        sys.exit(1)

    print("Password accepted.")
    new_password = getpass.getpass("Enter new password: ")
    new_password_confirm = getpass.getpass("Confirm new password: ")
    
    if new_password != new_password_confirm:
        print("New passwords do not match.")
        sys.exit(1)
        
    if not new_password:
        print("Error: New password cannot be empty.")
        sys.exit(1)

    print("Re-encrypting profile with new password...")
    try:
        new_encrypted_blob = encrypt_with_password(new_password, decrypted_archive)
        with open(encrypted_path, 'wb') as f:
            f.write(new_encrypted_blob)
        print("Password updated successfully.")
    except Exception as e:
        print(f"FATAL: An error occurred while re-encrypting and saving the profile: {e}")
        sys.exit(1)

def rename_profile(old_name: str, new_name: str):
    """Renames a profile. If running, it will prompt to lock it first."""
    old_encrypted_path = os.path.join(PROFILES_DIR, f"{old_name}{PROFILE_EXT}")
    new_encrypted_path = os.path.join(PROFILES_DIR, f"{new_name}{PROFILE_EXT}")

    # --- Validation ---
    if not os.path.exists(old_encrypted_path):
        print(f"Error: Profile '{old_name}' not found.")
        sys.exit(1)
    
    if os.path.exists(new_encrypted_path):
        print(f"Error: A profile named '{new_name}' already exists. Cannot rename.")
        sys.exit(1)

    if not new_name.strip() or '/' in new_name or '\\' in new_name:
        print(f"Error: Invalid new profile name '{new_name}'.")
        sys.exit(1)

    # --- Handle running profile ---
    if old_name in get_running_profiles():
        print(f"Warning: Profile '{old_name}' is currently running.")
        confirm = input("To rename it, the session must be closed and saved first. Continue? [y/N]: ")
        if confirm.lower() != 'y':
            print("Rename operation cancelled.")
            return
        lock_profile(old_name)

    # --- Perform rename ---
    print(f"Renaming profile '{old_name}' to '{new_name}'...")
    try:
        os.rename(old_encrypted_path, new_encrypted_path)
        print("Profile renamed successfully.")
    except Exception as e:
        print(f"An error occurred during rename: {e}")
        sys.exit(1)

def delete_all_profiles():
    """Permanently deletes ALL encrypted profiles."""
    if get_running_profiles():
        print("Error: One or more profiles appear to be active.")
        print("Please lock all active sessions before deleting all profiles.")
        sys.exit(1)
    
    try:
        profile_files = [f for f in os.listdir(PROFILES_DIR) if f.endswith(PROFILE_EXT)]
    except FileNotFoundError:
        print("Profile directory not found. Nothing to delete.")
        return

    if not profile_files:
        print("No profiles found to delete.")
        return

    print("The following profiles will be PERMANENTLY DELETED:")
    for profile_file in sorted(profile_files):
        print(f"  - {profile_file.replace(PROFILE_EXT, '')}")
    
    print("\nTHIS ACTION CANNOT BE UNDONE.")
    confirm = input("To confirm, please type 'yes': ")

    if confirm.lower() != 'yes':
        print("Deletion cancelled.")
        return

    print("Deleting all profiles...")
    deleted_count = 0
    for profile_file in profile_files:
        try:
            os.remove(os.path.join(PROFILES_DIR, profile_file))
            deleted_count += 1
        except Exception as e:
            print(f"Could not delete {profile_file}: {e}")
    
    print(f"{deleted_count} profile(s) deleted successfully.")

def main():
    """Main function to parse arguments and execute commands."""
    os.makedirs(PROFILES_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    parser = argparse.ArgumentParser(
        description="A command-line tool to manage encrypted Brave browser profiles.",
        epilog=(
            "Examples:\n"
            "  brave_manager.py -P work                     (Launch or create profile 'work')\n"
            "  brave_manager.py -k                          (Show interactive list of running profiles to lock)\n"
            "  brave_manager.py -k work                     (Lock the running 'work' profile)\n"
            "  brave_manager.py --rename work personal      (Rename profile 'work' to 'personal')"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-P", "--profile", metavar="<name>", help="Launch or create a profile.")
    group.add_argument("-L", "--list", action="store_true", help="List all available profiles.")
    group.add_argument("-k", "--lock", nargs='?', const='_interactive_', default=None, metavar="<name>", help="Manually lock a running profile.\nIf no name is given, shows an interactive list.")
    group.add_argument("-K", "--kill", metavar="<name>", help="Forcefully terminate a running profile and save its data.")
    group.add_argument("-D", "--delete", metavar="<name>", help="Delete an existing profile.")
    group.add_argument("-U", "--update-password", metavar="<name>", help="Change the password for an existing profile.")
    group.add_argument("-R", "--rename", nargs=2, metavar=("<old_name>", "<new_name>"), help="Rename a profile.")
    group.add_argument("--delete-all", action="store_true", help="Permanently delete ALL existing profiles.")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.profile:
        launch_profile(args.profile)
    elif args.list:
        list_profiles()
    elif args.lock is not None:
        if args.lock == '_interactive_':
            lock_profile_interactive()
        else:
            lock_profile(args.lock)
    elif args.kill:
        lock_profile(args.kill, forceful=True)
    elif args.delete:
        delete_profile(args.delete)
    elif args.update_password:
        update_password(args.update_password)
    elif args.rename:
        old, new = args.rename
        rename_profile(old, new)
    elif args.delete_all:
        delete_all_profiles()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
