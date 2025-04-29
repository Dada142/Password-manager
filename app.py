import getpass
import os
import json
import hashlib
import shutil
import random
import string
from datetime import datetime
import sys
from cryptography.fernet import Fernet
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess
import threading



common_passwords = [
    "123456", "123456789", "qwerty", "password", "1234567", "12345678", "12345", "iloveyou",
    "111111", "123123", "abc123", "qwerty123", "1q2w3e", "admin", "qwertyuiop", "654321", 
    "555555", "lovely", "7777777", "welcome", "888888", "princess", "dragon", "password1", 
    "123qwe", "666666", "1qaz2wsx", "sunshine", "ashley", "bailey", "qazwsx", "monkey", 
    "football", "charlie", "donald", "letmein", "696969", "shadow", "master", "michael", 
    "superman", "hello", "whatever", "1234", "pokemon", "batman", "trustno1", "jordan", 
    "hunter", "harley", "buster", "soccer", "killer", "ginger", "george", "joshua", "pepper", 
    "daniel", "access", "passw0rd", "starwars", "maggie", "qwerty1", "cheese", "asdfgh", 
    "matthew", "jennifer", "pepper", "jessica", "zxcvbnm", "tigger", "computer", "michelle", 
    "thomas", "internet", "hannah", "andrew", "security", "123321", "fuckyou", "buster", 
    "abcd1234", "ashley", "nicole", "babygirl", "monica", "qwert", "thunder", "taylor", 
    "purple", "michael1", "aaaaaa", "jordan23", "robert", "soccer1", "hockey", "chocolate", 
    "pussy", "silver", "cookie", "batman1", "maverick", "cowboy"
]



notes_folder = "notes"
Key_path = "secret.key"
watch_folder_path = "watched_folder"
password_folder_path = "passwords"
os.makedirs(watch_folder_path, exist_ok=True)
class InactivityTimer:
    def __init__(self, timeout, callback):
        self.timeout = timeout
        self.callback = callback
        self.timer = None
        self.lock = threading.Lock()

    def reset(self):
        with self.lock:
            if self.timer:
                self.timer.cancel()
            self.timer = threading.Timer(self.timeout, self.callback)
            self.timer.daemon = True
            self.timer.start()

    def stop(self):
        with self.lock:
            if self.timer:
                self.timer.cancel()
                self.timer = None

def timeout_action():
    print("\n🔐 Welcome to Secure Vault 🔐")
    print("Protect your notes, passwords, and files!")
    print("====================================\n")
    master_key = getpass.getpass("Master key: ")



inactivity_timer = InactivityTimer(60, timeout_action)

class Notes:
    def notes_management(self):
        while True:
            choice = input("\n1. Write notes\n2. View all notes\n3. Exit\nChoose an option: ")
            if choice == "1":
                self.save_notes()
            elif choice == "2":
                self.view_notes()
            elif choice == "3":
                break
            else:
                print("Invalid choice.")

    def save_notes(self):
        os.makedirs(notes_folder, exist_ok=True)
        notes_name = input("Notes name: ")
        print("Enter your note. Press Enter on an empty line to finish:")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        note = "\n".join(lines)
        file_path = os.path.join(notes_folder, f"{notes_name}.txt")
        with open(file_path, "w") as file:
            file.write(note)
        print("Note saved!")

    def view_notes(self):
        try:
            files = os.listdir(notes_folder)
            if not files:
                print("No notes saved.")
            else:
                print("Saved Notes:")
                for filename in files:
                    print(f"- {filename}")
        except FileNotFoundError:
            print("No notes folder found.")

def fake_password_op(password):
    while True:
        fake_password = input("Killswitch password: ")
        fake_password_length = len(fake_password)
        if fake_password_length >= 6:
            if fake_password == password:
                print("Password and killswitch password cannot be the same.")
            else:
                salt, hashed = fake_password_hashkey(fake_password)
                fpasswords = {
                    "salt": salt,
                    "password": hashed
                }
                with open("fake_password.json", 'w') as file:
                    json.dump(fpasswords, file, indent=1)
                break  # Exit the loop after successful creation
        else:
            print("Password length is too small. Must be at least 6 characters.")


def fake_password_hashkey(fake_password, Salt=16):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', fake_password.encode(), salt, 100000)
    return salt.hex(), hashed.hex()

def load_or_create_key():
    if not os.path.exists(Key_path):
        key = Fernet.generate_key()
        with open(Key_path, "wb") as file:
            file.write(key)
    else:
        with open(Key_path, "rb") as key_file:
            key = key_file.read()
    return key

def encrypt_file(file_path, key):
    if file_path.endswith(".enc"):
        return
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        fernet_obj = Fernet(key)
        encrypted = fernet_obj.encrypt(data)
        encrypted_path = file_path + ".enc"
        with open(encrypted_path, "wb") as f:
            f.write(encrypted)
        os.remove(file_path)
        print(f"Encrypted: {file_path}")
    except Exception as e:
        print(f"Encryption failed for {file_path}: {e}")

def hashkey(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex(), hashed.hex()

def verify_password(stored_salt, stored_hash, password_attempt):
    salt_bytes = bytes.fromhex(stored_salt)
    _, attempt_hash = hashkey(password_attempt, salt_bytes)
    return attempt_hash == stored_hash

def kill_switch():
    try:
        if os.path.exists(password_folder_path):
            shutil.rmtree(password_folder_path)
            print("💣 passwords folder deleted")
        if os.path.exists("user_info.json"):
            os.remove("user_info.json")
            print("💣 user_info.json deleted")
    except Exception as e:
        print(f"⚠️ Kill switch failed: {e}")

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for _ in range(length))

class EncryptHandler(FileSystemEventHandler):
    def __init__(self, key):
        self.key = key

    def on_created(self, event):
        if not event.is_directory:
            time.sleep(0.5)
            encrypt_file(event.src_path, self.key)

def start_folder_watch(folder_path, key):
    if not os.path.exists(folder_path):
        return
    event_handler = EncryptHandler(key)
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=False)
    observer.start()
    print(f"🔐 Watching folder: {folder_path}")
    return observer

def start_all_watches(key):
    observers = []
    folders = [watch_folder_path]
    if os.path.exists(password_folder_path):
        folders.append(password_folder_path)
    for folder in folders:
        observer = start_folder_watch(folder, key)
        if observer:
            observers.append(observer)
    return observers

def verify_fake_password(entered_password):
    with open("fake_password.json", "r") as file:
        fake_data = json.load(file)
    salt = bytes.fromhex(fake_data["salt"])
    hashed_attempt = hashlib.pbkdf2_hmac("sha256", entered_password.encode(), salt, 100000).hex()
    return hashed_attempt == fake_data["password"]

def startup_screen():
    print("""
====================================
🔐 Welcome to Secure Vault 🔐
Protect your notes, passwords, and files!
====================================
    """)
class App:
    def __init__(self):
        self.retries = 5
        self.observers = []

    def run(self):
        startup_screen()

        while True:
            inactivity_timer.reset()
            if self.retries == 0:
                kill_switch()
                print("Locked 🔒.")
                break

            if os.path.exists("user_info.json"):
                with open("user_info.json", "r") as file:
                    user_info = json.load(file)
                print("\nPlease enter your Master key.")
                entered_password = input("Master key: ")

                if verify_password(user_info['salt'], user_info['password'], entered_password):
                    print(f"Welcome {user_info['username']}!")
                    key = load_or_create_key()
                    self.observers = start_all_watches(key)
                    self.main_menu()
                elif verify_fake_password(entered_password):
                    kill_switch()
                    print("Locked 🔒.")
                    break
                else:
                    self.retries -= 1
                    print("Incorrect Master key.")
                    print(f"\nYou have {self.retries} retries left.")
            else:
                self.create_new_user()

    def main_menu(self):
        while True:
            inactivity_timer.reset()
            choice = input("\n1. Change folder name\n2. Create folder\n3. Delete folder/file\n4. Exit\n5. Management\n6. Notes\nChoose an option: ")
            
            if choice == '1':
                folder_name = input("Enter the current folder name: ")
                if os.path.exists(folder_name):
                    new_folder_name = input("Enter the new folder name: ")
                    try:
                        os.rename(folder_name, new_folder_name)
                        print("Folder renamed successfully!")
                    except Exception as e:
                        print(f"Error: {e}")
                else:
                    print("Folder does not exist.")

            elif choice == '2':
                new_folder_name = input("Enter the name for the new folder: ")
                try:
                    os.makedirs(new_folder_name, exist_ok=True)
                    print(f"Folder '{new_folder_name}' created successfully!")
                    choice_new_file = input("Would you like to create a file in this folder? (y/n): ").lower()
                    if choice_new_file == "y":
                        choose_file_name = input("Please enter the file name (with extension): ")
                        file_path = os.path.join(new_folder_name, choose_file_name)
                        with open(file_path, "w") as file:
                            file.write("This is a new file created inside the folder.")
                        print(f"File '{choose_file_name}' created successfully inside '{new_folder_name}'!")
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == '3':
                delete_choice = input("Delete a file or a folder? (f for file, d for folder): ").lower()
                if delete_choice == 'f':
                    file_name = input("File name (with extension): ")
                    if os.path.exists(file_name):
                        try:
                            os.remove(file_name)
                            print(f"File '{file_name}' deleted successfully!")
                        except Exception as e:
                            print(f"Error: {e}")
                elif delete_choice == 'd':
                    folder_name = input("Folder name: ")
                    if os.path.exists(folder_name):
                        try:
                            shutil.rmtree(folder_name)
                            print(f"Folder '{folder_name}' deleted successfully!")
                        except Exception as e:
                            print(f"Error: {e}")
                else:
                    print("Invalid choice.")

            elif choice == '4':
                for o in self.observers:
                    o.stop()
                for o in self.observers:
                    o.join()
                print("Goodbye!")
                quit()

            elif choice == '5':
                self.password_management()

            elif choice == '6':
                notes_app = Notes()
                notes_app.notes_management()

            else:
                print("Invalid choice.")

    def password_management(self):
        now = datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")

        while True:
            choice = input("\n1. Save passwords\n2. View passwords\n3. Generate a password\n4. Update passwords\n5. Back\nChoose an option: ")
            
            if choice == '1':
                name = input("Enter name: ")
                email = input("Enter email: ")
                password = input("Enter password: ")
                details = {
                    "Time edited": current_time,
                    "name": name,
                    "email": email,
                    "password": password
                }
                os.makedirs(password_folder_path, exist_ok=True)
                file_name = f"{name}.json"
                with open(file_name, "w") as file:
                    json.dump(details, file, indent=3)
                shutil.move(file_name, os.path.join(password_folder_path, file_name))
                print("Password file saved!")

            elif choice == '2':
                try:
                    files = os.listdir(password_folder_path)
                    if not files:
                        print("No passwords saved yet.")
                    else:
                        print("Password list:")
                        for file in files:
                            if file.endswith(".json"):
                                print(os.path.splitext(file)[0])
                        password_name = input("Enter password name (without .json): ")
                        with open(f"{password_folder_path}/{password_name}.json", 'r') as file:
                            data = json.load(file)
                        print(json.dumps(data, indent=3))
                except FileNotFoundError:
                    print("No passwords saved yet.")

            elif choice == '3':
                new_password = generate_password(16)
                print(f"\nYour new password is: {new_password}")

            elif choice == '4':
                files = os.listdir(password_folder_path)
                print("Password list:")
                for file in files:
                    if file.endswith(".json"):
                        print(os.path.splitext(file)[0])
                password_name = input("Enter password name: ")
                name = input("Name: ")
                email = input("Email: ")
                password = input("Password: ")
                updated = {
                    "Time edited": current_time,
                    "name": name,
                    "email": email,
                    "password": password
                }
                with open(f"{password_folder_path}/{password_name}.json", "w") as file:
                    json.dump(updated, file, indent=3)

            elif choice == '5':
                break

            else:
                print("Invalid choice.")

    def create_new_user(self):
        username = input("Username: ")
        password = input("Master key: ")

        if password in common_passwords:
            print("Weak password 🤦‍♀️.")

        if len(password) >= 6:
            fake_password_op(password)
            while True:
                confirm = input("Confirm Master key: ")
                if confirm == password:
                    salt, hashed = hashkey(password)
                    user_info = {
                        "username": username,
                        "salt": salt,
                        "password": hashed
                    }
                    with open("user_info.json", "w") as file:
                        json.dump(user_info, file, indent=2)
                    print("User created successfully!")
                    break
                else:
                    print("Passwords do not match.")
        else:
            print("Password length is too small.")


if __name__ == "__main__":
    app_instance = App()  # ✅ Define this first
    inactivity_timer = InactivityTimer(10, timeout_action)  # Then create timer
    app_instance.run()

