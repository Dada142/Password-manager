import os
import time
import hashlib
import json
from cryptography.fernet import Fernet
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_FOLDER = "passwords"  # Folder to watch
KEY_FILE = "secret.key"
HASHES_FILE = "file_hashes.json"  # File to store file hashes

# Step 1: Load or create encryption key
def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

# Step 2: Encrypt file
def encrypt_file(file_path, key):
    if file_path.endswith(".enc"):
        return  # Already encrypted
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted = Fernet(key).encrypt(data)
        with open(file_path + ".enc", "wb") as f:
            f.write(encrypted)
        os.remove(file_path)
        print(f"🔐 Encrypted: {file_path}")
        update_file_hashes(file_path)  # Update hash after encryption
    except Exception as e:
        print(f"❌ Failed to encrypt {file_path}: {e}")

# Step 3: Generate file hash (SHA256)
def generate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"❌ Error generating hash for {file_path}: {e}")
        return None

# Step 4: Check for file tampering
def check_for_tampering():
    try:
        if os.path.exists(HASHES_FILE):
            with open(HASHES_FILE, "r") as f:
                stored_hashes = json.load(f)
            for file, stored_hash in stored_hashes.items():
                current_hash = generate_file_hash(file)
                if current_hash != stored_hash:
                    print(f"⚠️ File tampered: {file}")
                else:
                    print(f"✔️ File intact: {file}")
    except Exception as e:
        print(f"❌ Error checking for tampering: {e}")

# Step 5: Update file hashes after encryption
def update_file_hashes(file_path):
    stored_hashes = {}
    if os.path.exists(HASHES_FILE):
        with open(HASHES_FILE, "r") as f:
            stored_hashes = json.load(f)

    file_hash = generate_file_hash(file_path)
    if file_hash:
        stored_hashes[file_path] = file_hash
        with open(HASHES_FILE, "w") as f:
            json.dump(stored_hashes, f, indent=4)

# Step 6: Folder watcher class
class EncryptHandler(FileSystemEventHandler):
    def __init__(self, key):
        self.key = key

    def on_created(self, event):
        if not event.is_directory:
            time.sleep(0.5)  # Give the file time to finish writing
            encrypt_file(event.src_path, self.key)

# Step 7: Start watching
def start_bot():
    os.makedirs(WATCH_FOLDER, exist_ok=True)
    key = load_or_create_key()
    handler = EncryptHandler(key)
    observer = Observer()
    observer.schedule(handler, WATCH_FOLDER, recursive=False)
    observer.start()
    print(f"🔍 Watching folder: {WATCH_FOLDER}")
    
    # Periodically check for tampered files
    try:
        while True:
            time.sleep(10)  # Check every 10 seconds
            check_for_tampering()
    except KeyboardInterrupt:
        observer.stop()
        print("🛑 Bot stopped.")
    observer.join()

if __name__ == "__main__":
    start_bot()
