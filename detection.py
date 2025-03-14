import os
import hashlib
import sys

evil_hashes = []
evil_hashes.append("ab01851fc8197d72bb290fd5d7422c88cee52f5e9b87a17f3d9cde5a6db547bb")
evil_hashes.append("6793ff619d42fdc38861fdfcc7ff0fc294cd05a8152d10f0a4835676f4f1b48c")
evil_hashes.append("39d9bcd2345e9c438a64334d576e6207dd22022013c54fd4de7b91bb8792d200")

def get_file_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            file_contents = f.read()
        return hashlib.sha256(file_contents).hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def insert_known_hashed():
    cur_dir = os.path.dirname(__file__)
    bad_path = os.path.join(cur_dir, "known_hashes")
    
    if not os.path.exists(bad_path):
        print(f"Warning: Directory '{bad_path}' does not exist.")
        return

    for dirpath, dirnames, filenames in os.walk(bad_path):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            file_hash = get_file_hash(file_path)
            if file_hash:
                evil_hashes.append(file_hash)
                print(f'File Hash: {file_hash}')

def detect_malware(scan_path):
    if not os.path.exists(scan_path):
        print(f"Error: Directory '{scan_path}' does not exist.")
        return

    print(f"Scanning {scan_path} for malware...")

    for dirpath, _, filenames in os.walk(scan_path, followlinks=False):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            file_hash = get_file_hash(file_path)
            if file_hash in evil_hashes:
                print(f"you have my malware >:) at {file_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory_to_scan>")
        sys.exit(1)

    scan_directory = sys.argv[1] 
    # insert_known_hashed() 
    detect_malware(scan_directory)