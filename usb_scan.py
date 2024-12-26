import os
import hashlib
import pyclamd
from datetime import datetime
import pytsk3  # Python wrapper for The Sleuth Kit

def list_files(directory):
    """
    Lists all files in the USB drive, including hidden files.
    """
    hidden_files = []
    print(f"\nScanning directory: {directory}")
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_info = os.stat(file_path)
            is_hidden = file.startswith('.')
            print(f"File: {file}")
            print(f" - Path: {file_path}")
            print(f" - Size: {file_info.st_size} bytes")
            print(f" - Last Modified: {datetime.fromtimestamp(file_info.st_mtime)}")
            print(f" - Hidden: {is_hidden}\n")
            if is_hidden:
                hidden_files.append(file_path)
    return hidden_files

def calculate_file_hash(file_path):
    """
    Calculates the hash (SHA-256) of a file for integrity checking.
    """
    try:
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(4096):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def scan_with_clamav(file_path):
    """
    Scans a file for malware using ClamAV.
    """
    try:
        cd = pyclamd.ClamdUnixSocket()  # Use local Unix socket (ClamAV daemon)
        if cd.ping():
            scan_result = cd.scan_file(file_path)
            if scan_result:
                return f"Infected: {scan_result}"
            else:
                return "Clean"
        else:
            return "ClamAV not responding"
    except Exception as e:
        print(f"Error scanning file with ClamAV: {e}")
        return "Error"

def detect_deleted_files(drive_path):
    """
    Detects and lists deleted files in the USB drive.
    """
    deleted_files = []
    print("\nDetecting deleted files for recovery...")

    try:
        img = pytsk3.Img_Info(drive_path)
        fs = pytsk3.FS_Info(img)
        for directory in fs.open_dir("/"):
            for entry in directory:
                if not hasattr(entry, "info") or not entry.info.meta:
                    continue
                if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                    file_name = entry.info.name.name.decode("utf-8")
                    deleted_files.append(file_name)
                    print(f" - Deleted File: {file_name}")
    except Exception as e:
        print(f"Error detecting deleted files: {e}")

    return deleted_files

def scan_usb(drive_path):
    """
    Main function to analyze a USB drive.
    """
    print(f"Analyzing USB drive at {drive_path}...\n")

    if not os.path.exists(drive_path):
        print(f"Error: Path {drive_path} does not exist.")
        return

    # Lists for summary
    hidden_files = list_files(drive_path)
    corrupted_files = []
    infected_files = []
    deleted_files = detect_deleted_files(drive_path)

    print("\nGenerating hashes and scanning files with ClamAV...")
    for root, _, files in os.walk(drive_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"\nFile: {file_path}")

            # Calculate file hash
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                print(f" - SHA-256 Hash: {file_hash}")
            else:
                print(f" - Corrupted: Unable to calculate hash")
                corrupted_files.append(file_path)
                continue

            # Scan with ClamAV
            scan_result = scan_with_clamav(file_path)
            print(f" - ClamAV Scan Result: {scan_result}")
            if "Infected" in scan_result:
                infected_files.append(file_path)

    # Summary Report
    print("\n--- Analysis Summary ---")
    print(f"Total Hidden Files: {len(hidden_files)}")
    for file in hidden_files:
        print(f" - {file}")

    print(f"\nTotal Corrupted Files: {len(corrupted_files)}")
    for file in corrupted_files:
        print(f" - {file}")

    print(f"\nTotal Infected Files: {len(infected_files)}")
    for file in infected_files:
        print(f" - {file}")

    print(f"\nTotal Deleted Files: {len(deleted_files)}")
    for file in deleted_files:
        print(f" - {file}")

# Replace '/dev/sdX' with the device path to your USB drive
usb_device_path = "/dev/sdb"  # Adjust this path based on your system
scan_usb(usb_device_path)
