# USB Analyser
scanning and analysing contents of usb for if there are any irregularities 

Libraries to Install
To run the script, you'll need to install the following Python libraries and tools:

1)Install the required Python packages:

pip install pyclamd pytsk3

  
2)Ensure ClamAV is installed and running:

sudo apt update
sudo apt install clamav clamav-daemon
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon


3)Update the virus database:

sudo freshclam


4)pytsk3 requires the Sleuth Kit libraries:

sudo apt install sleuthkit


5)Ensure you're using Python 3.8 or higher.


6)Script Adjustments
In the script, ensure:

Replace /dev/sdb with your USB drive's device path in the python code. Use lsblk to find the path.

7)Connect a USB Drive:

Ensure it's properly mounted or detected (lsblk to check the device path).


8)Run the Script:

python usb_scan.py

If there are errors related to permissions, run the script as root:

sudo python usb_scan.py




## Features:
This project is a USB drive analysis tool that:
- Scans for hidden, corrupted, and infected files.
- Detects deleted files for potential recovery.
- Generates file hashes (SHA-256) for integrity verification.

## Requirements

- Python 3.8 or higher
- ClamAV
- Sleuth Kit

### Install Dependencies

pip install -r requirements.txt




