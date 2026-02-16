# piclocker
PicLocker is a simple terminal-based tool to encrypt and decrypt images using AES encryption. Encrypted images look like random noise when opened normally, providing a lightweight way to secure your images.
Features

Terminal-based interface with banner and welcome message

Encrypt images with a password

Decrypt images back to original

Encrypted images appear as grains/noise when opened

Works with any image file format

# Installation
Prerequisites

Python 3.x

pycryptodome library

# Steps

Clone the repository:

git clone https://github.com/yourusername/PicLocker.git
cd PicLocker


 Create a virtual environment (recommended):

python3 -m venv venv
source venv/bin/activate


Install required packages:

pip install pycryptodome

# Usage
Run the script:

python3 piclocker.py


You will see the PICLOCKER banner.

Enter e to encrypt or d to decrypt.

Provide the path to your image file.

Enter a password (hidden input).

# Security Notes

Uses AES-256 in CBC mode

Passwords are converted to keys via SHA-256

Encrypted images cannot be viewed without the correct password

Always remember your password; lost passwords cannot be recovered
