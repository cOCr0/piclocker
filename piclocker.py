#!/usr/bin/env python3
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import getpass

BLOCK_SIZE = 16  # AES block size


# ----- Helper functions -----
def pad(data):
    """Pad data to multiple of BLOCK_SIZE"""
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length


def unpad(data):
    """Remove padding"""
    return data[:-data[-1]]


def get_key(password):
    """Derive 32-byte AES key from password"""
    return SHA256.new(password.encode()).digest()


def encrypt_file(file_path, key):
    """Encrypt the file"""
    if not os.path.isfile(file_path):
        print("File not found!")
        return

    with open(file_path, "rb") as f:
        data = f.read()

    data = pad(data)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(data)

    encrypted_file = os.path.splitext(file_path)[0] + "_encrypted.png"
    with open(encrypted_file, "wb") as f:
        f.write(iv + ciphertext)

    print(f"\nEncryption complete! Saved as: {encrypted_file}")


def decrypt_file(file_path, key):
    """Decrypt the file"""
    if not os.path.isfile(file_path):
        print("File not found!")
        return

    with open(file_path, "rb") as f:
        raw = f.read()

    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext))
    except ValueError:
        print("Wrong key or corrupted file!")
        return

    decrypted_file = os.path.splitext(file_path)[0].replace("_encrypted", "") + "_decrypted.png"
    with open(decrypted_file, "wb") as f:
        f.write(plaintext)

    print(f"\nDecryption complete! Saved as: {decrypted_file}")


# ----- Main program -----
def main():
    # Banner
    print("""
  PIC LOCKER
""")
    print("Welcome to Image Locker - simple tool to encrypt and decrypt images\n")

    # User input
    choice = input("Enter 'e' for encryption, 'd' for decryption: ").lower()
    file_path = input("Enter image path: ").strip()
    password = getpass.getpass("Enter encryption key: ").strip()
    key = get_key(password)

    # Run
    if choice == "e":
        encrypt_file(file_path, key)
    elif choice == "d":
        decrypt_file(file_path, key)
    else:
        print("Invalid option!")


if __name__ == "__main__":
    main()
