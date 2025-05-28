import hashlib
import base64
import os
import getpass  # For securely getting passwords

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Hash import SHA256
except ImportError:
    print("Some required libraries are not installed.")
    print("Please install them using: pip install cryptography pycryptodomex")
    exit()

# --- Constants ---
AES_BLOCK_SIZE = 16
BLOWFISH_BLOCK_SIZE = 8
SALT_SIZE = 16
RSA_KEY_SIZE = 2048

# --- Helper Functions ---

def get_password(prompt="Enter password: "):
    """Gets a password securely from the user."""
    return getpass.getpass(prompt)

def derive_key(password, salt, key_length=32):
    """Derives a key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=480000,  # Recommended number of iterations
    )
    return kdf.derive(password.encode())

def save_to_file(filename, data):
    """Saves binary data to a file."""
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"Data saved to {filename}")
    except IOError as e:
        print(f"Error saving file: {e}")

def load_from_file(filename):
    """Loads binary data from a file."""
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None
    except IOError as e:
        print(f"Error loading file: {e}")
        return None

def get_mode():
    """Gets the mode (encrypt/decrypt) from the user."""
    while True:
        mode = input("Choose mode (encrypt/decrypt): ").lower().strip()
        if mode in ["encrypt", "decrypt"]:
            return mode
        else:
            print("Invalid mode. Please choose 'encrypt' or 'decrypt'.")

def get_text_or_file():
    """Asks user if they want to process text or a file."""
    while True:
        choice = input("Process text input or file? (text/file): ").lower().strip()
        if choice == "text":
            return input("Enter text: ").encode()
        elif choice == "file":
            filepath = input("Enter file path: ")
            data = load_from_file(filepath)
            return data
        else:
            print("Invalid choice. Please enter 'text' or 'file'.")

# --- 1. Caesar Cipher ---
def caesar_cipher(data, shift, mode):
    """Encrypts or decrypts data using Caesar Cipher."""
    result = bytearray()
    text = data.decode(errors='ignore') # Decode for processing, ignore errors for binary data
    for char in text:
        if 'a' <= char <= 'z':
            shift_amount = shift if mode == "encrypt" else -shift
            start = ord('a')
            result.append((ord(char) - start + shift_amount) % 26 + start)
        elif 'A' <= char <= 'Z':
            shift_amount = shift if mode == "encrypt" else -shift
            start = ord('A')
            result.append((ord(char) - start + shift_amount) % 26 + start)
        else:
            result.append(ord(char))
    return bytes(result)

# --- 2. Fernet (AES-128-CBC) ---
def fernet_generate_key():
    """Generates a Fernet key."""
    return Fernet.generate_key()

def fernet_encrypt(data, key):
    """Encrypts data using Fernet."""
    try:
        fernet = Fernet(key)
        return fernet.encrypt(data)
    except Exception as e:
        print(f"Fernet encryption error: {e}")
        return None

def fernet_decrypt(encrypted_data, key):
    """Decrypts data using Fernet."""
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)
    except InvalidToken:
        print("Fernet decryption error: Invalid key or corrupted data.")
        return None
    except Exception as e:
        print(f"Fernet decryption error: {e}")
        return None

# --- 3. Base64 Encoding ---
def base64_encode(data):
    """Encodes data using Base64."""
    return base64.b64encode(data)

def base64_decode(encoded_data):
    """Decodes data using Base64."""
    try:
        return base64.b64decode(encoded_data)
    except base64.binascii.Error as e:
        print(f"Base64 decoding error: {e}")
        return None

# --- 4. ROT13 Cipher ---
def rot13(data):
    """Applies ROT13 cipher to data."""
    text = data.decode(errors='ignore')
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    )).encode()

# --- 5. XOR Cipher ---
def xor_cipher(data, key):
    """Encrypts or decrypts data using XOR with a repeating key."""
    key_bytes = key.encode()
    key_len = len(key_bytes)
    return bytes(b ^ key_bytes[i % key_len] for i, b in enumerate(data))

# --- 6. Vigenère Cipher ---
def vigenere_cipher(data, key, mode):
    """Encrypts or decrypts data using Vigenère Cipher."""
    result = bytearray()
    key = key.lower()
    key_len = len(key)
    key_index = 0
    text = data.decode(errors='ignore')

    if not all(c.isalpha() for c in key):
        print("Error: Vigenere key must contain only alphabetic characters.")
        return None

    for char in text:
        if 'a' <= char <= 'z':
            shift = ord(key[key_index % key_len]) - ord('a')
            shift = shift if mode == "encrypt" else -shift
            start = ord('a')
            result.append((ord(char) - start + shift) % 26 + start)
            key_index += 1
        elif 'A' <= char <= 'Z':
            shift = ord(key[key_index % key_len]) - ord('a')
            shift = shift if mode == "encrypt" else -shift
            start = ord('A')
            result.append((ord(char) - start + shift) % 26 + start)
            key_index += 1
        else:
            result.append(ord(char))
    return bytes(result)

# --- 7. MD5 Hashing ---
def md5_hash(data):
    """Computes the MD5 hash of data."""
    return hashlib.md5(data).hexdigest()

# --- 8. SHA-256 Hashing ---
def sha256_hash(data):
    """Computes the SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()

# --- 9. Blowfish (CBC Mode) ---
def blowfish_encrypt(data, key):
    """Encrypts data using Blowfish (CBC mode) with PKCS7 padding."""
    iv = get_random_bytes(BLOWFISH_BLOCK_SIZE)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    padded_data = pad(data, BLOWFISH_BLOCK_SIZE)
    return iv + cipher.encrypt(padded_data)

def blowfish_decrypt(encrypted_data, key):
    """Decrypts data using Blowfish (CBC mode) with PKCS7 padding."""
    try:
        iv = encrypted_data[:BLOWFISH_BLOCK_SIZE]
        ct = encrypted_data[BLOWFISH_BLOCK_SIZE:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), BLOWFISH_BLOCK_SIZE)
        return pt
    except (ValueError, KeyError) as e:
        print(f"Blowfish decryption error: Incorrect key or corrupted data. ({e})")
        return None

# --- 10. RSA (OAEP Padding) ---
def generate_rsa_keys():
    """Generates an RSA key pair."""
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(data, public_key_data):
    """Encrypts data using RSA with OAEP padding."""
    try:
        key = RSA.import_key(public_key_data)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(data)
    except Exception as e:
        print(f"RSA encryption error: {e}")
        return None

def rsa_decrypt(encrypted_data, private_key_data):
    """Decrypts data using RSA with OAEP padding."""
    try:
        key = RSA.import_key(private_key_data)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(encrypted_data)
    except (ValueError, TypeError) as e:
        print(f"RSA decryption error: Incorrect key or corrupted data. ({e})")
        return None

# --- 11. Atbash Cipher ---
def atbash_cipher(data):
    """Applies Atbash cipher to data."""
    text = data.decode(errors='ignore')
    atbash_map = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
    )
    return text.translate(atbash_map).encode()

# --- 12. ChaCha20-Poly1305 (AEAD) ---
def chacha20_encrypt(data, key):
    """Encrypts data using ChaCha20-Poly1305."""
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12) # 96-bit nonce
    return nonce + aead.encrypt(nonce, data, None)

def chacha20_decrypt(encrypted_data, key):
    """Decrypts data using ChaCha20-Poly1305."""
    try:
        aead = ChaCha20Poly1305(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aead.decrypt(nonce, ciphertext, None)
    except InvalidToken:
         print("ChaCha20 decryption error: Invalid key, nonce or corrupted data (authentication failed).")
         return None
    except Exception as e:
        print(f"ChaCha20 decryption error: {e}")
        return None

# --- 13. SHA-512 Hashing ---
def sha512_hash(data):
    """Computes the SHA-512 hash of data."""
    return hashlib.sha512(data).hexdigest()

# --- 14. PBKDF2 Key Derivation ---
def pbkdf2_derive():
    """Derives a key from a password using PBKDF2."""
    password = get_password()
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    print(f"Derived Key (hex): {key.hex()}")
    print(f"Salt (hex): {salt.hex()}")
    print("Store both the key (or derive it again) and the salt securely.")

# --- Main Application ---

def display_menu():
    """Displays the main menu options."""
    print("\n--- Cryptography Toolkit ---")
    print("Choose an algorithm or action:")
    print(" 1. Caesar Cipher")
    print(" 2. Fernet (AES-128-CBC)")
    print(" 3. Base64")
    print(" 4. ROT13")
    print(" 5. XOR Cipher")
    print(" 6. Vigenère Cipher")
    print(" 7. Blowfish (CBC)")
    print(" 8. RSA (OAEP)")
    print(" 9. Atbash Cipher")
    print("10. ChaCha20-Poly1305")
    print("--- Hashing & KDF ---")
    print("11. MD5 Hash")
    print("12. SHA-256 Hash")
    print("13. SHA-512 Hash")
    print("14. PBKDF2 Key Derivation")
    print("--- Utilities ---")
    print("15. Generate RSA Keys & Save")
    print("16. Exit")
    print("----------------------------")

def main():
    """Main function to run the cryptography application."""
    print("Welcome to the Cryptography Toolkit! 🛠️")

    while True:
        display_menu()
        choice = input("Enter your choice (1-16): ")

        result = None
        output_is_text = True # By default, try to print as text

        try:
            if choice == "1": # Caesar
                data = get_text_or_file()
                if data:
                    shift = int(input("Enter shift (integer): "))
                    mode = get_mode()
                    result = caesar_cipher(data, shift, mode)

            elif choice == "2": # Fernet
                mode = get_mode()
                key_choice = input("Generate new key (g), use existing (e), or load from file (l)? ").lower()
                key = None
                if key_choice == 'g':
                    key = fernet_generate_key()
                    print(f"Generated Fernet Key (keep this safe!): {key.decode()}")
                    save_to_file("fernet.key", key)
                elif key_choice == 'e':
                    key = input("Enter Fernet key: ").encode()
                elif key_choice == 'l':
                    key = load_from_file(input("Enter key file path: "))
                else:
                    print("Invalid key choice.")

                if key:
                    data = get_text_or_file()
                    if data:
                        if mode == "encrypt":
                            result = fernet_encrypt(data, key)
                        else:
                            result = fernet_decrypt(data, key)
                        output_is_text = (mode == "decrypt") # Encrypted is bytes

            elif choice == "3": # Base64
                mode = input("Choose mode (encode/decode): ").lower()
                data = get_text_or_file()
                if data:
                    if mode == "encode":
                        result = base64_encode(data)
                    elif mode == "decode":
                         result = base64_decode(data)
                    else:
                        print("Invalid mode.")

            elif choice == "4": # ROT13
                data = get_text_or_file()
                if data:
                    result = rot13(data)

            elif choice == "5": # XOR
                data = get_text_or_file()
                if data:
                    key = input("Enter XOR key (can be multiple characters): ")
                    result = xor_cipher(data, key)
                    output_is_text = False # XOR often produces non-printable chars

            elif choice == "6": # Vigenere
                data = get_text_or_file()
                if data:
                    key = input("Enter Vigenère key (alphabetic characters only): ")
                    mode = get_mode()
                    result = vigenere_cipher(data, key, mode)

            elif choice == "7": # Blowfish
                mode = get_mode()
                password = get_password("Enter password for Blowfish key: ")
                salt = os.urandom(SALT_SIZE) # Generate new salt for encryption
                if mode == "decrypt":
                     salt_hex = input("Enter salt (hex) used during encryption: ")
                     try:
                         salt = bytes.fromhex(salt_hex)
                     except ValueError:
                         print("Invalid salt format.")
                         continue
                else:
                    print(f"Generated Salt (hex - SAVE THIS for decryption!): {salt.hex()}")

                key = derive_key(password, salt, 8) # Blowfish key (up to 56 bytes, 8 used here)

                data = get_text_or_file()
                if data:
                    if mode == "encrypt":
                        result = blowfish_encrypt(data, key)
                    else:
                        result = blowfish_decrypt(data, key)
                    output_is_text = (mode == "decrypt")

            elif choice == "8": # RSA
                mode = get_mode()
                if mode == "encrypt":
                    key_data = load_from_file(input("Enter public key file path: "))
                    if key_data:
                        data = get_text_or_file()
                        if data:
                            result = rsa_encrypt(data, key_data)
                else: # Decrypt
                    key_data = load_from_file(input("Enter private key file path: "))
                    if key_data:
                        data = get_text_or_file()
                        if data:
                           result = rsa_decrypt(data, key_data)
                output_is_text = (mode == "decrypt")

            elif choice == "9": # Atbash
                data = get_text_or_file()
                if data:
                    result = atbash_cipher(data)

            elif choice == "10": # ChaCha20
                mode = get_mode()
                password = get_password("Enter password for ChaCha20 key: ")
                salt = os.urandom(SALT_SIZE)
                if mode == "decrypt":
                     salt_hex = input("Enter salt (hex) used during encryption: ")
                     try:
                         salt = bytes.fromhex(salt_hex)
                     except ValueError:
                         print("Invalid salt format.")
                         continue
                else:
                    print(f"Generated Salt (hex - SAVE THIS for decryption!): {salt.hex()}")

                key = derive_key(password, salt, 32) # ChaCha20 needs a 32-byte key

                data = get_text_or_file()
                if data:
                    if mode == "encrypt":
                        result = chacha20_encrypt(data, key)
                    else:
                        result = chacha20_decrypt(data, key)
                    output_is_text = (mode == "decrypt")

            elif choice == "11": # MD5
                data = get_text_or_file()
                if data:
                    result = md5_hash(data).encode() # Keep as bytes for consistent handling

            elif choice == "12": # SHA-256
                data = get_text_or_file()
                if data:
                    result = sha256_hash(data).encode()

            elif choice == "13": # SHA-512
                data = get_text_or_file()
                if data:
                    result = sha512_hash(data).encode()

            elif choice == "14": # PBKDF2
                pbkdf2_derive()
                result = None # No direct output to display

            elif choice == "15": # Generate RSA Keys
                private_key, public_key = generate_rsa_keys()
                save_to_file("private.pem", private_key)
                save_to_file("public.pem", public_key)
                print("RSA keys generated and saved as 'private.pem' and 'public.pem'.")
                result = None

            elif choice == "16":
                print("Thank you for using the Cryptography Toolkit! Goodbye! 👋")
                break

            else:
                print("Invalid choice. Please try again.")

            # --- Output Handling ---
            if result is not None:
                print("\n--- Result ---")
                if output_is_text:
                    try:
                        print(result.decode())
                    except UnicodeDecodeError:
                        print("Result contains non-text data. Displaying as Base64:")
                        print(base64.b64encode(result).decode())
                else:
                    print("Result (Base64 encoded):")
                    print(base64.b64encode(result).decode())

                save_choice = input("Save result to file? (y/n): ").lower()
                if save_choice == 'y':
                    filename = input("Enter output filename: ")
                    save_to_file(filename, result)

        except ValueError as ve:
            print(f"Input Error: {ve}. Please enter valid data.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
