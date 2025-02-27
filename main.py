from cryptography.fernet import Fernet
from Crypto.Cipher import Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
import base64
import os

# 1. Caesar Cipher
def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift if mode == "encrypt" else -shift
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift_amount) % 26 + start)
        else:
            result += char
    return result

# 2. AES Encryption
def generate_aes_key():
    return Fernet.generate_key()

def aes_encrypt(text, key):
    fernet = Fernet(key)
    return fernet.encrypt(text.encode())

def aes_decrypt(encrypted_text, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_text).decode()

# 3. Base64 Encoding
def base64_encode(text):
    return base64.b64encode(text.encode()).decode()

def base64_decode(encoded_text):
    return base64.b64decode(encoded_text).decode()

# 4. ROT13 Cipher
def rot13(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

# 5. XOR Cipher
def xor_cipher(text, key):
    return ''.join(chr(ord(c) ^ ord(key)) for c in text)

# 6. Vigenère Cipher
def vigenere_cipher(text, key, mode):
    result = []
    key = key.lower()
    key_length = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('a')
            shift = shift if mode == "encrypt" else -shift
            start = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - start + shift) % 26 + start))
        else:
            result.append(char)
    return ''.join(result)

# 7. MD5 Hashing
def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

# 8. SHA-256 Hashing
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# 9. Blowfish Encryption
def blowfish_encrypt(text, key):
    cipher = Blowfish.new(key.ljust(16, b'\0'), Blowfish.MODE_ECB)
    while len(text) % 8 != 0:
        text += " "
    return base64.b64encode(cipher.encrypt(text.encode())).decode()

def blowfish_decrypt(encrypted_text, key):
    cipher = Blowfish.new(key.ljust(16, b'\0'), Blowfish.MODE_ECB)
    return cipher.decrypt(base64.b64decode(encrypted_text)).decode().strip()

# 10. RSA Encryption
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(text, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(text.encode())).decode()

def rsa_decrypt(encrypted_text, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(encrypted_text)).decode()

# Main Application
def main():
    print("Selamat datang di Aplikasi Kriptografi!")
    while True:
        print("\nPilih algoritma:")
        print("1. Caesar Cipher")
        print("2. AES")
        print("3. Base64")
        print("4. ROT13")
        print("5. XOR Cipher")
        print("6. Vigenère Cipher")
        print("7. MD5 Hashing")
        print("8. SHA-256 Hashing")
        print("9. Blowfish")
        print("10. RSA")
        print("11. Keluar")
        choice = input("Masukkan pilihan (1-11): ")

        if choice == "1":
            text = input("Masukkan pesan: ")
            shift = int(input("Masukkan shift (angka): "))
            mode = input("Pilih mode (encrypt/decrypt): ").lower()
            result = caesar_cipher(text, shift, mode)
            print(f"Hasil {mode}: {result}")

        elif choice == "2":
            key = generate_aes_key()
            print(f"Kunci AES Anda: {key.decode()}")
            text = input("Masukkan pesan: ")
            mode = input("Pilih mode (encrypt/decrypt): ").lower()
            if mode == "encrypt":
                encrypted_text = aes_encrypt(text, key)
                print(f"Hasil enkripsi: {encrypted_text.decode()}")
            else:
                encrypted_text = input("Masukkan teks terenkripsi: ").encode()
                print(f"Hasil dekripsi: {aes_decrypt(encrypted_text, key)}")

        elif choice == "3":
            text = input("Masukkan pesan: ")
            print(f"Base64 Encode: {base64_encode(text)}")

        elif choice == "4":
            text = input("Masukkan pesan: ")
            print(f"ROT13: {rot13(text)}")

        elif choice == "5":
            text = input("Masukkan pesan: ")
            key = input("Masukkan kunci satu karakter: ")
            print(f"XOR Cipher: {xor_cipher(text, key)}")

        elif choice == "6":
            text = input("Masukkan pesan: ")
            key = input("Masukkan kunci (kata): ")
            mode = input("Pilih mode (encrypt/decrypt): ").lower()
            print(f"Hasil {mode}: {vigenere_cipher(text, key, mode)}")

        elif choice == "7":
            text = input("Masukkan pesan: ")
            print(f"MD5 Hash: {md5_hash(text)}")

        elif choice == "8":
            text = input("Masukkan pesan: ")
            print(f"SHA-256 Hash: {sha256_hash(text)}")

        elif choice == "9":
            text = input("Masukkan pesan: ")
            key = input("Masukkan kunci (maks 16 karakter): ").encode()
            mode = input("Pilih mode (encrypt/decrypt): ").lower()
            if mode == "encrypt":
                print(f"Hasil enkripsi: {blowfish_encrypt(text, key)}")
            else:
                encrypted_text = input("Masukkan teks terenkripsi: ")
                print(f"Hasil dekripsi: {blowfish_decrypt(encrypted_text, key)}")

        elif choice == "10":
            private_key, public_key = generate_rsa_keys()
            print(f"Kunci Publik Anda:\n{public_key.decode()}")
            print(f"Kunci Privat Anda:\n{private_key.decode()}")
            text = input("Masukkan pesan: ")
            mode = input("Pilih mode (encrypt/decrypt): ").lower()
            if mode == "encrypt":
                print(f"Hasil enkripsi: {rsa_encrypt(text, public_key)}")
            else:
                encrypted_text = input("Masukkan teks terenkripsi: ")
                print(f"Hasil dekripsi: {rsa_decrypt(encrypted_text, private_key)}")

        elif choice == "11":
            print("Terima kasih telah menggunakan aplikasi ini!")
            break

        else:
            print("Pilihan tidak valid. Silakan coba lagi.")

if __name__ == "__main__":
    main()