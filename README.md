# Python Cryptography Toolkit

This is a Command Line Interface (CLI) based cryptography tool written in Python. It allows users to encrypt, decrypt, hash messages, and derive keys using a variety of cryptographic algorithms. This application is designed to help users understand and practice fundamental cryptography concepts in a hands-on manner.

## Features

This application supports a wide range of cryptographic algorithms and functionalities:

**Classic & Simple Ciphers:**
1.  **Caesar Cipher**: Encrypt/decrypt with a character shift.
2.  **ROT13 Cipher**: Simple substitution with a 13-character shift.
3.  **Atbash Cipher**: Simple substitution (reverses the alphabet).
4.  **XOR Cipher**: Encrypt/decrypt using XOR with a repeating key.
5.  **Vigenère Cipher**: Polyalphabetic substitution using a keyword.

**Modern Symmetric Ciphers:**
6.  **Fernet (AES-128-CBC)**: High-level symmetric encryption with authentication. Supports key generation/loading.
7.  **Blowfish (CBC Mode)**: Symmetric block cipher using Cipher Block Chaining and PKCS7 padding. Keys derived using PBKDF2.
8.  **ChaCha20-Poly1305**: Modern, fast, and secure Authenticated Encryption with Associated Data (AEAD) stream cipher. Keys derived using PBKDF2.

**Asymmetric Ciphers:**
9.  **RSA (OAEP Padding)**: Asymmetric encryption/decryption using public/private keys with OAEP padding. Supports key generation/saving/loading.

**Encoding:**
10. **Base64 Encoding**: Encode/decode data to/from Base64 format.

**Hashing:**
11. **MD5 Hashing**: Generate MD5 hash (Note: MD5 is considered insecure for cryptographic use).
12. **SHA-256 Hashing**: Generate SHA-256 hash.
13. **SHA-512 Hashing**: Generate SHA-512 hash.

**Key Derivation:**
14. **PBKDF2**: Derive strong cryptographic keys from user passwords using PBKDF2HMAC-SHA256.

**Utilities:**
15. **RSA Key Generation**: Generate and save RSA public/private key pairs.
16. **File I/O**: Supports encrypting/decrypting both text input and files.
17. **Secure Password Input**: Uses `getpass` for hidden password entry.

## Requirements

* Python 3.x
* `cryptography` library
* `pycryptodomex` library

## Installation

1.  **Clone the Repository (Optional):**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```
2.  **Install Dependencies:**
    Make sure you have Python 3.x installed. Then, install the required libraries using pip:
    ```bash
    pip install cryptography pycryptodomex
    ```

## How to Use

1.  **Save the Script:** Save the provided Python code as a file (e.g., `crypto_tool.py`).
2.  **Run the Application:**
    Execute the script from your terminal:
    ```bash
    python crypto_tool.py
    ```
3.  **Choose an Option:** The application will display a menu. Enter the number corresponding to the desired algorithm or action.
4.  **Follow Prompts:** The tool will guide you through the process, asking for input (text or file), keys, passwords, modes (encrypt/decrypt), etc.
5.  **View/Save Results:** The result will be displayed. For non-text results (like ciphertext), it will be shown in Base64 encoding. You will be prompted if you wish to save the result to a file.

**Important Notes:**

* **Key Management:** For RSA and Fernet, you can save/load keys. For Blowfish and ChaCha20, it uses PBKDF2; **you must save the salt** displayed during encryption to use it for decryption.
* **File Paths:** When prompted for file paths, provide the correct path to your input or key files.
* **Output:** Encrypted data is often binary. The tool displays it as Base64 for readability, but when saving to a file, it saves the raw binary data.

## Example Usage

### SHA-256 Hashing

--- Cryptography Toolkit ---
Choose an algorithm or action:
...
12. SHA-256 Hash
...
16. Exit
Enter your choice (1-16): 12
Process text input or file? (text/file): text
Enter text: Hello World
--- Result ---
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
Save result to file? (y/n): n

### ChaCha20 Encryption (Password-Based)

Enter your choice (1-16): 10
Choose mode (encrypt/decrypt): encrypt
Enter password for ChaCha20 key: ****
Generated Salt (hex - SAVE THIS for decryption!): 8a...d3
Process text input or file? (text/file): text
Enter text: This is a secret message.
--- Result ---
Result (Base64 encoded):
OGo...Jk=
Save result to file? (y/n): y
Enter output filename: secret.enc
Data saved to secret.enc

### RSA Decryption (Using Saved Key)

Enter your choice (1-16): 8
Choose mode (encrypt/decrypt): decrypt
Enter private key file path: private.pem
Process text input or file? (text/file): file
Enter file path: secret.enc
--- Result ---
This is a secret message.
Save result to file? (y/n): n

## Security Considerations

* **Algorithm Choice:** Not all algorithms here are suitable for all purposes. Caesar, ROT13, Atbash, and XOR (as implemented) are weak and should only be used for educational purposes. MD5 is broken and should not be used for security. Use AES (Fernet), ChaCha20, and RSA for secure applications.
* **Key Security:** **Your keys are your security.** Store private keys and Fernet keys securely. Do *not* share private keys.
* **Salts & Nonces:** Salts (used in PBKDF2) and Nonces/IVs (used in CBC/ChaCha20) are crucial. Salts can be stored publicly with the ciphertext, but **never reuse a Nonce/IV with the same key**. This tool generates them randomly, but be aware of this principle.
* **Passwords:** Use strong, unique passwords when using PBKDF2-based options.

## Contributing

If you wish to contribute to this project, please follow these steps:

1.  Fork this repository.
2.  Create a new branch for your feature or fix (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).

## Contact

If you have questions or suggestions, feel free to reach out:

* **Email**: [service@obscuraworks.com]
* **GitHub**: [NyxObscura]

