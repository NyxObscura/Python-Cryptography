
---

# Aplikasi Kriptografi Python

Aplikasi ini adalah alat kriptografi berbasis CLI (Command Line Interface) yang memungkinkan pengguna untuk mengenkripsi, mendekripsi, dan menghash pesan menggunakan berbagai algoritma kriptografi. Aplikasi ini dirancang untuk membantu pengguna memahami dan mempraktikkan konsep dasar kriptografi.

## Fitur

Aplikasi ini mendukung algoritma kriptografi berikut:

1. **Caesar Cipher**: Enkripsi dan dekripsi dengan pergeseran karakter.
2. **AES (Advanced Encryption Standard)**: Enkripsi dan dekripsi simetris.
3. **Base64 Encoding**: Encoding dan decoding teks ke/dari Base64.
4. **ROT13 Cipher**: Enkripsi dan dekripsi sederhana dengan pergeseran 13 karakter.
5. **XOR Cipher**: Enkripsi dan dekripsi menggunakan operasi XOR.
6. **Vigenère Cipher**: Enkripsi dan dekripsi dengan kunci kata.
7. **MD5 Hashing**: Menghasilkan hash MD5 dari teks.
8. **SHA-256 Hashing**: Menghasilkan hash SHA-256 dari teks.
9. **Blowfish Encryption**: Enkripsi dan dekripsi menggunakan algoritma Blowfish.
10. **RSA Encryption**: Enkripsi dan dekripsi asimetris dengan kunci publik dan privat.

## Cara Menggunakan

1. **Install Dependencies**  
   Pastikan Anda telah menginstal Python 3.x. Kemudian, install dependensi dengan perintah:
   ```bash
   pip install -r requirements.txt
   ```

2. **Jalankan Aplikasi**  
   Jalankan aplikasi dengan perintah:
   ```bash
   python main.py
   ```

3. **Pilih Algoritma**  
   Pilih algoritma yang ingin Anda gunakan dari menu yang ditampilkan.

4. **Masukkan Pesan**  
   Ikuti petunjuk untuk memasukkan pesan, kunci, atau parameter lainnya.

5. **Lihat Hasil**  
   Aplikasi akan menampilkan hasil enkripsi, dekripsi, atau hash.

## Contoh Penggunaan

### Caesar Cipher
```
Selamat datang di Aplikasi Kriptografi!
Pilih algoritma:
1. Caesar Cipher
2. AES
3. Base64
4. ROT13
5. XOR Cipher
6. Vigenère Cipher
7. MD5 Hashing
8. SHA-256 Hashing
9. Blowfish
10. RSA
11. Keluar
Masukkan pilihan (1-11): 1
Masukkan pesan: Hello World
Masukkan shift (angka): 3
Pilih mode (encrypt/decrypt): encrypt
Hasil encrypt: Khoor Zruog
```

### AES Encryption
```
Pilih algoritma: 2
Kunci AES Anda: your_aes_key_here
Masukkan pesan: Hello World
Pilih mode (encrypt/decrypt): encrypt
Hasil enkripsi: gAAAAABl... (teks terenkripsi)
```

### RSA Encryption
```
Pilih algoritma: 10
Kunci Publik Anda:
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
Kunci Privat Anda:
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
Masukkan pesan: Hello World
Pilih mode (encrypt/decrypt): encrypt
Hasil enkripsi: encrypted_rsa_text
```

## Dependencies

- `cryptography`: Untuk implementasi AES dan RSA.
- `pycryptodome`: Untuk implementasi Blowfish dan RSA.

## Kontribusi

Jika Anda ingin berkontribusi pada proyek ini, silakan ikuti langkah-langkah berikut:

1. Fork repositori ini.
2. Buat branch baru untuk fitur atau perbaikan Anda.
3. Commit perubahan Anda.
4. Push ke branch yang Anda buat.
5. Buat Pull Request.

## Lisensi

Proyek ini dilisensikan di bawah [MIT License](LICENSE).

## Kontak

Jika Anda memiliki pertanyaan atau saran, silakan hubungi:

- **Email**: [service@obscuraworks.com]
- **GitHub**: [NyxObscura]

---

### **Cara Menjalankan Proyek**

1. **Install Dependencies**  
   Jalankan perintah berikut untuk menginstal dependensi:
   ```bash
   pip install cryptography pycryptodome
   ```

2. **Jalankan Aplikasi**  
   Jalankan aplikasi dengan perintah:
   ```bash
   python main.py
   ```

3. **Ikuti Petunjuk**  
   Pilih algoritma, masukkan pesan, dan lihat hasil enkripsi, dekripsi, atau hash.

---

### **Contoh Output**
- **Caesar Cipher**:
  - Input: `Hello World`, Shift: `3`, Mode: `encrypt`
  - Output: `Khoor Zruog`
- **AES**:
  - Input: `Hello World`, Mode: `encrypt`
  - Output: `gAAAAABl...` (teks terenkripsi)
- **RSA**:
  - Input: `Hello World`, Mode: `encrypt`
  - Output: `encrypted_rsa_text`

---

Dengan proyek ini, Anda dapat mempelajari dan mempraktikkan berbagai algoritma kriptografi secara langsung. Selamat mencoba! 🚀