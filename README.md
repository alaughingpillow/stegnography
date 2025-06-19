# 🕵️‍♂️ StegOSAURUS: Secure Image Steganography Tool

A powerful Flask-based web tool that lets you securely hide and extract secret messages in images using **AES encryption (Fernet)** and **HMAC integrity checks**. Ideal for secure communication and learning steganography with modern cryptography.

---

## 🔐 Features

- 🔑 **End-to-End Encryption**  
  Uses **Fernet (AES-CBC with HMAC)** to encrypt your messages before embedding.

- 🧂 **Password-Based Key Derivation**  
  Utilizes `PBKDF2HMAC` with SHA-256 for strong key derivation from user passwords.

- 🖼️ **LSB Steganography**  
  Hides encrypted data in the **least significant bits** of the image pixels.

- 🧪 **HMAC-SHA256 Verification**  
  Ensures that extracted messages are **untampered** and valid.

- ⚡ Clean UI and simple web interface using Flask.

---

## 📦 Dependencies

Install all dependencies using:

```bash
pip install -r requirements.txt
