Secure Image Vault: Advanced Cryptography & Steganography
Secure Image Vault is a comprehensive web application built with Flask and MongoDB that provides a suite of tools for robust image encryption and LSB-based steganography. It allows users to create accounts, secure their images using various advanced cryptographic algorithms, and manage their activity through a persistent history log.

The application leverages a cloud-based architecture, using Cloudinary for scalable image storage and management.


📜 Table of Contents
Key Features

Cryptographic Methods

Technology Stack

Setup and Installation

Configuration

How to Use

License

✨ Key Features
User Authentication: Secure user registration and login system.

Multi-Method Dashboard: A central hub to select from various security techniques.

Persistent History: Each user has a private history of their encryption/steganography activities, allowing them to view and decrypt past results.

Cloud Media Management: All images (original, secret, and processed) are uploaded to Cloudinary, keeping the local server stateless and scalable.

Dynamic Image Resizing: Automatically resizes large images to prevent processing errors and manage storage efficiently.

Secure Key Generation: Generates strong, random keys for encryption when a user doesn't provide one.

🔐 Cryptographic Methods
The application offers several distinct methods for securing images:

LSB Steganography:

Hides a secret image inside a cover image using the Least Significant Bit (LSB) technique.

The secret image data is first encrypted with Fernet (AES-128-CBC) before being embedded, ensuring the hidden payload is secure.

Bitplane Slicing Encryption:

Encrypts specific bit planes of an image (from 0 to 7).

Supports three different key-based stream ciphers:

AES-CTR

DES-CTR

Custom Hash-Based XOR

Uses a unique nonce for each encryption, meaning encrypting the same image twice with the same key will produce two different outputs.

Chaotic Map Encryption:

Utilizes mathematical chaotic maps to shuffle image pixels, completely distorting the image.

Supported maps:

Arnold's Cat Map

Logistic Map

Hénon Map

Key-Based XOR Cipher (Neural Network Style):

A fast and secure stream cipher that generates a keystream from a user-provided key and XORs it with the image pixels.

DNA-Based Encryption:

A conceptual model that uses a key-derived keystream to perform a secure XOR operation on the image, thematically based on DNA encoding principles.

💻 Technology Stack
Backend: Python with Flask Framework

Database: MongoDB (with PyMongo driver)

Image Processing: OpenCV, NumPy

Cryptography: PyCryptodome (for AES/DES), Cryptography (for Fernet)

Cloud Storage: Cloudinary

Environment Variables: python-dotenv

Server (optional): Gunicorn