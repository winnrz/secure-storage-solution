# secure-storage-solution
This project implements a secure file and folder backup system featuring strong encryption, flexible key management, and support for multiple users. It allows users to encrypt and decrypt files using separate cryptographic keys, ensuring confidentiality and integrity of backed-up data. It uses modern cryptographic algorithms, including **Ed25519** for signing and **X25519** for key exchange.


## Features
- Uses **Ed25519 key pairs** for signing and verifying messages, ensuring authenticity for 'Alice' and 'Bob'  
- Uses **X25519 key pairs** for secure long-term key exchange between users  
- Generates **ephemeral X25519 keys** for one-time session encryption, adding perfect forward secrecy  
- Derives a **shared secret** and AES encryption key from ephemeral and long-term keys  
- Encrypts files with **AES-GCM**, keeping data both confidential and tamper-proof  
- Supports **Authenticated Additional Data (AAD)** to protect metadata like sender, recipient, and filename  
- Creates a **secure package** combining ciphertext, ephemeral public key, salt, and metadata  
- Signs packages with **Ed25519 private keys** to verify sender authenticity  
- Verifies digital signatures before decryption, preventing unauthorized tampering  
- Decrypts files safely using derived AES keys, reproducing the original plaintext in `decryption_res/`  
- Stores **private keys with a passphrase** for enhanced confidentiality and security  


## Setup
1. **Create a virtual environment**
```bash
python -m venv venv
```
2. **Activate the virtual environment**
```bash
# Linux / Mac
source venv/bin/activate

# Windows
venv\Scripts\activate
```
3. **Install dependencies**
```bash
pip install -r requirements.txt
```
4. **Run the program**
```bash
python src/main.py
```
