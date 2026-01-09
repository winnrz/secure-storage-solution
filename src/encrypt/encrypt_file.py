import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Optional

def aes_gcm_encrypt_file(aes_key: bytes,
                         input_path: str,
                         output_path: str,
                         aad: Optional[bytes] = None) -> bytes:
    """
    Encrypt a file using AES-256-GCM with optional AAD binding.

    Args:
        aes_key: 32-byte AES key
        input_path: path to plaintext file
        output_path: path to write encrypted file
        aad: optional associated authenticated data (bytes)

    Returns:
        The ciphertext including nonce and GCM tag (bytes)
    """
    
    # AES-GCM requires a 12-byte nonce
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    # Read plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Encrypt with optional AAD
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=aad)

    # Write nonce + ciphertext to output
    with open(output_path, "wb") as f:
        f.write(nonce + ciphertext)

    print(f"✔ File encrypted successfully and stored at: {output_path}")

    # Return the bytes for in-memory packaging
    return nonce + ciphertext
