import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_gcm_encrypt_file(aes_key: bytes, input_path: str, output_path: str) -> str:
    """
    Encrypt a file using AES-256-GCM.

    Args:
        aes_key: 32-byte AES key
        input_path: path to plaintext file
        output_path: path to write encrypted file

    Returns:
        The path to the encrypted file
    """
    
    # AES-GCM requires a 12-byte nonce
    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)

    # Read plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Encrypt (ciphertext includes the GCM tag automatically)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Write nonce + ciphertext to output
    with open(output_path, "wb") as f:
        f.write(nonce + ciphertext)

    # Print confirmation message
    print(f"✔ File encrypted successfully and stored at: {output_path}")

    return output_path
