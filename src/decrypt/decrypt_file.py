from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_gcm_decrypt_file(aes_key: bytes, ciphertext_bytes: bytes, output_path: str, aad: bytes) -> str:
    """
    Decrypt a file encrypted with AES-GCM.
    Returns path to decrypted file.
    """

    # Extract nonce and ciphertext
    nonce = ciphertext_bytes[:12]
    ciphertext = ciphertext_bytes[12:]

    # Decrypt
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=aad)

    # Write decrypted output
    with open(output_path, "wb") as f:
        f.write(plaintext)

    # Print confirmation message
    print(f"✔ File decrypted successfully and stored at: {output_path}")

    return output_path
