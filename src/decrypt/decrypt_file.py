from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_gcm_decrypt_file(aes_key: bytes, encrypted_path: str, output_path: str) -> str:
    """
    Decrypt a file encrypted with AES-GCM.
    Returns path to decrypted file.
    """
    # Read encrypted data
    with open(encrypted_path, "rb") as f:
        data = f.read()

    # Extract nonce and ciphertext
    nonce = data[:12]
    ciphertext = data[12:]

    # Decrypt
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    # Write decrypted output
    with open(output_path, "wb") as f:
        f.write(plaintext)

    # Print confirmation message
    print(f"✔ File decrypted successfully and stored at: {output_path}")

    return output_path
