from cryptography.hazmat.primitives.asymmetric import ed25519

def sign_message(sender_private_key: ed25519.Ed25519PrivateKey, file_path: str) -> bytes:
    """
    Sign the contents of a file using Ed25519.

    Args:
        sender_private_key: Ed25519 private key object
        file_path: path to the file to sign

    Returns:
        signature as bytes
    """
    with open(file_path, "rb") as f:
        data = f.read()

    signature = sender_private_key.sign(data)
    return signature
