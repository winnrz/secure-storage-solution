import base64

def decode_package(package: dict):
    """
    Decode base64 elements from a secure package.
    
    Returns:
        ephemeral_pub_bytes, signature_bytes, salt_bytes, ciphertext_path
    """
    ephemeral_pub_bytes = base64.b64decode(package["ephemeral_pub"])
    signature_bytes = base64.b64decode(package["signature"])
    salt_bytes = base64.b64decode(package["salt"])
    ciphertext_path = package["ciphertext_file"]
    return ephemeral_pub_bytes, signature_bytes, salt_bytes, ciphertext_path