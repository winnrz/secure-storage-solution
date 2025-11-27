import base64
from typing import Dict

def create_secure_package(ciphertext_path: str,
                          ephemeral_pub_bytes: bytes,
                          signature_bytes: bytes,
                          salt_bytes: bytes) -> Dict[str, str]:
    """
    Create a secure package dictionary for sending to a recipient.
    
    Args:
        ciphertext_path: Path to the AES-GCM encrypted file
        ephemeral_pub_bytes: Ephemeral X25519 public key (bytes)
        signature_bytes: Ed25519 signature over ciphertext (bytes)
        salt_bytes: HKDF salt used to derive AES key (bytes)
    
    Returns:
        Dictionary containing base64-encoded package data.
        Keys: 'ciphertext_file', 'ephemeral_pub', 'signature', 'salt'
    """
    
    package = {
        "ciphertext_file": ciphertext_path,
        "ephemeral_pub": base64.b64encode(ephemeral_pub_bytes).decode('utf-8'),
        "signature": base64.b64encode(signature_bytes).decode('utf-8'),
        "salt": base64.b64encode(salt_bytes).decode('utf-8')
    }
    
    return package
