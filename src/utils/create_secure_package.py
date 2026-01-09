import base64
from typing import Dict

def create_secure_package(ciphertext_bytes: bytes,
                          ephemeral_pub_bytes: bytes,
                          salt_bytes: bytes,
                          metadata: Dict) -> Dict[str, str]:
    """
    Create a secure package dictionary for sending to a recipient.
    
    Args:
        ciphertext_bytes: AES-GCM encrypted content (bytes)
        ephemeral_pub_bytes: ephemeral X25519 public key bytes
        salt_bytes: HKDF salt bytes
        metadata: additional package metadata (dict)
    
    Returns:
        Dictionary containing base64-encoded package data and metadata
    """
    package = {
        "ciphertext": base64.b64encode(ciphertext_bytes).decode("utf-8"),
        "ephemeral_pub": base64.b64encode(ephemeral_pub_bytes).decode("utf-8"),
        "salt": base64.b64encode(salt_bytes).decode("utf-8"),
        "metadata": metadata  
    }

    return package
