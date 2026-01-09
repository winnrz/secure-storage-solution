import base64
from typing import Tuple, Dict

def decode_package(package: Dict[str, str]) -> Tuple[bytes, bytes, bytes]:
    """
    Decode base64-encoded elements from a secure package.

    Args:
        package: Dictionary containing the keys:
                 'ciphertext', 'ephemeral_pub', 'salt'

    Returns:
        Tuple of:
            ephemeral_pub_bytes: Ephemeral X25519 public key bytes
            salt_bytes: HKDF salt bytes
            ciphertext_bytes: AES-GCM encrypted file bytes
    """

    ephemeral_pub_bytes = base64.b64decode(package["ephemeral_pub"])
    salt_bytes = base64.b64decode(package["salt"])
    ciphertext_bytes = base64.b64decode(package["ciphertext"])

    return ephemeral_pub_bytes, salt_bytes, ciphertext_bytes
