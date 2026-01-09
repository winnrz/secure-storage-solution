import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing import Dict

def sign_message(sender_private_key: ed25519.Ed25519PrivateKey,
                 package: Dict) -> bytes:
    """
    Sign a package dictionary using Ed25519.

    Args:
        sender_private_key: Ed25519 private key object
        package: Dictionary containing the package data

    Returns:
        signature as bytes
    """
    # Add version and algorithm identifiers
    package_to_sign = package.copy()
    package_to_sign["version"] = 1
    package_to_sign["cipher"] = "AES-256-GCM"
    package_to_sign["kdf"] = "HKDF-SHA256"

    # Canonical serialization (deterministic)
    package_bytes = json.dumps(
        package_to_sign,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    # Sign the serialized package
    signature = sender_private_key.sign(package_bytes)
    return signature
