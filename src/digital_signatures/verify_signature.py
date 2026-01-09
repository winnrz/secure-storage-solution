import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing import Dict

def verify_signature(sender_ed_pub: ed25519.Ed25519PublicKey,
                     signature_bytes: bytes,
                     package: Dict) -> bool:
    """
    Verify the Ed25519 signature over a package dictionary.
    Returns True if valid, False if invalid.
    """

    try:
        # Add version and algorithm identifiers (must match signing)
        package_to_verify = package.copy()
        package_to_verify["version"] = 1
        package_to_verify["cipher"] = "AES-256-GCM"
        package_to_verify["kdf"] = "HKDF-SHA256"

        # Canonical serialization (must match sign_message)
        package_bytes = json.dumps(
            package_to_verify,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        # Verify signature
        sender_ed_pub.verify(signature_bytes, package_bytes)
        print("✔ Signature is valid.")
        return True
    except Exception:
        print("✘ Signature is INVALID.")
        return False
