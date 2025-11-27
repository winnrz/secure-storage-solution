from cryptography.hazmat.primitives.asymmetric import ed25519

def verify_signature(sender_ed_pub: ed25519.Ed25519PublicKey,
                     signature_bytes: bytes,
                     file_path: str) -> bool:
    """
    Verify the Ed25519 signature over a file.
    Returns True if valid, False if invalid.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        sender_ed_pub.verify(signature_bytes, data)
        print("✔ Signature is valid.")
        return True
    except Exception:
        print("✘ Signature is INVALID.")
        return False
