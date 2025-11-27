from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_aes_key(shared_secret: bytes, salt: bytes = None, info: bytes = b"file-encryption") -> bytes:
    """
    Derive a 256-bit AES key from a shared secret using HKDF-SHA256.
    
    Args:
        shared_secret: Raw bytes from X25519 ECDH
        salt: Optional salt; should be random or None
        info: Optional context/application info (used in HKDF)
    
    Returns:
        aes_key (32 bytes) suitable for AES-256
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,       # 256-bit AES key
        salt=salt,       # Can be None
        info=info,
    )
    aes_key = hkdf.derive(shared_secret)
    return aes_key
