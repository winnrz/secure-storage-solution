import base64
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_aes_key(recipient_x_priv: x25519.X25519PrivateKey, ephemeral_pub_bytes: bytes, salt: bytes) -> bytes:
    ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_secret = recipient_x_priv.exchange(ephemeral_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"file-encryption"
    )
    return hkdf.derive(shared_secret)