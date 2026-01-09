import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_ed25519_keypair(username: str, key_dir="store", passphrase: str = None):
    """
    Generate an Ed25519 signing key pair for <username>
    and save them securely to disk.
    
    Args:
        username: user identifier
        key_dir: directory to save keys
        passphrase: optional passphrase to encrypt the private key
    """

    os.makedirs(key_dir, exist_ok=True)

    # Generate keys
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Determine encryption
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()

    # Serialize private key
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )

    # Serialize public key
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # File paths
    priv_path = os.path.join(key_dir, f"{username}_ed25519_private.key")
    pub_path  = os.path.join(key_dir, f"{username}_ed25519_public.key")

    # Save keys
    with open(priv_path, "wb") as f:
        f.write(private_bytes)
    with open(pub_path, "wb") as f:
        f.write(public_bytes)

    print(f"✔ Ed25519 private key saved to: {priv_path} (encrypted: {passphrase is not None})")
    print(f"✔ Ed25519 public key saved to:  {pub_path}")

    return public_key
