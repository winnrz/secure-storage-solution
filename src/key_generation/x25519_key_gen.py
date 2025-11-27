import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def generate_x25519_keypair(username: str, key_dir="store"):
    """
    Generate an X25519 key pair for <username> and save them to disk under /store.
    
    Files created:
        store/<username>_x25519_private.key
        store/<username>_x25519_public.key
    """

    # Ensure directory exists
    os.makedirs(key_dir, exist_ok=True)

    # 1. Generate X25519 private key
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 2. Convert to raw bytes using serialization module
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # 3. File paths
    priv_path = os.path.join(key_dir, f"{username}_x25519_private.key")
    pub_path  = os.path.join(key_dir, f"{username}_x25519_public.key")

    # 4. Save keys
    with open(priv_path, "wb") as f:
        f.write(private_bytes)

    with open(pub_path, "wb") as f:
        f.write(public_bytes)

    print(f"✔ X25519 private key saved to: {priv_path}")
    print(f"✔ X25519 public key saved to:  {pub_path}")

    return private_key, public_key
