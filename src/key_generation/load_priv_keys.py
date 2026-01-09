import os
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

def load_priv_keys(key_dir="store", passphrases: dict = None):
    """
    Load only the private keys for Alice and Bob from disk.
    
    Args:
        key_dir: directory where keys are stored
        passphrases: optional dict of passphrases for private keys, e.g.
                     {
                         "e_priv_alice": "pass1",
                         "x_priv_alice": "pass2",
                         "e_priv_bob": "pass3",
                         "x_priv_bob": "pass4"
                     }

    Returns:
        Tuple: (e_priv_alice, x_priv_alice, x_priv_bob, e_priv_bob)
    """
    if passphrases is None:
        passphrases = {}

    def load_ed25519_priv(username: str):
        priv_path = os.path.join(key_dir, f"{username}_ed25519_private.key")
        with open(priv_path, "rb") as f:
            priv_bytes = f.read()
        priv_key = serialization.load_pem_private_key(
            priv_bytes,
            password=passphrases.get(f"e_priv_{username}", None).encode() 
                     if passphrases.get(f"e_priv_{username}") else None
        )
        return priv_key

    def load_x25519_priv(username: str):
        priv_path = os.path.join(key_dir, f"{username}_x25519_private.key")
        with open(priv_path, "rb") as f:
            priv_bytes = f.read()
        priv_key = serialization.load_pem_private_key(
            priv_bytes,
            password=passphrases.get(f"x_priv_{username}", None).encode() 
                     if passphrases.get(f"x_priv_{username}") else None
        )
        return priv_key

    e_priv_alice = load_ed25519_priv("alice")
    x_priv_alice = load_x25519_priv("alice")
    x_priv_bob   = load_x25519_priv("bob")
    e_priv_bob   = load_ed25519_priv("bob")

    return e_priv_alice, x_priv_alice, x_priv_bob, e_priv_bob
