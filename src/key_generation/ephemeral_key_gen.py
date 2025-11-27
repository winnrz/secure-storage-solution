from cryptography.hazmat.primitives.asymmetric import x25519

def generate_ephemeral_x25519_keypair():
    """
    Generate an ephemeral X25519 key pair for one-time use in ECDH.
    
    Returns:
        ephemeral_private_key (X25519PrivateKey)
        ephemeral_public_key  (X25519PublicKey)
    
    Note:
        - The private key should be discarded after use.
        - The public key is sent to the recipient along with the encrypted data.
    """
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key  = ephemeral_private_key.public_key()
    
    return ephemeral_private_key, ephemeral_public_key
