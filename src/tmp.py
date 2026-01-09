# Activate virtual environment with: source venv/bin/activate

import os
from utils.decode_package import decode_package
from decrypt.decrypt_file import aes_gcm_decrypt_file
from key_generation.aes_key_gen import generate_aes_key
from encrypt.encrypt_file import aes_gcm_encrypt_file
from digital_signatures.sign_message import sign_message
from cryptography.hazmat.primitives import serialization
from key_generation.aes_key_derive import derive_aes_key
from utils.create_secure_package import create_secure_package
from key_generation.x25519_key_gen import generate_x25519_keypair
from key_generation.ed25519_key_gen import generate_ed25519_keypair
from digital_signatures.verify_signature import verify_signature
from key_generation.ephemeral_key_gen import generate_ephemeral_x25519_keypair

if __name__ == "__main__":
    # Produce a fresh salt value for HKDF operations
    salt = os.urandom(16)

    # Generate Ed25519 identity keys for Alice
    alice_ed_priv, alice_ed_pub = generate_ed25519_keypair("alice")

    # Generate X25519 static keys for Alice
    alice_x_priv, alice_x_pub = generate_x25519_keypair("alice")

    # Generate Ed25519 identity keys for Bob
    bob_ed_priv, bob_ed_pub = generate_ed25519_keypair("bob")

    # Generate X25519 static keys for Bob
    bob_x_priv, bob_x_pub = generate_x25519_keypair("bob")

    # Create an ephemeral X25519 keypair for the sender
    eph_priv, eph_pub = generate_ephemeral_x25519_keypair()

    # Compute a shared secret using Bob’s long-term public key
    shared_secret = eph_priv.exchange(bob_x_pub)

    # Produce an AES key from the shared secret
    aes_key = generate_aes_key(shared_secret, salt=salt)

    # Encrypt plaintext using the derived AES key
    encrypted_file = aes_gcm_encrypt_file(
        aes_key,
        "plaintext/plaintext.txt",
        "encryption_res/ciphertext.enc"
    )

    # Sign the encrypted file using Alice’s Ed25519 private key
    sig = sign_message(alice_ed_priv, "encryption_res/ciphertext.enc")

    # Convert the ephemeral public key to raw bytes for packaging
    eph_pub_bytes = eph_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Assemble all components into a secure transport package
    pkg = create_secure_package(
        ciphertext_path="encryption_res/ciphertext.enc",
        ephemeral_pub_bytes=eph_pub_bytes,
        signature_bytes=sig,
        salt_bytes=salt
    )

    # Extract data from the generated package
    eph_pub_bytes, sig_bytes, salt_bytes, cipher_path = decode_package(pkg)

    # Validate signature from Alice
    valid = verify_signature(alice_ed_pub, sig_bytes, cipher_path)

    if not valid:
        raise Exception("✘ Signature check failed!")
    else:
        print("✔ Signature OK — starting decryption...")

    # Reconstruct the AES key using Bob’s private key and the sender’s ephemeral key
    aes_key = derive_aes_key(bob_x_priv, eph_pub_bytes, salt_bytes)

    # Recover the plaintext
    output_path = aes_gcm_decrypt_file(
        aes_key,
        cipher_path,
        "decryption_res/plaintext_decrypted.txt"
    )
