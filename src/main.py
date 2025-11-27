# To activate the venv -> source venv/bin/activate

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
  #Generates a random salt for HKDF
  salt = os.urandom(16)

  # Create a Ed25519 key pair
  e_priv_alice, e_pub_alice = generate_ed25519_keypair("alice")

  # Create a X25519 key pair
  x_priv_alice, x_pub_alice = generate_x25519_keypair("alice")

  # Create a Ed25519 key pair
  e_priv_bob, e_pub_bob = generate_ed25519_keypair("bob")

  # Create a X25519 key pair
  x_priv_bob, x_pub_bob = generate_x25519_keypair("bob")

  # Generate ephemeral key pair
  ephemeral_priv, ephemeral_pub = generate_ephemeral_x25519_keypair()

  # Derive shared secret with recipient's long-term X25519 public key
  shared_secret = ephemeral_priv.exchange(x_pub_bob)

  # Derive AES key from shared secret
  aes_key = generate_aes_key(shared_secret, salt = salt)

  # Encrypt a file using the derived AES key
  encrypted_path = aes_gcm_encrypt_file(aes_key, "plaintext/plaintext.txt", "encryption_res/ciphertext.enc")

  # Sign the encrypted file with sender's Ed25519 private key
  digital_signature = sign_message(e_priv_alice, "encryption_res/ciphertext.enc")

  # Serialize ephemeral public key to bytes for packaging
  ephemeral_pub_bytes = ephemeral_pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

  # Create secure package
  package = create_secure_package(
    ciphertext_path="encryption_res/ciphertext.enc",
    ephemeral_pub_bytes=ephemeral_pub_bytes,
    signature_bytes=digital_signature,
    salt_bytes=salt
)

  #  Decode the package
  ephemeral_pub_bytes, signature_bytes, salt_bytes, ciphertext_path = decode_package(package)

  # Verify the sender's signature
# Verify the sender's signature
  is_valid = verify_signature(e_pub_alice, signature_bytes, ciphertext_path)

  if not is_valid:
    raise Exception("✘ Signature verification failed!")
  else:
    print("✔ Proceeding with decryption...")

  # Derive shared secret with recipient's long-term X25519 private key
  aes_key = derive_aes_key(x_priv_bob, ephemeral_pub_bytes, salt_bytes)

  # Decrypt the file using the derived AES key
  decrypted_path = aes_gcm_decrypt_file(aes_key, ciphertext_path, "decryption_res/plaintext_decrypted.txt")

























    
    





    




    