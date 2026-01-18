from crypto_utils_keys import generate_e25519_keypair,generate_x25519_keypair
from crypto_utils_encryption import encrypt_message
from crypto_utils_decryption import decrypt_message
import os


session_key = os.urandom(32)

msg ="hi".encode("utf-8")

encrypted = encrypt_message(session_key,msg)
print(encrypted)
decrypted = decrypt_message(session_key,encrypted["ciphertext"],encrypted["nonce"])

print(decrypted)