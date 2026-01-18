from crypto_utils_keys import generate_e25519_keypair,generate_x25519_keypair,generate_session_key
from crypto_utils_encryption import encrypt_message
from crypto_utils_decryption import decrypt_message
import os


client_1 = generate_x25519_keypair()
client_2 = generate_x25519_keypair()

session_key_1 = generate_session_key(client_1["private"],client_2["public"])
session_key_2 = generate_session_key(client_2["private"],client_1["public"])

assert session_key_1 == session_key_2

print("✅ Session keys match")


msg ="hi".encode("utf-8")

encrypted = encrypt_message(session_key_1,msg)
print(encrypted)
decrypted = decrypt_message(session_key_2,encrypted["ciphertext"],encrypted["nonce"])

print(decrypted)