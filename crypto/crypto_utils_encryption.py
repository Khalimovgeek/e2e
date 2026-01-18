from cryptography.hazmat.primitives.ciphers.aead import  AESGCM
import os, base64

def encrypt_message(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce  = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce,
                                plaintext,
                                associated_data=None
    )

    return {
        "ciphertext": 
    base64.b64encode(ciphertext).decode(),
        "nonce":
    base64.b64encode(nonce).decode()
    }
