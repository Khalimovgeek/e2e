from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64


def decrypt_message(key: bytes, cipher_text_b64: str, nonce_b64: str):
    aesgcm = AESGCM(key)
    cipher_text = base64.b64decode(cipher_text_b64)
    nonce = base64.b64decode(nonce_b64)

    return aesgcm.decrypt(nonce,data=cipher_text,associated_data=None)


