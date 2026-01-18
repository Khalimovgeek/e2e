from nacl.signing import SigningKey
import base64

def sign_message(private_key_b64 : str, message: bytes):
    sk = SigningKey(base64.b64decode(private_key_b64))
    signed = sk.sign(message)

    return base64.b64encode(signed.signature).decode()