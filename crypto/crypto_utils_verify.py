from nacl.signing import VerifyKey
import base64

def verify_sign(public_key_b64: str, message: bytes, signature_b64: str):
    vk = VerifyKey(base64.b64decode(public_key_b64))
    vk.verify(message,base64.b64decode(signature_b64))

    return True