from nacl.public import PrivateKey
from nacl.signing import SigningKey
import base64

def generate_x25519_keypair():
    private = PrivateKey.generate()
    public = private.public_key


    return (
        base64.b64encode(bytes(private)).decode(),
        base64.b64encode(bytes(public)).decode()
    )

def generate_e25519_keypair():

    signing_key = SigningKey.generate()
    verify_key  = signing_key.verify_key

    return (
        base64.b64encode(bytes(signing_key)).decode(),
        base64.b64encode(bytes(verify_key)).decode()
    )