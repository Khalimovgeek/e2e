from nacl.public import PrivateKey,PublicKey,Box
from nacl.signing import SigningKey
import base64

def generate_x25519_keypair():
    private = PrivateKey.generate()
    public = private.public_key


    return {
        "private": base64.b64encode(bytes(private)).decode(),
        "public": base64.b64encode(bytes(public)).decode()
    }

def generate_session_key(sender_private_b64,peer_public_b64):
    sender_private = PrivateKey(base64.b64decode(sender_private_b64))
    peer_public    =  PublicKey(base64.b64decode(peer_public_b64))

    box = Box(sender_private,peer_public)

    return box.shared_key()


def generate_e25519_keypair():

    signing_key = SigningKey.generate()
    verify_key  = signing_key.verify_key

    return {
            "private": base64.b64encode(bytes(signing_key)).decode(),
            "public": base64.b64encode(bytes(verify_key)).decode()
        }

