import sys
import os
import base64
import json
import asyncio
import websockets
import aioconsole # pip install aioconsole

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.crypto_utils_keys import generate_e25519_keypair, generate_x25519_keypair, generate_session_key
from crypto.crypto_utils_encryption import encrypt_message
from crypto.crypto_utils_decryption import decrypt_message
from crypto.crypto_utils_sign import sign_message
from crypto.crypto_utils_verify import verify_sign

class PeerStore:
    def __init__(self):
        self.keys = {} # { "node_id": {"exchange_pub": ..., "signing_pub": ...} }

    def add_peer(self, node_id, exchange_pub, signing_pub):
        self.keys[node_id] = {
            "exchange_pub": exchange_pub,
            "signing_pub": signing_pub
        }

class Node:
    def __init__(self, server_url):
        self.server_url = server_url
        
        # 1. Generate Identity: Exchange Keys (X25519) and Signing Keys (Ed25519)
        self.x_keys = generate_x25519_keypair()
        self.e_keys = generate_e25519_keypair()
        
        # Identity is the first 12 chars of the Signing Public Key (Hex)
        self.node_id = self.e_keys["public"][:12]
        
        self.peers = PeerStore()

    async def prepare_payload(self, message, target_id):
        """Wraps the cryptic pipeline into a transportable JSON"""
        peer = self.peers.keys.get(target_id)
        if not peer:
            return None

        # Derive shared secret using OUR private and THEIR public X25519 key
        shared_key = generate_session_key(self.x_keys["private"], peer["exchange_pub"])
        
        # Encrypt
        encrypted_bundle = encrypt_message(shared_key, message)
        
        # Sign the ciphertext+nonce to prevent tampering
        # We use the Ed25519 private key for this
        to_sign = encrypted_bundle["ciphertext"] + encrypted_bundle["nonce"]
        signature = sign_message(self.e_keys["private"], to_sign)

        return {
            "target": target_id,
            "payload": {
                "ciphertext": encrypted_bundle["ciphertext"],
                "nonce": encrypted_bundle["nonce"],
                "signature": signature,
                "signing_pub": self.e_keys["public"], # Provide our signing pub for verification
                "exchange_pub": self.x_keys["public"] # Provide our exchange pub for their next reply
            }
        }

    async def process_incoming(self, sender_id, data):
        """Unwraps incoming JSON and verifies/decrypts"""
        try:
            # 1. Store/Update peer keys from the message header
            self.peers.add_peer(sender_id, data["exchange_pub"], data["signing_pub"])
            
            # 2. Verify Signature
            to_verify = data["ciphertext"] + data["nonce"]
            is_valid = verify_sign(data["signing_pub"], to_verify, data["signature"])
            
            if not is_valid:
                return "[!] Signature mismatch! Message tampered."

            # 3. Decrypt
            shared_key = generate_session_key(self.x_keys["private"], data["exchange_pub"])
            decrypted = decrypt_message(shared_key, data["ciphertext"], data["nonce"])
            return decrypted.decode()
        except Exception as e:
            return f"[!] Decryption error: {str(e)}"

    async def start(self):
        uri = f"{self.server_url}/ws/{self.node_id}"
        async with websockets.connect(uri) as ws:
            print(f"[*] Node Online. ID: {self.node_id}")
            
            # Run receiver and sender
            await asyncio.gather(
                self.listen(ws),
                self.chat(ws)
            )

    async def listen(self, ws):
        async for message in ws:
            data = json.loads(message)
            sender_id = data["from"]
            content = await self.process_incoming(sender_id, data["payload"])
            print(f"\n[{sender_id}]: {content}")

    async def chat(self, ws):
        while True:
            target = await aioconsole.ainput("Target ID (or 'handshake'): ")
            msg = await aioconsole.ainput("Message: ")
            
            # In a real cryptic system, first message is a handshake
            # For this redo, we just send keys with every message for simplicity
            packet = await self.prepare_payload(msg, target)
            if packet:
                await ws.send(json.dumps(packet))
            else:
                # If peer unknown, we send a 'discovery' packet with just our keys
                print("[*] Peer unknown. Sending handshake...")
                handshake = {
                    "target": target,
                    "payload": {
                        "ciphertext": "", "nonce": "", "signature": "",
                        "signing_pub": self.e_keys["public"],
                        "exchange_pub": self.x_keys["public"]
                    }
                }
                await ws.send(json.dumps(handshake))

if __name__ == "__main__":
    node = Node("ws://localhost:8000")
    asyncio.run(node.start())