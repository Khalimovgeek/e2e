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
        peer = self.peers.keys.get(target_id)
        if not peer: return None

        shared_key = generate_session_key(self.x_keys["private"], peer["exchange_pub"])
        
        # Ensure message is bytes for your AES utility
        msg_bytes = message.encode('utf-8') if isinstance(message, str) else message
        encrypted_bundle = encrypt_message(shared_key, msg_bytes)
        
        # Normalize to strings for JSON transport
        ciphertext = base64.b64decode(encrypted_bundle["ciphertext"])
        nonce = base64.b64decode(encrypted_bundle["nonce"])
        payload = ciphertext + nonce
        signature = sign_message(self.e_keys["private"], payload)

        # FINAL JSON WRAP: Ensure all fields are strings (Base64)
        def finalize(val):
            if isinstance(val, bytes):
                return base64.b64encode(val).decode('utf-8')
            return str(val).strip()

        return {
            "target": target_id,
            "payload": {
                "ciphertext": finalize(ciphertext),
                "nonce": finalize(nonce),
                "signature": finalize(signature),
                "signing_pub": self.e_keys["public"],
                "exchange_pub": self.x_keys["public"]
            }
        }

    async def process_incoming(self, sender_id, data):
        try:
            ciphertext_bytes = base64.b64decode(data["ciphertext"])
            nonce_bytes = base64.b64decode(data["nonce"])

            payload = ciphertext_bytes + nonce_bytes
            is_valid = verify_sign(
                data["signing_pub"],
                payload,
                data["signature"]        
            )
            if not is_valid:
                return "[!] Signature mismatch!"

            # ... rest of decryption ...
            shared_key = generate_session_key(self.x_keys["private"], data["exchange_pub"])
            decrypted = decrypt_message(shared_key, data["ciphertext"], data["nonce"])
            return decrypted.decode('utf-8')

        except Exception as e:
            return f"[!] Decryption error: {str(e)}"
    async def listen(self, ws):
        async for message in ws:
            data = json.loads(message)
            
            # CASE 1: The server is sending us keys we asked for
            if data.get("type") == "KEY_REPLY":
                target_id = data.get("target")
                keys = data.get("keys")
                if keys:
                    # Save the keys so prepare_payload can find them
                    self.peers.add_peer(target_id, keys["x"], keys["e"])
                    print(f"\n[*] Received keys for {target_id}. Ready to chat.")
                else:
                    print(f"\n[!] Server: User {target_id} not found.")
                continue

            # CASE 2: A normal chat message from another node
            if "from" in data:
                sender_id = data["from"]
                content = await self.process_incoming(sender_id, data["payload"])
                print(f"\n[{sender_id}]: {content}")
    async def start(self):
        uri = f"{self.server_url}/ws/{self.node_id}"
        async with websockets.connect(uri) as ws:
            # 1. Register our keys immediately
            registration = {
                "public_keys": {
                    "x": self.x_keys["public"],
                    "e": self.e_keys["public"]
                }
            }
            await ws.send(json.dumps(registration))
            
            await asyncio.gather(self.listen(ws), self.chat(ws))

    async def get_remote_keys(self, ws, target_id):
        """Ask the channel for a target's public keys"""
        await ws.send(json.dumps({
            "type": "GET_KEY",
            "target": target_id
        }))
        # In a real app, you'd wait for the KEY_REPLY message.
        # For a quick fix, we can just handle it in the listen loop.

    async def chat(self, ws):
        while True:
            target = await aioconsole.ainput("\nTarget ID: ")
            
            # FIX: Check .keys dictionary, not the object itself
            if target not in self.peers.keys: 
                print(f"[*] Fetching keys for {target}...")
                await self.get_remote_keys(ws, target)
                await asyncio.sleep(0.5) 
                
                if target not in self.peers.keys:
                    print("[!] Target not found on server.")
                    continue

            msg = await aioconsole.ainput("Message: ")
            # Now encryption will work because keys are in self.peers
            packet = await self.prepare_payload(msg, target)
            await ws.send(json.dumps(packet))

if __name__ == "__main__":
    node = Node("ws://localhost:8000")
    asyncio.run(node.start())