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
        self.username = ""
        self.current_target_id = None
        self.id_to_name = {} # Map IDs to Usernames for display
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
            msg_type = data.get("type")

            if msg_type == "SYSTEM":
                print(f"\n[SYSTEM]: {data.get('message')}")
                # If target is offline, clear our current chat
                if "offline" in data.get('message').lower():
                    self.current_target_id = None
                continue

            # 1. HANDLE USER LIST
            if msg_type == "USER_LIST":
                print("\n--- Online Users ---")
                for u in data.get("users", []):
                    print(f"ID: {u['id']} | Name: {u['name']}")
                print("--------------------\n")
                continue

            # 2. HANDLE KEY REPLIES (Fixed nesting)
            if msg_type == "KEY_REPLY":
                target_id = data.get("target")
                keys_data = data.get("keys") # This is now {"public_keys": {...}, "username": ...}
                
                if keys_data:
                    pub_keys = keys_data.get("public_keys")
                    # Extract x and e from the nested dict
                    self.peers.add_peer(target_id, pub_keys["x"], pub_keys["e"])
                    self.id_to_name[target_id] = keys_data.get("username", target_id)
                    print(f"\n[*] Keys for {self.id_to_name[target_id]} received.")
                else:
                    print(f"\n[!] Server: User {target_id} not found.")
                continue

            # 3. HANDLE MESSAGES
            if "from" in data:
                sender_id = data["from"]
                content = await self.process_incoming(sender_id, data["payload"])
                # Use name if we know it, otherwise use ID
                display_name = self.id_to_name.get(sender_id, sender_id)
                print(f"\n[{display_name}]: {content}")

    async def start(self):
        # 1. Ask for username BEFORE connecting
        self.username = await aioconsole.ainput("Enter your username: ")
        
        uri = f"{self.server_url}/ws/{self.node_id}"
        async with websockets.connect(uri) as ws:
            # 2. Now the first message has the real name
            registration = {
                "public_keys": {
                    "x": self.x_keys["public"],
                    "e": self.e_keys["public"]
                },
                "username": self.username
            }
            await ws.send(json.dumps(registration))
            print(f"[*] Registered as {self.username}. ID: {self.node_id}")
            
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
        
        print(f"[*] Registered as {self.username}. Commands: /list, /chat <id>, /exit")

        while True:
            prompt = f"[{self.username} -> {self.current_target_id or 'NONE'}]: "
            user_input = await aioconsole.ainput(prompt)
            
            if user_input.startswith("/"):
                parts = user_input.split()
                cmd = parts[0].lower()

                if cmd == "/list":
                    await ws.send(json.dumps({"type": "LIST_USERS"}))
                
                elif cmd == "/chat" and len(parts) > 1:
                    target_id = parts[1]
                    if target_id not in self.peers.keys:
                        print(f"[*] Requesting keys for {target_id}...")
                        await self.get_remote_keys(ws, target_id)
                        await asyncio.sleep(0.5) # Wait for KEY_REPLY
                    
                    if target_id in self.peers.keys:
                        self.current_target_id = target_id
                        print(f"[*] Now chatting with {self.id_to_name.get(target_id, target_id)}")
                
                elif cmd == "/exit":
                    break
                elif cmd == "/name" and len(parts) > 1:
                    new_name = parts[1]
                    self.username = new_name
                    # Notify the server
                    await ws.send(json.dumps({
                        "type": "UPDATE_NAME",
                        "username": new_name
                    }))
                    print(f"[*] Name changed to {new_name}")
            else:
                if not self.current_target_id:
                    print("[!] Use /chat <id> first.")
                    continue
                
                # Logic: Only send if we have a target
                packet = await self.prepare_payload(user_input, self.current_target_id)
                if packet:
                    await ws.send(json.dumps(packet))

if __name__ == "__main__":
    node = Node("ws://localhost:8000")
    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        print("system shut down")
        sys.exit(0)
