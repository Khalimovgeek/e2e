from fastapi import WebSocket
from typing import Dict

class ConnectionManager:
    def __init__(self):
        self.active_connections = {} 
        # Map node_id -> {"public_keys": {...}, "username": "alice"}
        self.peer_registry = {} 

    async def connect(self, node_id: str, websocket: WebSocket, registration_data: dict):
        self.active_connections[node_id] = websocket
        self.peer_registry[node_id] = {
            "public_keys": registration_data["public_keys"],
            "username": registration_data.get("username", node_id) # Default to ID
        }
        print(f"[Channel] Registered {node_id}")

    def get_keys(self, node_id: str):
        return self.peer_registry.get(node_id)

    def disconnect(self, node_id: str):
        if node_id in self.active_connections:
            del self.active_connections[node_id]
            print(f"[Channel] Node {node_id} disconnected.")

        if node_id in self.peer_registry:
            username = self.peer_registry[node_id].get("username", node_id)
            del self.peer_registry[node_id]
            print(f"[Channel] Cleanup: {username} ({node_id}) removed from registry.")

            
    async def send_to_node(self, target_id: str, message: dict):
        if target_id in self.active_connections:
            await self.active_connections[target_id].send_json(message)
            return True
        return False

manager = ConnectionManager()

