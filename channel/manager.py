from fastapi import WebSocket
from typing import Dict

class ConnectionManager:
    def __init__(self):
        self.active_connections = {}
        # New: Global directory of public keys
        self.peer_registry = {} 

    async def connect(self, node_id: str, websocket: WebSocket, public_keys: dict):
        self.active_connections[node_id] = websocket
        # Store keys when the node connects
        self.peer_registry[node_id] = public_keys
        print(f"[Channel] Registered {node_id}")

    def get_keys(self, node_id: str):
        return self.peer_registry.get(node_id)

    def disconnect(self, node_id: str):
        if node_id in self.active_connections:
            del self.active_connections[node_id]
            print(f"[Channel] Node {node_id} disconnected.")

    async def send_to_node(self, target_id: str, message: dict):
        if target_id in self.active_connections:
            await self.active_connections[target_id].send_json(message)
            return True
        return False

manager = ConnectionManager()

