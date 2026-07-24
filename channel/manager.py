from fastapi import WebSocket
from typing import Dict

class ConnectionManager:
    def __init__(self):
        # Maps Node ID (e.g., Public Key Hash) to their WebSocket
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, node_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[node_id] = websocket
        print(f"[Channel] Node {node_id} connected.")

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