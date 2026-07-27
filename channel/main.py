from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from manager import manager
import uvicorn

app = FastAPI(title="E2E Cryptic Channel")

@app.websocket("/ws/{node_id}")
async def websocket_endpoint(websocket: WebSocket, node_id: str):
    # 1. Accept the connection first!
    await websocket.accept() 
    
    try:
        # 2. Now you can receive the registration keys
        initial_data = await websocket.receive_json()
        # 3. Register in manager (remove the accept() call from manager.connect)
        await manager.connect(node_id, websocket, initial_data)
        
        while True:
            data = await websocket.receive_json()
            
            # ALLOW USERNAME UPDATES
            if "username" in data:
                manager.peer_registry[node_id]["username"] = data.get("username")
                print(f"[Channel] {node_id} updated name to: {data.get('username')}")
                # If this was just a name update, we can continue
                if data.get("type") == "UPDATE_NAME": 
                    continue
            msg_type = data.get("type")
            # 1. Handle Key Requests
            if msg_type == "GET_KEY":
                target_query = data.get("target")
                keys = manager.get_keys(target_query)
                await websocket.send_json({
                    "type": "KEY_REPLY", 
                    "target": target_query, 
                    "keys": keys
                })
                continue
            if msg_type == "LIST_USERS":
                users = [{"id": uid, "name": info["username"]} for uid, info in manager.peer_registry.items()]
                await websocket.send_json({"type": "USER_LIST", "users": users})
                continue
            # 2. Handle Message Relaying
            target_id = data.get("target") # Get target for messages
            payload = data.get("payload")

            if target_id and payload:
                success = await manager.send_to_node(target_id, {
                    "from": node_id,
                    "type": "MESSAGE", # Tell the node what this is
                    "payload": payload
                })
                if not success:
                    # Notify the sender that the target is gone
                    await websocket.send_json({
                        "type": "SYSTEM",
                        "message": f"Target {target_id} is offline. Message not delivered."
                    })            
            else:
                await websocket.send_json({"error": "Invalid message format"})

    except WebSocketDisconnect:
        manager.disconnect(node_id)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)