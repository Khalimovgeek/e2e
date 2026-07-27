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
        await manager.connect(node_id, websocket, initial_data["public_keys"])
        
        while True:
            data = await websocket.receive_json()
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
                    await websocket.send_json({"error": "Target node offline"})
            else:
                await websocket.send_json({"error": "Invalid message format"})

    except WebSocketDisconnect:
        manager.disconnect(node_id)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)