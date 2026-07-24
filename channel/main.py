from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from manager import manager
import uvicorn

app = FastAPI(title="E2E Cryptic Channel")

@app.websocket("/ws/{node_id}")
async def websocket_endpoint(websocket: WebSocket, node_id: str):
    await manager.connect(node_id, websocket)
    try:
        while True:
            # Expecting JSON: {"target": "node_b_id", "payload": "ENCRYPTED_DATA"}
            data = await websocket.receive_json()
            
            target_id = data.get("target")
            payload = data.get("payload")

            if target_id and payload:
                # Relay the message
                success = await manager.send_to_node(target_id, {
                    "from": node_id,
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