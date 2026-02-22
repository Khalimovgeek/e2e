import asyncio
import websockets
import json
from rest_framework import status

# list of users
connected_users ={}

async def handler(websocket):
    #user gets registered 
    register = await websocket.recv()
    data = json.loads(register)

    # gets userdata
    username = data["username"]

    # save the websocket
    connected_users[username] = websocket

    # debug print for user connected
    print(f"username {username}")

    try:
        async for payload in websocket:

            payload_transmitted = json.loads(payload)

            recipient = payload_transmitted["recipient"]
            sender = payload_transmitted["sender"]
            text = payload_transmitted["message"]


            if recipient in connected_users:
                await connected_users[recipient].send(
                    json.dumps({
                        "message" : text,
                        "sender"  : sender,
                        

                    })
                )
                await websocket.send(
                    json.dumps(
                        {
                        "response": "message send succcessfully",
                        "status" : status.HTTP_200_OK
                    }
                    )
                )
            else:
                await websocket.send(
                    json.dumps(
                        {
                        "error": "Recipient not connected",
                        "status" : status.HTTP_404_NOT_FOUND
                    }
                    )
                )
    finally:
        del connected_users[username]
        print(f"{username} disconnected")


async def main():
    async with websockets.serve(handler,"localhost", 8765):
        await asyncio.Future()

asyncio.run(main())

