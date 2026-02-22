import asyncio
import websockets
import json


class user:
    def __init__(self,username):
        self.username = username
        self.uri = "ws://localhost:8765"

    async def connect(self):
        self.websocket = await websockets.connect(self.uri)

        #user registration
        await self.websocket.send(
            json.dumps(
                {
                    "username" : self.username
                }
            )
        )
        print(self.username)



    async def send(self,payload,recipient):
            
            # data send 
            await self.websocket.send(
                 json.dumps(
                      {
                           "message" : payload ,
                           "sender" : self.username,
                           "recipient" : recipient
                      }
                    )
            )

            #get server response
            response = await self.websocket.recv()
            response = json.loads(response)
            # print server response
            print(f"server reply :{response["response"]}")


    async def recieve(self):
        while True:
            response = await self.websocket.recv()
            print(response)



async def main():
    user1 = user("albin1")
    
    user2 = user("albin")

    await user1.connect()
    await user2.connect()

    await user1.send("hi", "albin")
    await user2.recieve()

asyncio.run(main())