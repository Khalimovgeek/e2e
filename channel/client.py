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
        

        users = await self.websocket.recv()
        users = json.loads(users)["users"]

        self.users = users

    async def disconnect(self):
        await websockets.Close(self.uri)



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
            return response



async def main():
    user1 = user("albin111")
    
    user2 = user("albin354234")

    await user1.connect()
    await user2.connect()

    print(f"server current users {user1.users}")
    await user1.send("hi", "albin354234")
    await user1.disconnect()
    await user2.recieve()
    await user2.disconnect()

asyncio.run(main())