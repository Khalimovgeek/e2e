# from client import user
# from server import connected_users
# import time

# def main():
#     print("welcome to our test chat room")

#     while True:
#         username = input("Please enter your name: ")

#         if username in connected_users:
#             print("sorry the name is already taken")
#             time.sleep(1000)
#         else:
#             curent_user = user(username)
#             curent_user.connect()
#             print("user connected successfully")

#             print("available memebers\n")
#             for i in curent_user:
#                 print(connected_users.keys)

#             recipient = ("please select the user you want to communicate:")


#             while True:
#                 message = input()
#                 user.send(message,recipient)
#                 user.recieve()


        
# import asyncio

# asyncio.run(main())
        

import asyncio
from client import user as User
from server import userlist

async def main():
    print("Welcome to our test chat room")

    username = input("Enter your name: ")

    current_user = User(username)
    await current_user.connect()

    print("Connected successfully!")

    print(await userlist())

    while True:
        
            recipient = input("Enter recipient name: ")
            message = input("You :")
            await current_user.send(message,recipient)
            print(await current_user.recieve())

asyncio.run(main())
    
