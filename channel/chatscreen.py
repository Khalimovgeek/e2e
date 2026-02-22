from client import user
import time

async def main():
    print("welcome to our test chat room")

    while True:
        username = input("Please enter your name: ")

        curent_user = user(username)
        await curent_user.connect()
        print("user connected successfully")

        print("available memebers ")
        print(curent_user.users)
        

        recipient = input("please select the user you want to communicate:")


        while True:
            message = input()
            await curent_user.send(message,recipient)
            await curent_user.recieve()


        
import asyncio

asyncio.run(main())
        

# import asyncio
# from client import user as User
# from server import userlist

# async def main():
#     print("Welcome to our test chat room")

#     username = input("Enter your name: ")

#     current_user = User(username)
#     await current_user.connect()

#     print("Connected successfully!")

#     print(await userlist())

#     while True:
        
#             recipient = input("Enter recipient name: ")
#             message = input("You :")
#             await current_user.send(message,recipient)
#             print(await current_user.recieve())

# asyncio.run(main())
    
