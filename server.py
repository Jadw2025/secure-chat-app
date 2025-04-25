# Name: Jad Wahab
# Class: CIS 446 – Mobile and Wireless Security
# Term Project: Secure Mobile Messaging App (Encrypted Chat Server)

import socket 
import threading
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Sets the server to use localhost and port 55555
HOST = '127.0.0.1'
PORT = 55555

# Defines a 16-byte AES encryption key and initialization vector (IV)
KEY = b'ThisIsASecretKey'
IV = b'ThisIsAnIV456789'

# Initializes the server socket with IPv4 and TCP settings
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

# Stores all connected client sockets and their usernames
clients = []
usernames = []

# Encrypts a given message using AES encryption in CBC mode and returns base64-encoded output
def encrypt_message(message):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pads the message to a multiple of 16 bytes (AES block size requirement)
    padded = message + ' ' * (16 - len(message) % 16)
    ct = encryptor.update(padded.encode()) + encryptor.finalize()
    return base64.b64encode(ct)

# Decrypts a base64-encoded AES-encrypted message and removes trailing padding
def decrypt_message(ciphertext_b64):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    ct = base64.b64decode(ciphertext_b64)
    pt = decryptor.update(ct) + decryptor.finalize()
    return pt.decode().rstrip()

# Sends an encrypted message to all clients except the sender
def broadcast(message, sender=None):
    encrypted = encrypt_message(message)
    for client in clients:
        if client != sender:
            try:
                client.send(encrypted)
            except:
                # Closes and removes the client if an error occurs
                client.close()
                if client in clients:
                    clients.remove(client)

# Listens for and handles messages from a single client
def handle(client):
    while True:
        try:
            # Receives encrypted data from the client
            encrypted_message = client.recv(1024)
            if not encrypted_message:
                break
            # Decrypts the message and appends the sender’s username
            decrypted_text = decrypt_message(encrypted_message)
            index = clients.index(client)
            full_message = f"{usernames[index]}: {decrypted_text}"
            broadcast(full_message, sender=client)
        except:
            # Handles disconnection and notifies other clients
            index = clients.index(client)
            client.close()
            username = usernames[index]
            broadcast(f"{username} has left the chat.")
            clients.remove(client)
            usernames.remove(username)
            break

# Continuously accepts new client connections and starts a new thread for each
def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}")

        # Requests and receives the client's username
        client.send("USERNAME".encode())
        username = client.recv(1024).decode()

        usernames.append(username)
        clients.append(client)

        print(f"Username is {username}")
        client.send(encrypt_message("Connected to the server!"))
        broadcast(f"{username} joined the chat!", sender=client)

        # Starts a separate thread to manage communication with the connected client
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

# Starts the server and begins accepting incoming connections
print("Server is listening...")
receive()
