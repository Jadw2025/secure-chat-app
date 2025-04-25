# Name: Jad Wahab
# Class: CIS 446 – Mobile and Wireless Security
# Term Project: Secure Mobile Messaging App (Encrypted Chat Client)

import socket
import threading
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Defines a 16-byte AES encryption key and initialization vector (IV)
KEY = b'ThisIsASecretKey'
IV = b'ThisIsAnIV456789'

# Creates a TCP client socket and connects to the server on localhost and port 55555
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))

# Encrypts a message using AES (CBC mode) and returns it as base64-encoded ciphertext
def encrypt_message(message):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pads the message to a multiple of 16 bytes for AES block alignment
    padded = message + ' ' * (16 - len(message) % 16)
    ct = encryptor.update(padded.encode()) + encryptor.finalize()
    return base64.b64encode(ct)

# Decrypts a base64-encoded AES-encrypted message and returns the plaintext
def decrypt_message(ciphertext_b64):
    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        ct = base64.b64decode(ciphertext_b64)
        pt = decryptor.update(ct) + decryptor.finalize()
        return pt.decode().rstrip()
    except:
        return "[Error: Decryption failed]"

# Continuously listens for messages from the server and prints the decrypted content
def receive():
    while True:
        try:
            message = client.recv(1024)
            print(decrypt_message(message))
        except:
            print("Disconnected from server.")
            break

# Continuously reads user input, encrypts it, and sends it to the server
def write():
    while True:
        message = input('')
        encrypted = encrypt_message(message)
        client.send(encrypted)

# Receives an initial prompt from the server requesting a username
if client.recv(1024).decode() == "USERNAME":
    username = input("Enter your username: ")
    client.send(username.encode())

# Starts two threads: one for receiving messages and one for sending them
threading.Thread(target=receive).start()
threading.Thread(target=write).start()
