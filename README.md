# Secure Chat App (AES Encrypted)

This project implements a simple secure messaging application using Python.

## Features:
- AES Encryption (128-bit, CBC mode)
- End-to-end encrypted communication between clients
- Kivy-based GUI for chat interface
- CLI-based client for command-line testing
- Realtime server-client message broadcasting

## Technologies:
- Python 3
- `socket`, `threading`
- `cryptography` library (AES)
- `kivy` (for GUI)

## How to Run:
Open **3 separate terminals** and run:
python server.py
python client.py
python client_gui.py


## Follow Prompts:
When prompted, enter a username in both the CLI and GUI clients.

Type messages to broadcast them securely to all connected users.
server.py         # Encrypted chat server
client.py         # CLI client
client_gui.py     # Kivy GUI client
README.md         # Project documentation

## Encryption Details:
- AES key: 16 bytes (ThisIsASecretKey)
- IV (Initialization Vector): 16 bytes (ThisIsAnIV456789)
- CBC (Cipher Block Chaining) mode is used.
- Messages are padded to 16-byte blocks before encryption

## Status:
- This project has been tested and confirmed working with:
- Multiple clients
- Real-time encrypted chat
- Cross-compatibility between GUI and CLI clients

## Author:
Jad Wahab
CIS 446 – Mobile and Wireless Security
Term Project – Secure Mobile Messaging App
2025
