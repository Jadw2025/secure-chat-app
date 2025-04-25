# Name: Jad Wahab
# Class: CIS 446 – Mobile and Wireless Security
# Term Project: Secure Mobile Messaging App (AES-Encrypted GUI Chat Client)

import socket
import threading
import base64
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Defines the AES key and IV for encryption (both 16 bytes for AES-128 CBC)
KEY = b'ThisIsASecretKey'
IV = b'ThisIsAnIV456789'

# Creates a TCP client socket and connects to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))

# Encrypts a message using AES in CBC mode and encodes it as base64
def encrypt_message(message):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pads the message to be a multiple of 16 bytes
    padded = message + ' ' * (16 - len(message) % 16)
    ct = encryptor.update(padded.encode()) + encryptor.finalize()
    return base64.b64encode(ct)

# Decrypts a base64-encoded AES message and removes padding
def decrypt_message(ciphertext_b64):
    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        ct = base64.b64decode(ciphertext_b64)
        pt = decryptor.update(ct) + decryptor.finalize()
        return pt.decode().rstrip()
    except:
        return "[Error: Unable to decrypt]"

# Defines the main Kivy app for the secure chat GUI
class ChatApp(App):
    def build(self):
        # Sets the app title and main vertical layout
        self.title = "Secure Chat App (AES Encrypted)"
        self.layout = BoxLayout(orientation='vertical')

        # Creates a label to display incoming chat messages
        self.chat_display = Label(size_hint_y=0.9)
        self.layout.add_widget(self.chat_display)

        # Creates a horizontal layout for the input box and send button
        bottom = BoxLayout(size_hint_y=0.1)
        self.msg_input = TextInput(hint_text="Enter message...", multiline=False)
        send_btn = Button(text="Send")
        send_btn.bind(on_press=self.send_msg)

        bottom.add_widget(self.msg_input)
        bottom.add_widget(send_btn)
        self.layout.add_widget(bottom)

        # Starts the background thread to receive messages
        threading.Thread(target=self.receive).start()

        # Prompts the user for a username on app launch
        self.prompt_username()

        return self.layout

    # Displays a popup asking the user to enter their username
    def prompt_username(self):
        box = BoxLayout(orientation='vertical')
        username_input = TextInput(hint_text='Enter your username')
        ok_btn = Button(text='OK')

        def on_ok(instance):
            self.username = username_input.text.strip()
            client.send(self.username.encode())
            popup.dismiss()

        box.add_widget(username_input)
        box.add_widget(ok_btn)
        popup = Popup(title='Username', content=box, size_hint=(None, None), size=(400, 200))
        ok_btn.bind(on_press=on_ok)
        popup.open()

    # Listens for messages from the server, decrypts them, and updates the chat display
    def receive(self):
        while True:
            try:
                message = client.recv(1024)
                msg = decrypt_message(message)
                self.chat_display.text += f"\n{msg}"
            except:
                break

    # Sends the user’s typed message after encryption and clears the input box
    def send_msg(self, _):
        message = self.msg_input.text
        if message:
            client.send(encrypt_message(message))
            self.msg_input.text = ""

# Entry point of the program – handles initial server handshake then launches GUI
if __name__ == "__main__":
    if client.recv(1024).decode() == "USERNAME":
        pass  # GUI handles username input via popup
    ChatApp().run()
