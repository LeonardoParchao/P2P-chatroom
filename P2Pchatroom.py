import socket
import threading
import os
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import random

class P2PChatroom:
    def __init__(self, master):
        self.master = master
        self.master.title("P2P Chatroom")
        self.create_widgets()

    def create_widgets(self):
        self.chat_history = scrolledtext.ScrolledText(self.master, width=50, height=20)
        self.chat_history.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(self.master, width=40)
        self.message_entry.pack(padx=10, pady=(0, 10))

        self.send_button = tk.Button(self.master, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=5)

        self.send_file_button = tk.Button(self.master, text="Send File", command=self.send_file)
        self.send_file_button.pack(padx=10, pady=5)

    def append_message(self, message):
        self.chat_history.insert(tk.END, message + "\n")
        self.chat_history.see(tk.END)

    def generate_keys(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def send_message(self):
        message = self.message_entry.get()
        if message:
            self.append_message("You: " + message)
            session_key = get_random_bytes(32)
            encrypted_message = self.encrypt_message(message.encode(), session_key)
            self.client_socket.send(encrypted_message)
            self.message_entry.delete(0, tk.END)

    def encrypt_message(self, message, session_key):
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(pad(message, AES.block_size))
        return ciphertext

    def decrypt_message(self, encrypted_message, session_key):
        cipher_aes = AES.new(session_key, AES.MODE_CBC)
        decrypted_message = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size)
        return decrypted_message.decode()

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            file_name = os.path.basename(file_path)
            with open(file_path, "rb") as file:
                file_data = file.read()
                session_key = get_random_bytes(32)
                encrypted_file_data = self.encrypt_message(file_data, session_key)
                self.client_socket.send(file_name.encode())
                self.client_socket.send(encrypted_file_data)
            self.append_message("You sent file: " + file_name)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(4096)
                if encrypted_message:
                    decrypted_message = self.decrypt_message(encrypted_message, self.session_key)
                    self.append_message("Peer: " + decrypted_message)
            except ConnectionAbortedError:
                break

    def receive_file(self):
        while True:
            try:
                file_name = self.client_socket.recv(1024).decode()
                if file_name:
                    encrypted_file_data = self.client_socket.recv(4096)
                    decrypted_file_data = self.decrypt_message(encrypted_file_data, self.session_key)
                    with open(file_name, "wb") as file:
                        file.write(decrypted_file_data)
                    self.append_message("Received file: " + file_name)
            except ConnectionAbortedError:
                break

    def start(self):
        self.generate_keys()

        host = input("Enter your IP address: ")
        port = int(input("Enter a port number to use: "))

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        self.client_socket.send(self.public_key.export_key())

        peer_public_key = RSA.import_key(self.client_socket.recv(4096))
        session_key = get_random_bytes(32)
        encrypted_session_key = PKCS1_OAEP.new(peer_public_key).encrypt(session_key)
        self.client_socket.send(encrypted_session_key)

        self.session_key = scrypt(session_key, self.client_socket.recv(16), 32, N=2**14, r=8, p=1)
        threading.Thread(target=self.receive_messages).start()
        threading.Thread(target=self.receive_file).start()

root = tk.Tk()
chatroom = P2PChatroom(root)
chatroom.start()
root.mainloop()
