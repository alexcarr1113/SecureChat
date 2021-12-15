import sqlite3
import socket
import time
import pickle
import yaml
import os
import hashlib
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def read_yaml(filepath):
    with open(filepath, "r") as config:
        return yaml.safe_load(config)

db = sqlite3.connect("accounts.db")
cursor = db.cursor()

# Load values from config file

config = read_yaml("config.yaml")

server_address = config["server-address"]
server_port = int(config["server-port"])

# Create server socket and listen on given address

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_address, server_port))
server_socket.listen()
print("Listening on", server_address+":"+str(server_port))


def main():

    running = True

    while running:
        connection_socket, client_address = server_socket.accept()
        print("Incoming connection from", client_address[0])
        data = connection_socket.recv(1024)
        message = pickle.loads(data)
        if "CMD" in message:
            handle_cmd(connection_socket, message["CMD"])

    connection_socket.close()
    server_socket.close()


def handle_cmd(connection_socket, cmd):  # Handle commands sent from client
    if cmd == "CRT":  # CRT signals account creation
        print("Creating account")
        create_account(connection_socket)
    if cmd == "RCV": # RCV signals message retrieval
        print("Receiving messages")
        retrieve_messages((connection_socket))

def retrieve_messages(connection_socket):
    data = connection_socket.recv(1024)
    message = pickle.loads(data)
    username = message["username"]
    password = message["password"]
    print(check_hash(username, password))


def create_account(connection_socket):
    username = ""
    hash = ""
    message = {
        "status": 200
    }
    data = pickle.dumps(message)
    connection_socket.send(data)
    while username == "":
        data = pickle.loads(connection_socket.recv(1024))
        if "username" in data and "hash" in data and "pub" in data:
            checkUsername = cursor.execute("SELECT * FROM accounts WHERE username = ?", (data["username"],)).fetchall()
            if len(checkUsername) > 0:
                # User already exists
                message = {
                    "status": 400,
                    "message": "User already exists"
                }
                data = pickle.dumps(message)
                connection_socket.send(data)
            else:
                username = data["username"]
                hash = data["hash"]
                public_key = data["pub"]
                cursor.execute("INSERT INTO accounts (username, password, public_key) VALUES (?, ?, ?)", (username, hash, public_key))
                db.commit()
                message = {
                    "status": 200,
                }
                data = pickle.dumps(message)
                connection_socket.send(data)


def check_hash(username, password):
    correct_key = cursor.execute(
        "SELECT password FROM accounts WHERE username = ?", (username,)).fetchall()[0][0]
    salt = correct_key[:32]  # salt is last 32 bytes
    correct_key = correct_key[32:]  # key is first 32 bytes
    key = hashlib.pbkdf2_hmac(
        'sha-256',
        password.encode('utf-8'),
        salt,
        100000
    )
    if key == correct_key:
        return True
    else:
        return False

main()


# NEED TO SETUP CONNECTION SO THAT CLIENT CAN CREATE ACCOUNT AND GENERATE
# HASHES / KEYS LOCALLY THEN ONLY SEND PUBLIC KEY AND HASHED PASSWORD OVER
# TCP TO SERVER
