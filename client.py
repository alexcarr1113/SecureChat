import socket
import pickle
import hashlib
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from getpass import getpass

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 8081))


def main():
    create_account()

def create_account():
    successful = False
    while not successful:
        username = input("Username: ")
        password = getpass()
        private_pem, public_pem = generate_keys()
        hash = hash_password(password)
        print(hash)
        message = {
            "CMD": "CRT"
        }
        send(message)
        response = get_response()
        if response["status"] == 200:
            message = {
                "username": username,
                "hash": hash,
                "pub": public_pem
            }
            send(message)
            response = get_response()
            if response["status"] == 200:
                successful = True
                print("Account created")

def retrieve_messages(username, password):
    message = {
        "username": username,
        "password": password
    }

def send(message):
    data = pickle.dumps(message)
    client_socket.send(data)

def get_response():
    data = client_socket.recv(1024)
    response = pickle.loads(data)
    return response

def generate_keys():

    # Generate encryption keys

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialise keys into byte format

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',  # Hash algorithm for hmac
        password.encode('utf-8'),
        salt,  # Provide salt
        100000,  # 100000 iterations of SHA-256
    )
    return salt + key


main()
