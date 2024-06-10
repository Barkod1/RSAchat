import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA keys for the client
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()


def load_server_public_key(server_key_data):
    return serialization.load_pem_public_key(server_key_data)


def handle_server_messages(client, client_private_key):
    while True:
        try:
            data = client.recv(4096)
            if data:
                message = client_private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
                print(f"\n{message}")
        except Exception as e:
            print(f"Error: {e}")
            break


def handle_user_input(client, server_public_key):
    while True:
        try:
            message = input()
            encrypted_message = server_public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client.send(encrypted_message)
        except Exception as e:
            print(f"Error: {e}")
            break


def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 9999))

    nickname = input("Enter your nickname: ")

    # Receive server's public key
    server_key_data = client.recv(4096)
    server_public_key = load_server_public_key(server_key_data)

    # Send client's public key to the server
    client.send(
        client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    # Send client's nickname to the server
    client.send(nickname.encode())

    # Start threads for handling server messages and user input
    threading.Thread(target=handle_server_messages, args=(client, client_private_key)).start()
    threading.Thread(target=handle_user_input, args=(client, server_public_key)).start()


start_client()
