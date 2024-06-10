import socket
import select
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA keys for the server
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()


class Client:
    # Constructor
    def __init__(self, name, socket, public_key):
        self.name = name
        self.socket = socket
        self.public_key = public_key


def load_client_public_key(client_key_data):
    return serialization.load_pem_public_key(client_key_data)


# get a message and send the encrypted message to every client
def broadcast_data(sender_name, message, clients):
    for client in clients:
        try:
            encrypted_message = client.public_key.encrypt(
                f"{sender_name}: {message}".encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            client.socket.send(encrypted_message)
        except Exception as e:
            print(f"Error sending message to {client.name}: {e}")
            client.socket.close()
            clients.remove(client)


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9999))
    server.listen(10)

    input_sockets = [server]
    clients = []

    print("Server started and listening on port 9999")

    while True:
        read_sockets, _, _ = select.select(input_sockets, [], [])

        for sock in read_sockets:
            if sock == server:
                # create new client
                client_socket, addr = server.accept()
                input_sockets.append(client_socket)
                print(f"Connection from {addr}")

                # Send server's public key to the client
                client_socket.send(
                    server_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )

                # Receive client's public key
                client_key_data = client_socket.recv(1024)
                client_public_key = load_client_public_key(client_key_data)

                # Receive client's name
                client_name = client_socket.recv(1024).decode()

                client = Client(client_name, client_socket, client_public_key)
                clients.append(client)

            else:
                # if socket sent message
                try:
                    data = sock.recv(4096)
                    if data:
                        decrypted_message = server_private_key.decrypt(
                            data,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        ).decode()
                        print(f"Received: {decrypted_message}")

                        sender_name = None
                        for client in clients:
                            if client.socket == sock:
                                sender_name = client.name
                                break

                        broadcast_data(sender_name, decrypted_message, clients)
                    else:
                        # if socket disconnected
                        sock.close()
                        input_sockets.remove(sock)
                        clients = [client for client in clients if client.socket != sock]
                except Exception as e:
                    print(f"Error: {e}")
                    continue


start_server()
