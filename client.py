import socket
import client_server_utility as csu
import time
import pickle
from host_list import get_host_id
from key_management import load_private_key, load_public_key
from rsa import decrypt_message


server_id, client_port, server_port = get_host_id("server"), 1233, 1234

def client_program():
    pu_client = load_public_key("pu_client.pem")
    pr_client = load_private_key("pr_client.pem")
    pu_pka = load_public_key("pu_pka.pem")
    

    # Start the server to listen for incoming connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', client_port))
        server_socket.listen(1)
        print(f"Client listening on 127.0.0.1:{client_port} ...")

        # Get server's public key from PKA
        pu_server = csu.get_public_key(server_id, int(time.time()), pu_pka)
        true_n1 = 1000

        # Initiate first connection
        csu.initiate_connection('127.0.0.1', server_port, {"id": 1, "n1": true_n1}, pu_server)

        # Handle response from server
        client_socket, addr = server_socket.accept()
        with client_socket:
            print(f"Got a connection from {addr}")
            decrypted = decrypt_message(client_socket.recv(1024).decode(), pr_client)
            received_dict = pickle.loads(decrypted)
            print("Received dict:", received_dict)

            if received_dict["n1"] != true_n1:
                return

            # Respond to server challenge
            csu.initiate_connection('127.0.0.1', server_port, {"n2": received_dict["n2"]}, pu_server)

            # Send secret key
            secret_key = ""
            while len(secret_key) != 8:
                secret_key = input("> Enter secret key (8 characters): ")
            csu.initiate_connection('127.0.0.1', server_port, {"secret_key": secret_key}, pu_server)
            return secret_key

def start_client(secret_key):
    """Start the server and listen for incoming connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', client_port))
    server_socket.listen(1)
    print(f"Client listening on 127.0.0.1:{client_port} ...")

    try:
        client_socket, addr = server_socket.accept()
        print(f"Got a connection from {addr}")

        while True:
            csu.handle_from_other_connection(client_socket, secret_key)
            csu.handle_to_another_connection(client_socket, secret_key)

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_client(client_program())
