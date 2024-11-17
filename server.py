import socket
import client_server_utility as csu
from rsa import decrypt_message
import pickle
from key_management import load_private_key, load_public_key

def start_server():
    pu_server = load_public_key("pu_server.pem")
    pr_server = load_private_key("pr_server.pem")
    """Start the server and listen for incoming connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 1234
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server Listening on {host}:{port} ...")

    # receive request connection from client (initiate)
    client_socket, addr = server_socket.accept()
    print(f"Got a connection from {addr}")

    encrypted = client_socket.recv(1024).decode()

    print(encrypted)

    decrypted = decrypt_message(encrypted, pr_server)

    received_dict = pickle.loads(decrypted)

    print("recieved dict", received_dict)
    

    # get public key 
    # client_public_key = getPublicKey(client_id)

    # continue intiate connection


    # receive DES key

    # connection established

    try:
        client_socket, addr = server_socket.accept()
        print(f"Got a connection from {addr}")

        while True:
            csu.handle_from_other_connection(client_socket)
            csu.handle_to_another_connection(client_socket)

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
