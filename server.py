import socket
import client_server_utility as csu
import time
import pickle
from host_list import get_host_id
from key_management import load_private_key, load_public_key
from rsa import encrypt, decrypt

client_port, server_port = 1233, 1234

def start_server():
    pu_server = (5, 7663)
    pr_server = (4493, 7663)
    pu_pka = (5, 5293)

    # Start the server to listen for incoming connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', server_port))
        server_socket.listen(1)
        print(f"Server listening on 127.0.0.1:{server_port} ...")

        # Handle initial client connection
        client_socket, addr = server_socket.accept()
        with client_socket:
            print(f"Got a connection from {addr}")
            decrypted = decrypt(client_socket.recv(1024).decode(), pr_server)
            received_dict = pickle.loads(decrypted)
            print("Received dict:", received_dict)

            # request public key client (step 4)
            print("sending request for public key client...")
            pu_client = csu.get_public_key(get_host_id("client"), int(time.time()), pu_pka)
            
            true_n2 = 2000

            # Respond to client challenge (step 6)
            print("send respond back to client....")
            csu.initiate_connection('127.0.0.1', client_port, {"n1": received_dict["n1"], "n2": true_n2}, pu_client)
            

            # Handle further connections
        client_socket, addr = server_socket.accept()
        with client_socket:
            decrypted = decrypt(client_socket.recv(1024).decode(), pr_server)
            received_dict = pickle.loads(decrypted)
            print("Received dict:", received_dict)

            if received_dict["n2"] != true_n2:
                print("Error: Invalid n2 received.")
                return
            
            print("n2 valid. conection established")
            
        client_socket, addr = server_socket.accept()
        with client_socket:
            decrypted = decrypt(client_socket.recv(1024).decode(), pr_server)
            received_dict = pickle.loads(decrypted)
            print("Handshake Step 3 - Received dict:", received_dict)
            secret_key = received_dict.get("secret_key")
            if not secret_key or len(secret_key) != 8:
                print("Error: Invalid secret key received.")
                return
            print("secret key received successfully. ready to receive message")
            return secret_key

def server_program(secret_key):
    """Connect to the server and start exchanging messages."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', client_port))

    try:
        while True:
            csu.handle_to_another_connection(client_socket,secret_key)
            csu.handle_from_other_connection(client_socket,secret_key)

    except KeyboardInterrupt:
        print("Client disconnecting.")
    finally:
        client_socket.close()



if __name__ == '__main__':
    server_program(start_server())