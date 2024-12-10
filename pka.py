import socket
import pickle
import time
import client_server_utility as csu
from rsa import encrypt

def start_server():
    pu_pka = (5, 5293),
    pr_pka = (3089, 5293)
    pu_client = (5, 8633)
    pu_server = (5, 7663)

    public_keys = {
        1 : pu_client,
        2 : pu_server,
    }

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 1235
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"PKA Listening on {host}:{port} ...")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Got a connection from {addr}")

            request = client_socket.recv(1024)
            received_dict = pickle.loads(request)
            print("Received dictionary:", received_dict)

            id = received_dict["server_id"]
            public_key = public_keys[id]

            public_key_to_be_encrypted_as_string = f"{public_key[0]},{public_key[1]}"
            message = public_key_to_be_encrypted_as_string

            encrypted = encrypt(message, pr_pka)

            # public_key_server_bytes = public_key.public_bytes(
            #     encoding=serialization.Encoding.PEM,
            #     format=serialization.PublicFormat.SubjectPublicKeyInfo
            # )

            # signature = sign_with_private_key(pr_pka, public_key_server_bytes)

            res = {
                "public_key" : encrypted,
                "timestamp" : int(time.time()),
            }

            data = pickle.dumps(res)

            # send public key server and client (step 2 and 5)
            client_socket.send(data)
            print(f'sending public key id {id}....')

            client_socket.close()

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
