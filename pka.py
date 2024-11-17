import socket
import pickle
import time
from key_management import load_private_key, load_public_key
import client_server_utility as csu
from cryptography.hazmat.primitives import serialization
from rsa import sign_with_private_key

def start_server():
    pu_pka = load_public_key("pu_pka.pem")
    pr_pka = load_private_key("pr_pka.pem")
    pu_client = load_public_key("pu_client.pem")
    pu_server = load_public_key("pu_server.pem")

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

            public_key_server_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            signature = sign_with_private_key(pr_pka, public_key_server_bytes)

            res = {
                "public_key" : public_key_server_bytes,
                "signature" : signature,
                "timestamp" : int(time.time()),
            }

            data = pickle.dumps(res)


            client_socket.send(data)
            print("sending public key...")

            client_socket.close()

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()
