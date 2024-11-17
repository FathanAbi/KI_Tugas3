import socket
import client_server_utility as csu
import time
import pickle
from host_list import hosts, get_host_id
from key_management import load_private_key, load_public_key
from cryptography.hazmat.primitives import serialization
from rsa import verify_with_public_key, encrypt_message

def getPublicKey(server_id, timestamp, public_key_pka):
    req = {
        "server_id" : server_id,
        "timestamp" : timestamp,
    }

    data = pickle.dumps(req)

    host = '127.0.0.1'
    port = 1235

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    client_socket.send(data)

    print("sending request to pka...")

    request = client_socket.recv(1024)
    received_dict = pickle.loads(request)
    print("Received dictionary:", received_dict)

    public_key = received_dict["public_key"]
    signature = received_dict["signature"]

    verify_with_public_key(public_key_pka, signature, public_key)

    client_socket.close()

    public_key = serialization.load_pem_public_key(public_key)

    return public_key

def initateConnection(public_key_server):
    """Connect to the server and start exchanging messages."""
    host = '127.0.0.1'
    port = 1234
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    req = {
        "id" : 1,
        "n1" : 1000,
    }

    serialized_data = pickle.dumps(req)
    encrypted_data = encrypt_message(serialized_data, public_key_server)

    client_socket.send(encrypted_data.encode())

    print("sending request to server...")

    client_socket.close()


def client_program():
    pu_client = load_public_key("pu_client.pem")
    pr_client = load_private_key("pr_client.pem")
    pu_pka = load_public_key("pu_pka.pem")
    # get public key server from pka
    current_unix_timestamp = int(time.time())
    pu_server = getPublicKey(get_host_id("server"), current_unix_timestamp, pu_pka)

    # initiate connection
    initateConnection(pu_server)

    return
    # send DES key
    # sendDESKey()

    # connection established

    try:
        while True:
            csu.handle_to_another_connection(client_socket)
            csu.handle_from_other_connection(client_socket)

    except KeyboardInterrupt:
        print("Client disconnecting.")
    finally:
        client_socket.close()

if __name__ == '__main__':
    client_program()
