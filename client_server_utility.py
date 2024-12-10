import des
import socket
import pickle
from rsa import encrypt, decrypt
import ast

# padding dan unpadding mengguankan PKCS7
def pad(string, block_size):
  padding_number = block_size - len(string) % block_size
  if padding_number == block_size:
    return string
  padding = chr(padding_number) * padding_number
  return string + padding

def unpad(string, block_size):
  if not string: return string
  if len(string) % block_size:
    raise TypeError('string is not a multiple of the block size.')
  padding_number = ord(string[-1])
  if padding_number >= block_size:
    return string
  else:
    if all( padding_number == ord(c) for c in string[-padding_number:] ):
      return string[0:-padding_number]
    else:
      return string


def handle_to_another_connection(client_socket, secret_key):
    """Send encrypted data to the other device."""
    text = input("> Masukkan text: ")
    text = pad(text, 8)
    key = secret_key
    while len(key) != 8:
        print("> Panjang secret key tidak valid. Silakan masukkan 8 karakter.")
        key = input("> Masukkan secret key (8 karakter): ")

    print("\n--- Mode Enkripsi ---")
    print("> 1. Electronic Code Book (ECB)")
    print("> 2. Cipher Block Chaining (CBC)")
    print("> 3. Cipher FeedBack (CFB)")
    print("> 4. Output FeedBack (OFB)")
    encryption_mode = int(input(">> Pilih opsi enkripsi(1/2/3/4): "))

    if encryption_mode == 1:
        cipher_text = des.ecb_process(text, key, mode="encrypt")
        message = des.bin_to_hex(cipher_text)
        print(f">> ECB >> Teks Cipher (hex): {message}")
        client_socket.send(message.encode())
    elif encryption_mode == 2:
        iv = input(">> Masukkan initial vector (8 karakter): ")
        while len(iv) != 8:
            print(">> Panjang initial vector tidak valid. Silakan masukkan 8 karakter.")
            iv = input(">> Masukkan initial vector (8 karakter): ")

        cipher_text = des.cbc_process(text, key, iv, mode="encrypt")
        message = iv+des.bin_to_hex(cipher_text)
        print(f">> CBC >> Teks Cipher (hex): {message}")
        client_socket.send(message.encode())
    elif encryption_mode == 3:
        iv = input(">> Masukkan initial vector (8 karakter): ")
        while len(iv) != 8:
            print(">> Panjang initial vector tidak valid. Silakan masukkan 8 karakter.")
            iv = input(">> Masukkan initial vector (8 karakter): ")

        cipher_text = des.cfb_process(text, key, iv, mode="encrypt")
        message = iv+des.bin_to_hex(cipher_text)
        print(f">> CFB >> Teks Cipher (hex): {message}")
        client_socket.send(message.encode())
    elif encryption_mode == 4:
        iv = input(">> Masukkan initial vector (8 karakter): ")
        while len(iv) != 8:
            print(">> Panjang initial vector tidak valid. Silakan masukkan 8 karakter.")
            iv = input(">> Masukkan initial vector (8 karakter): ")

        cipher_text = des.ofb_process(text, key, iv, mode="encrypt")
        message = iv+des.bin_to_hex(cipher_text)
        print(f">> OFB >> Teks Cipher (hex): {message}")
        client_socket.send(message.encode())
    else:
        print("> Opsi tidak valid, silakan coba lagi.")

def handle_from_other_connection(client_socket, secret_key):
    """Receive encrypted data from the other device."""
    message = client_socket.recv(1024)
    if not message:
        return
    text = message.decode()
    print(f"> Received from other device: {text}")

    key = secret_key
    while len(key) != 8:
        print("> Panjang secretkey tidak valid. Silakan masukkan 8 karakter.")
        key = input("> Masukkan secret key (8 karakter): ")

    print("\n--- Mode Dekripsi ---")
    print("> 1. Electronic Code Book (ECB)")
    print("> 2. Cipher Block Chaining (CBC)")
    print("> 3. Cipher FeedBack (CFB)")
    print("> 4. Output FeedBack (OFB)")
    decryption_mode = int(input(">> Pilih opsi dekripsi(1/2/3/4): "))

    if decryption_mode == 1:
        decrypted_text = des.ecb_process(text, key, mode="decrypt")
        print(f">> ECB >> Teks Terdekripsi: {unpad(des.bin_to_text(decrypted_text), 8)}")
    elif decryption_mode == 2:
        
        decrypted_text = des.cbc_process(text[8:], key, text[:8], mode="decrypt")
        print(f">> CBC >> Teks Terdekripsi: {unpad(des.bin_to_text(decrypted_text), 8)}")
    elif decryption_mode == 3:

        decrypted_text = des.cfb_process(text[8:], key, text[:8], mode="decrypt")
        print(f">> CFB >> Teks Terdekripsi: {unpad(des.bin_to_text(decrypted_text), 8)}")
      
    elif decryption_mode == 4:

        decrypted_text = des.ofb_process(text[8:], key, text[:8], mode="decrypt")
        print(f">> OFB >> Teks Terdekripsi: {unpad(des.bin_to_text(decrypted_text), 8)}")
    else:
        print("> Opsi tidak valid, silakan coba lagi.")

def send_request(host, port, data):
    """Utility to send a request to a server and receive a response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        client_socket.send(pickle.dumps(data))
        response = client_socket.recv(1024).decode()
        return response


def get_public_key(client_id, timestamp, public_key_pka):
    """Fetch a public key from the Public Key Authority (PKA)."""
    response = send_request('127.0.0.1', 1235, {"server_id": client_id, "timestamp": timestamp})
    print("Received response:", response)

    decrypted = decrypt(response, public_key_pka)
    print(f"decrypted response: {decrypted}")

    response = ast.literal_eval(decrypted)
    public_key, timestamp = response["public_key"], response["timestamp"]
    
    print(f"get public key {public_key}")
    return public_key


def initiate_connection(host, port, req, public_key):
    """Establish a connection and send an encrypted request."""
    req = str(req)
    encrypted_data = encrypt(req, public_key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        client_socket.send(encrypted_data.encode())
    print(f"Sent request to {host}:{port}.")

def get_socket_only(host, port):
    """Establish a connection"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
    print(f"Sent request to {host}:{port}.")
    return client_socket


