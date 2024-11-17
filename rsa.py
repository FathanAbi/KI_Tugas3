from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

# Encrypt the message using the public key
# def encrypt_message(message, public_key):
#     ciphertext = public_key.encrypt(
#         message.encode(),
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return base64.b64encode(ciphertext).decode()
# Function to encrypt data with a public key
def sign_with_private_key(private_key, data):
    signature = private_key.sign(
        data,  # Data to encrypt (must be bytes)
        padding.PSS(  # RSA padding scheme
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()  # Hashing algorithm used in PSS
    )
    return signature

# Function to decrypt the encrypted server public key using PKA's public key
def verify_with_public_key(public_key, signature, data):
    try:
        # Verify the signature using the public key
        public_key.verify(
            signature,  # The signature to verify
            data,       # The original data that was signed (must be bytes)
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()  # Hashing algorithm used in PSS
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature verification failed:", str(e))

# Encrypt the message using the public key
def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

# Decrypt the message using the private key
def decrypt_message(ciphertext, private_key):
    ciphertext = base64.b64decode(ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext



# Load the private key from a file
def load_private_key(file_path, password=None):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode() if password else None
        )
    return private_key

# Load the public key from a file
def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

if __name__ == "__main__":
    public_key_server = load_public_key("pu_server.pem")
    private_key_pka = load_private_key("pr_pka.pem")
    public_key_pka = load_public_key("pu_pka.pem")

    public_key_server_bytes = public_key_server.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Step 3: Encrypt a message
    message = "Hello, this is a secret message!aaaa"
    signature = sign_with_private_key(private_key_pka, public_key_server_bytes)
    print(f"signature: {signature}")

    # Step 4: Decrypt the message
    verfiy_server_public_key = verify_with_public_key(public_key_pka, signature, public_key_server_bytes)

    