from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Commonly used value
    key_size=2048  # Key size (2048 or higher is recommended)
)

# Save the private key to a file
with open("private_key.pem", "wb") as private_file:
    private_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Or use a password
        )
    )

# Generate public key from the private key
public_key = private_key.public_key()

# Save the public key to a file
with open("public_key.pem", "wb") as public_file:
    public_file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("RSA key pair generated and saved to 'private_key.pem' and 'public_key.pem'.")
