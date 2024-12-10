def encrypt(message, public_key):
    e, n = public_key
    ciphertext = [(pow(ord(char), e, n)) for char in message]
    ciphertext_string = ','.join(map(str, ciphertext))

    return ciphertext_string

# Function to decrypt a message
def decrypt(ciphertext, private_key):
    d, n = private_key
    ciphertext_list = list(map(int, ciphertext.split(',')))
    message = ''.join([chr(pow(char, d, n)) for char in ciphertext_list])

    return message


if __name__ == '__main__':
    public_key_to_be_encrypted = (5, 8633)
    public_key_to_be_encrypted_as_string = f"{public_key_to_be_encrypted[0]},{public_key_to_be_encrypted[1]}"
    message = public_key_to_be_encrypted_as_string

    print(message)

    public_key = (5, 5293)
    encrypted = encrypt(message, public_key)
    print(encrypted)

    encrypted = encrypted.encode()
    print(encrypted)

    private_key = (3089, 5293)
    encrypted = encrypted.decode()
    decrypted = decrypt(encrypted, private_key)
    print(decrypted)

    public_key_restored = tuple(map(int, decrypted.split(',')))
    print("Restored Public Key as Tuple:", public_key_restored)

    # ## test
    message = "HELLLOOO"
    encrypted2 = encrypt(message, public_key_restored)
    print(encrypted2)

    encrypted2 = encrypted2.encode()
    print(encrypted2)


    private_key = (5069, 8633)
    encrypted2 = encrypted2.decode()
    decrypted2 = decrypt(encrypted2, private_key)

    print(decrypted2)

    # ## reverse
    message1 = "encrypt using private_key"

    public_key = (5, 7663)
    private_key = (4493, 7663)

    encrypted3 = encrypt(message1, private_key)
    print(encrypted3)
   
    encrypted3 = encrypted3.encode()
    print(encrypted3)


    received_ecnrypted = encrypted3.decode()
    print(received_ecnrypted)

    decrypted3 = decrypt(received_ecnrypted, public_key)
    print(decrypted3)