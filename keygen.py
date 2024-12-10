from sympy import isprime, nextprime
import random
from math import gcd

def modular_inverse(e, phi):
    for x in range(1, phi):
        if (e * x) % phi == 1:
            return x
    return None

# Function to generate RSA keys
def generate_keys():
    # Step 1: Choose two distinct prime numbers, p and q
    p = nextprime(random.randint(50, 100))
    q = nextprime(random.randint(50, 100))
    
    # Step 2: Compute n = p * q and φ(n) = (p-1)*(q-1)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Step 3: Find an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = 3
    while gcd(e, phi) != 1:
        e = nextprime(e)
    
    # Step 4: Determine d such that d * e ≡ 1 (mod φ(n))
    d = modular_inverse(e, phi)
    
    # Public and private keys
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

print(generate_keys())