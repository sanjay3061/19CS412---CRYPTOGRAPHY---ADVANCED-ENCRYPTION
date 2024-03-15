 ## IMPLEMENTATION OF RSA
 # AIM :
 To write a python program to implement the RSA encryption algorithm.

## ALGORITHM:
STEP-1: Select two co-prime numbers as p and q.

STEP-2: Compute n as the product of p and q.

STEP-3: Compute (p-1)*(q-1) and store it in z.

STEP-4: Select a random prime number e that is less than that of z.

STEP-5: Compute the private key, d as e *
mod-1
(z).

STEP-6: The cipher text is computed as messagee *

STEP-7: Decryption is done as cipherdmod n.

## PROGRAM:
```python
import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

# encryption

def encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

# decryption

def decrypt(private_key, ciphertext):
    d, n = private_key
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)

def main():
    p = 61
    q = 53
    public_key, private_key = generate_keypair(p, q)
    message = "Sanjay"
    encrypted_message = encrypt(public_key, message)
    decrypted_message = decrypt(private_key, encrypted_message)
    print("Original message:", message)
    print("Encrypted message:", encrypted_message)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()


```
## OUTPUT:
![image](https://github.com/sanjay3061/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/121215929/564d3ea8-8459-4eb1-90e8-d6144f1a7c15)


## RESULT :

Thus the python program to implement RSA encryption technique had been
implemented successfully





## IMPLEMENTATION OF DIFFIE HELLMAN KEY EXCHANGE ALGORITHM

## AIM:

To implement the Diffie-Hellman Key Exchange algorithm using python language.


## ALGORITHM:

STEP-1: Both Alice and Bob shares the same public keys g and p.

STEP-2: Alice selects a random public key a.

STEP-3: Alice computes his secret key A as g
a mod p.

STEP-4: Then Alice sends A to Bob.


STEP-5: Similarly Bob also selects a public key b and computes his secret
key as B and sends the same back to Alice.


STEP-6: Now both of them compute their common secret key as the other
one’s secret key power of a mod p.

## PROGRAM: 

```python
import random

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def get_prime_from_user():
    p = int(input("Enter a prime number (p): "))
    while not is_prime(p):
        print("The number you entered is not prime. Please enter a prime number.")
        p = int(input("Enter a prime number (p): "))
    return p

def main():
    # Get shared prime number and base from the user
    p = get_prime_from_user()
    g = int(input("Enter the base (g): "))

    # Get private keys from the user
    a = int(input("Enter Alice's private key (a): "))
    b = int(input("Enter Bob's private key (b): "))

    # Calculate public keys
    A = mod_exp(g, a, p)
    B = mod_exp(g, b, p)

    # Exchange public keys
    shared_secret_A = mod_exp(B, a, p)
    shared_secret_B = mod_exp(A, b, p)

    # Verify shared secrets match
    assert shared_secret_A == shared_secret_B

    print("Shared secret:", shared_secret_A)

if __name__ == "__main__":
    main()

```
## OUTPUT:

<![image](https://github.com/sanjay3061/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/121215929/14ba98c3-44fb-43b9-a827-8d222eee050f)


## RESULT: 

Thus the Diffie-Hellman key exchange algorithm had been successfully
implemented using python.





## IMPLEMENTATION OF DES ALGORITHM

## AIM:
To write a program to implement Data Encryption Standard (DES)

## ALGORITHM :

STEP-1: Read the 64-bit plain text.

STEP-2: Split it into two 32-bit blocks and store it in two different arrays.

STEP-3: Perform XOR operation between these two arrays.

STEP-4: The output obtained is stored as the second 32-bit sequence and the
original second 32-bit sequence forms the first part.

STEP-5: Thus the encrypted 64-bit cipher text is obtained in this way. Repeat the
same process for the remaining plain text characters.

### PROGRAM :

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def pad(text):
    padder = padding.PKCS7(64).padder()
    padded_text = padder.update(text)
    return padded_text + padder.finalize()


def unpad(text):
    unpadder = padding.PKCS7(64).unpadder()
    unpadded_text = unpadder.update(text)
    return unpadded_text + unpadder.finalize()

# key
key = b"abcdefgh"


cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())


plaintext = b"Sanjay"
print("plaintext: Sanjay")

padded_plaintext = pad(plaintext)

# encryption 

encryptor = cipher.encryptor()


ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

print("Encrypted Text:", ciphertext.hex())

# decryption 
decryptor = cipher.decryptor()


decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()


decrypted_plaintext = unpad(decrypted_padded_text)

print("Decrypted Text:", decrypted_plaintext.decode('utf-8'))


```
## OUTPUT:
![image](https://github.com/sanjay3061/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/121215929/a0b8bdbf-d93c-454b-8e3e-3b821aaace3f)


## RESULT:

Thus the data encryption standard algorithm had been implemented
successfully.

