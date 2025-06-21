# input the message and the private key of RSA 

# input the second level of AES print out the private keys for teh user to store
# and take em in and decrypt them 

import rsa
import hashlib
import random
import math
from cryptography.fernet import Fernet 
from aes import aes

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def decrypt(rsa_encrypted_message, privkey, aes_key):
    
    rsa_decrypted_message = rsa.decrypt(rsa_encrypted_message, privkey)
    print("Outer layer (RSA) decrypted.")

    aes_decryptor = aes_cipher.decryptor()
    decrypted_padded_message = aes_decryptor.update(rsa_decrypted_message) + aes_decryptor.finalize()

    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
    print("Inner layer (AES) decrypted.")

    print("Decrypted message:", decrypted_message)
