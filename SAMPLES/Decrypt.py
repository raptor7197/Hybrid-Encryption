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
    backend = default_backend()
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)
    rsa_encrypted_message = input("Enter the RSA-encrypted message (hex): ")
    privkey = input("Enter your private key for decryption: ")
    aes_key = input("Enter your AES key for decryption (hex): ")
    rsa_encrypted_message = bytes.fromhex(rsa_encrypted_message)
    privkey = bytes.fromhex(privkey)
    aes_key = bytes.fromhex(aes_key)
    print("Decryption Process:")
    print("AES Key:", aes_key.hex())
    print("Private Key:", privkey.hex())
    print("Original message:", privkey)
    
    # AES encryption

    # Pad the message
    # def pad(data):
    #     padding_length = 16 - (len(data) % 16)
    #     return data + bytes([padding_length] * padding_length)

    # padded_message = pad(message.encode('utf-8'))

    # aes_encryptor = aes_cipher.encryptor()
    # aes_encrypted_message = aes_encryptor.update(padded_message) + aes_encryptor.finalize()
    # print("Message encrypted with AES.")
    # rsa_encrypted_message = rsa.encrypt(aes_encrypted_message, pubkey)
    # print("AES-encrypted message further encrypted with RSA.")
    # print("Double-encrypted message:", rsa_encrypted_message.hex())
    print("\nDecryption Process:")

    # First decryption: RSA
    rsa_decrypted_message = rsa.decrypt(rsa_encrypted_message, privkey)
    print("Outer layer (RSA) decrypted.")

    # Second decryption: AES
    aes_decryptor = aes_cipher.decryptor()
    decrypted_padded_message = aes_decryptor.update(rsa_decrypted_message) + aes_decryptor.finalize()

    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
    print("Inner layer (AES) decrypted.")

    print("Decrypted message:", decrypted_message)
    return decrypted_message

def main():
    rsa_encrypted_message = input("Enter the RSA-encrypted message (hex): ")
    privkey = input("Enter your private key for decryption: ")
    aes_key = input("Enter your AES key for decryption (hex): ")

            # decrypt(rsa_encrypted_message, privkey, aes_key)
    decrypted_message = decrypt(rsa_encrypted_message, privkey, bytes.fromhex(aes_key))
    print("Decrypted message:", decrypted_message)


if __name__ == "__main__":
    main()