

import rsa
import hashlib
import random
import math
from cryptography.fernet import Fernet 
from aes import aes


import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend





def rsa_example():
    (pubkey, privkey) = rsa.newkeys(2048, poolsize=15)
    l = input("Enter Your message: ")
    message = l.encode('utf8')
    print("Encoded Message:", message)
    crypto = rsa.encrypt(message, pubkey)
    print("Encrypted Message:", crypto)
    print("----------------------------------------------------------------------------------------------------\n")
    
    msg = 'hello this is a test message'.encode()
    hash_value = rsa.compute_hash(msg, 'SHA-512')
    signature = rsa.sign(msg, privkey, 'SHA-512')
    print("Signature:", signature)
    
    try:
        rsa.verify(msg, signature, pubkey)
        print("Signature is valid.")
    except rsa.VerificationError:
        print("Signature is invalid.")
    
    output = rsa.decrypt(crypto, privkey)
    print("Decrypted Message:", output.decode('utf8'))


def aes():
    
	print("AES")
	print("----------------------------------------------------------------------------------------------------\n")
	key = os.urandom(32)
	print("Generated AES key:", key.hex())

	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

	message = input("Enter the message to encrypt by aes: ").encode('utf-8')
	print("Original message:", message.decode('utf-8'))

	# Pad the message to be a multiple of 16 bytes (AES block size)
	def pad(data):
		padding_length = 16 - (len(data) % 16)
		return data + bytes([padding_length] * padding_length)

	padded_message = pad(message)
	print("Padded message length:", len(padded_message), "bytes")

	# Encrypt the message
	encryptor = cipher.encryptor()
	encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
	print("Encrypted message:", encrypted_message.hex())

	# Decrypt the message
	decryptor = cipher.decryptor()
	decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

	def unpad(data):
		padding_length = data[-1]
		return data[:-padding_length]

	decrypted_message = unpad(decrypted_padded_message)
	print("Decrypted message:", decrypted_message.decode('utf-8'))

	print("\nExplanation:")
	print("1. We use the cryptography library for AES encryption.")
	print("2. A random 256-bit key is generated for AES-256 encryption.")
	print("3. We create an AES cipher in ECB (Electronic Codebook) mode.")
	print("4. The user's message is encoded to bytes and padded to fit AES block size.")
	print("5. The padded message is encrypted using the AES cipher.")
	print("6. For decryption, we use the same key and cipher to decrypt and unpad.")
	print("Note: ECB mode is used for simplicity, but it's not recommended for secure applications.")
	print("For better security, consider using modes like CBC or GCM with proper IV/nonce handling.")

def hybrid_encryption():
    print("Hybrid Encryption (RSA + AES)")
    print("----------------------------------------------------------------------------------------------------\n")

    # RSA key generation
    (pubkey, privkey) = rsa.newkeys(2048, poolsize=15)
    print("RSA keys generated.")

    # Get user input
    message = input("Enter your message for hybrid encryption: ")
    print("Original message:", message)

    # RSA encryption of AES key
    aes_key = os.urandom(32)
    encrypted_aes_key = rsa.encrypt(aes_key, pubkey)
    print("AES key encrypted with RSA.")

    # AES encryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)

    # Pad the message
    def pad(data):
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    padded_message = pad(message.encode('utf-8'))

    # Encrypt the message with AES
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    print("Message encrypted with AES.")

    print("\nEncrypted Data:")
    print("RSA-encrypted AES key:", encrypted_aes_key.hex())
    print("AES-encrypted message:", encrypted_message.hex())

    # Decryption process
    print("\nDecryption Process:")

    # Decrypt the AES key using RSA
    decrypted_aes_key = rsa.decrypt(encrypted_aes_key, privkey)
    print("AES key decrypted with RSA.")

    # Decrypt the message using AES
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Unpad the message
    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
    print("Message decrypted with AES.")

    print("Decrypted message:", decrypted_message)

    print("\nExplanation:")
    print("1. RSA is used to securely encrypt the AES key.")
    print("2. The message is encrypted using AES with the generated key.")
    print("3. For decryption, the AES key is first decrypted using RSA private key.")
    print("4. Then, the message is decrypted using the recovered AES key.")
    print("Note: This example uses ECB mode for simplicity. In practice, use more secure modes like CBC or GCM.")



def main():
    print("Welcome to the AES Encryption Demo")
    print("==================================")
    while True:
        choice = input("\nChoose an option:\n1. Run AES encryption/decryption\n2. Exit\nYour choice (1/2): ")
        
        if choice == '1':
            hybrid_encryption()
            aes()
        elif choice == '2':
            print("Thank you for using the AES Encryption Demo. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()

