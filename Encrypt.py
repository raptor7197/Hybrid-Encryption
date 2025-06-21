import rsa
import hashlib
import random
import math
from cryptography.fernet import Fernet 
from aes import aes

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

print("Hybrid Encryption (RSA + AES) Double Dhamaka fr !!!")
print("This works by padding the message, encrypting it with AES, and then encrypting the AES key with RSA.")

def rsa_example():
    (pubkey, privkey) = rsa.newkeys(2048, poolsize=15)
    l = input("Enter Your message: ")
    message = l.encode('utf8')
    print("Encoded Message:", message)
    crypto = rsa.encrypt(message, pubkey)
    print("Encrypted Message:", crypto)
    print("----------------------------------------------------------------------------------------------------\n")

    with open('hybrid_decryption.py', 'w') as f:
        f.write('''
import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def hybrid_decryption(crypto, privkey, aes_key):
    # First decryption: RSA
    rsa_decrypted_message = rsa.decrypt(crypto, privkey)
    print("Outer layer (RSA) decrypted.")

    # Second decryption: AES
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(rsa_decrypted_message) + decryptor.finalize()

    # Unpad the message
    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
    print("Inner layer (AES) decrypted.")

    return decrypted_message

# Example usage:
# decrypted_message = hybrid_decryption(crypto, privkey, aes_key)
# print("Decrypted message:", decrypted_message)
''')
    print("Decryption process has been written to 'hybrid_decryption.py'")
    
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

	message = input("Enter the message to encrypt by AES: ").encode('utf-8')
	print("Original message:", message.decode('utf-8'))

	# Pad the message to be a multiple of 16 bytes (AES block size)
	def pad(data):
		padding_length = 16 - (len(data) % 16)
		return data + bytes([padding_length] * padding_length)

	padded_message = pad(message)
	print("Padded message length:", len(padded_message), "bytes")

	encryptor = cipher.encryptor()
	encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
	print("Encrypted message:", encrypted_message.hex())

	decryptor = cipher.decryptor()
	decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

	def unpad(data):
		padding_length = data[-1]
		return data[:-padding_length]

	decrypted_message = unpad(decrypted_padded_message)
	print("Decrypted message:", decrypted_message.decode('utf-8'))

	
def hybrid_encryption():
    print("Double Encryption Process:")
    print("1. AES encryption")
    print("2. RSA encryption of the AES-encrypted message")
    print("\n")

    # RSA key generation
    (pubkey, privkey) = rsa.newkeys(2048, poolsize=15)
    print("RSA keys generated.")
    print("Public Key:", pubkey ,"\n")

    print("Private Key:", privkey)

    print("Keep the keys safe and if you forget theres no way to recoever the message ")
    aes_key = os.urandom(32)
    print("AES key generated.")
    print("AES Key (hex):", aes_key.hex())

    # Get user input
    message = input("Enter your message for double encryption: ")
    print("Original message:", message)

    # AES encryption
    backend = default_backend()
    aes_cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)

    # Pad the message
    def pad(data):
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    padded_message = pad(message.encode('utf-8'))

    aes_encryptor = aes_cipher.encryptor()
    aes_encrypted_message = aes_encryptor.update(padded_message) + aes_encryptor.finalize()
    print("Message encrypted with AES.")
    rsa_encrypted_message = rsa.encrypt(aes_encrypted_message, pubkey)
    print("AES-encrypted message further encrypted with RSA.")
    print("Double-encrypted message:", rsa_encrypted_message.hex())
    print("\nDecryption Process:")

    # First decryption: RSA
    rsa_decrypted_message = rsa.decrypt(rsa_encrypted_message, privkey)
    print("Outer layer (RSA) decrypted.")

    # Second decryption: AES
    aes_decryptor = aes_cipher.decryptor()
    decrypted_padded_message = aes_decryptor.update(rsa_decrypted_message) + aes_decryptor.finalize()

    # Unpad the message
    def unpad(data):
        padding_length = data[-1]
        return data[:-padding_length]

    decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
    print("Inner layer (AES) decrypted.")

    print("Decrypted message:", decrypted_message)

  


def main():
   
    while True:
        choice = input("\nChoose an option:\n1. Run Hybrid encryption/decryption\n2. Run AES encryption/decryption\n3. Run RSA example\n4. Exit\nYour choice (1/2/3/4): ")
        
        if choice == '1':
            hybrid_encryption()
        elif choice == '2':
            aes()
        elif choice == '3':
            rsa_example()
        elif choice == '4':
            print("Thank you for using the Service. Sayonara! Visit Again!!!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()

