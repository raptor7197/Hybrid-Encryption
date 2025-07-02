# import rsa
# import hashlib
# import random
# import math
# from cryptography.fernet import Fernet 
# from aes import aes

# import os
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend

# print("Hybrid Encryption (RSA + AES) Double Dhamaka fr !!!")
# print("This works by padding the message, encrypting it with AES, and then encrypting the AES key with RSA.")


# # aes then rsa
# def hybrid_encrypt(message, pubkey, aes_key):
#     print("Double Encryption Process:")
    
#     print("\n")
    
#     backend = default_backend()
#     aes_cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)
    
#     def pad(data):
#         padding_length = 16 - (len(data) % 16)
#         return data + bytes([padding_length] * padding_length)
    
#     padded_message = pad(message.encode('utf-8'))
    
#     aes_encryptor = aes_cipher.encryptor()
#     aes_encrypted_message = aes_encryptor.update(padded_message) + aes_encryptor.finalize()
#     print("Message encrypted with AES.")
    
#     rsa_encrypted_message = rsa.encrypt(aes_encrypted_message, pubkey)
#     print("AES-encrypted message further encrypted with RSA.")
#     print("Double-encrypted message:", rsa_encrypted_message.hex())
    
#     return rsa_encrypted_message


# def generate_rsa_keys():
#     return rsa.newkeys(2048, poolsize=15)

# def generate_aes_key():
#     return os.urandom(32)

# def sign_message(message, privkey):
#     msg = message.encode()
#     hash_value = rsa.compute_hash(msg, 'SHA-512')
#     signature = rsa.sign(msg, privkey, 'SHA-512')
#     print("Signature:", signature)
#     return signature

# def verify_signature(message, signature, pubkey):
#     msg = message.encode()
#     try:
#         rsa.verify(msg, signature, pubkey)
#         print("Signature is valid.")
#         return True
#     except rsa.VerificationError:
#         print("Signature is invalid.")
#         return False


# # def rsa_demo():
# #     print("RSA Demo")
# #     print("----------------------------------------------------------------------------------------------------\n")
    
# #     pubkey, privkey = generate_rsa_keys()
    
# #     message = input("Enter Your message: ")
# #     crypto = rsa_encrypt(message, pubkey)
    
# #     with open('hybrid_decryption.py', 'w') as f:
# #         f.write('''
# # import rsa
# # from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# # from cryptography.hazmat.backends import default_backend

# def hybrid_decryption(crypto, privkey, aes_key):
#     # First decryption: RSA
#     rsa_decrypted_message = rsa.decrypt(crypto, privkey)
#     print("Outer layer (RSA) decrypted.")

#     # Second decryption: AES
#     backend = default_backend()
#     cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)
#     decryptor = cipher.decryptor()
#     decrypted_padded_message = decryptor.update(rsa_decrypted_message) + decryptor.finalize()

#     # Unpad the message
#     def unpad(data):
#         padding_length = data[-1]
#         return data[:-padding_length]

#     decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
#     print("Inner layer (AES) decrypted.")

#     return decrypted_message

# # # Example usage:
# # # decrypted_message = hybrid_decryption(crypto, privkey, aes_key)
# # # print("Decrypted message:", decrypted_message)
# # ''')
# #     print("Decryption process has been written to 'hybrid_decryption.py'")
    
# #     # Sign and verify
# #     signature = sign_message('hello this is a test message', privkey)
# #     verify_signature('hello this is a test message', signature, pubkey)
    
# #     # Decrypt
# #     print("----------------------------------------------------------------------------------------------------\n")
# #     rsa_decrypt(crypto, privkey)

# # def aes_demo():
# #     """AES encryption/decryption demo"""
# #     print("AES Demo")
# #     print("----------------------------------------------------------------------------------------------------\n")
    
# #     # Generate key
# #     key = generate_aes_key()
# #     print("Generated AES key:", key.hex())
    
# #     # Get message and encrypt
# #     message = input("Enter the message to encrypt by AES: ")
# #     print("Original message:", message)
    
# #     encrypted_message = aes_encrypt(message, key)
    
# #     # Decrypt
# #     aes_decrypt(encrypted_message, key)

# def hybrid_demo():
#     """Hybrid encryption/decryption demo"""
#     print("Hybrid Encryption Demo")
#     print("----------------------------------------------------------------------------------------------------\n")
    
#     # Generate keys
#     pubkey, privkey = generate_rsa_keys()
#     print("RSA keys generated.")
#     print("Public Key:", pubkey ,"\n")
#     print("Private Key:", privkey.hex())
#     print("Keep the keys safe and if you forget theres no way to recover the message")
    
#     aes_key = generate_aes_key()
#     print("AES key generated.")
#     print("AES Key (hex):", aes_key.hex())
    
#     # Get message and encrypt
#     message = input("Enter your message for double encryption: ")
#     print("Original message:", message)
    
#     # Encrypt
#     encrypted_message = hybrid_encrypt(message, pubkey, aes_key)
    
#     # Decrypt
#     # hybrid_decrypt(encrypted_message, privkey, aes_key)

# def main():
#     while True:
#         choice = input("\nChoose an option:\n1. Run Hybrid encryption/decryption\n2. Run AES encryption/decryption\n3. Run RSA example\n4. Exit\nYour choice (1/2/3/4): ")
        
#         if choice == '1':
#             hybrid_demo()
#         # elif choice == '2':
#         #     aes_demo()
#         # elif choice == '3':
#         #     rsa_demo()
#         elif choice == '4':
#             print("Thank you for using the Service. Sayonara! Visit Again!!!")
#             break
#         else:
#             print("Invalid choice. Please enter 1, 2, 3, or 4.")

# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3

import rsa
import os
import pickle
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class HybridEncryption:
    def __init__(self):
        self.backend = default_backend()
    
    def generate_rsa_keys(self, key_size=2048):
        print("Generating RSA keys...")
        pubkey, privkey = rsa.newkeys(key_size, poolsize=8)
        print(f"RSA {key_size}-bit keys generated successfully!")
        return pubkey, privkey
    
    def generate_aes_key(self):
        return os.urandom(32)  # 256-bit key
    
    def save_keys(self, pubkey, privkey, key_dir="keys"):
        #  keys dir if it dont there
        os.makedirs(key_dir, exist_ok=True)
        
        #  RSA keys save
        with open(f"{key_dir}/public_key.pkl", 'wb') as f:
            pickle.dump(pubkey, f)
        
        with open(f"{key_dir}/private_key.pkl", 'wb') as f:
            pickle.dump(privkey, f)
        
        print(f"RSA keys saved in '{key_dir}/' directory")
        
    
    def pad_message(self, data):
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)
    
    def aes_encrypt(self, message, aes_key):
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # pad and encrypt
        padded_message = self.pad_message(message.encode('utf-8'))
        encrypted_data = encryptor.update(padded_message) + encryptor.finalize()
        
        return encrypted_data
    
    def rsa_encrypt(self, data, pubkey):
        return rsa.encrypt(data, pubkey)
    
    def hybrid_encrypt(self, message, pubkey):
        
        print("\n Hybrid encryption processsssssssssssssssssssssssss..... ;~)")
        
        aes_key = self.generate_aes_key()
        
        aes_encrypted_message = self.aes_encrypt(message, aes_key)
        
        rsa_encrypted_aes_key = self.rsa_encrypt(aes_key, pubkey)
                
        return aes_encrypted_message, rsa_encrypted_aes_key, aes_key
    
    def save_encrypted_data(self, aes_encrypted_message, rsa_encrypted_aes_key, filename="encrypted_data.json"):
        data = {
            "encrypted_message": aes_encrypted_message.hex(),
            "encrypted_aes_key": rsa_encrypted_aes_key.hex(),
            "encryption_method": "AES-256-ECB + RSA-2048",
            "timestamp": str(os.times())
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Encrypted data saved to: {filename}")

def main():
    print("HYBRID ENCRYPTION SYSTEM ")
    print("=" * 50)
    
    crypto = HybridEncryption()
    
    while True:
        print("\nChoose an option:")
        print("1. generate new  keys and encrypt ")
        print("2. use existing  keys to encrypt message") 
        print("3. AES-only encryption")
        print("4. RSA-only encryption")
        print("5. Exit")
        
        choice = input("\n choice (1-5): ").strip()
        
        if choice == '1':
            pubkey, privkey = crypto.generate_rsa_keys()
            crypto.save_keys(pubkey, privkey)
            
            message = input("\nEnter message to encrypt: ")
            
            aes_encrypted, rsa_encrypted_key, aes_key = crypto.hybrid_encrypt(message, pubkey)
            
            crypto.save_encrypted_data(aes_encrypted, rsa_encrypted_key)
            
            print(f"\n ENCRYPTION SUMMARY:")
            print(f"Original message: {message}")
            print(f"Message length: {len(message)} characters")
            print(f"AES encrypted message: {aes_encrypted.hex()[:50]}...")
            print(f"RSA encrypted AES key: {rsa_encrypted_key.hex()[:50]}...")
            print(f"AES key (keep secret!): {aes_key.hex()}")
            
        elif choice == '2':
            try:
                with open("keys/public_key.pkl", 'rb') as f:
                    pubkey = pickle.load(f)
                print("✓ Public key loaded successfully")
                
                message = input("\nEnter message to encrypt: ")
                
                aes_encrypted, rsa_encrypted_key, aes_key = crypto.hybrid_encrypt(message, pubkey)
                
                crypto.save_encrypted_data(aes_encrypted, rsa_encrypted_key)
                
                print(f"\n SUMMARY:")
                print(f"Original message: {message}")
                print(f"AES encrypted message: {aes_encrypted.hex()[:50]}...")
                print(f"RSA encrypted AES key: {rsa_encrypted_key.hex()[:50]}...")
                
            except FileNotFoundError:
                print(" key nahi hai gandu pehle bana (option 1)")
        
        elif choice == '3':
            message = input("\n message to encrypt with AES: ")
            aes_key = crypto.generate_aes_key()
            
            encrypted_data = crypto.aes_encrypt(message, aes_key)
            
            print(f"\n AES ENCRYPTION:")
            print(f"Original: {message}")
            print(f"AES Key: {aes_key.hex()}")
            print(f"Encrypted: {encrypted_data.hex()}")
            
            with open("aes_encrypted.json", 'w') as f:
                json.dump({
                    "encrypted_message": encrypted_data.hex(),
                    "aes_key": aes_key.hex()
                }, f, indent=4)
        
        elif choice == '4':
            pubkey, privkey = crypto.generate_rsa_keys()
            crypto.save_keys(pubkey, privkey)
            
            message = input("\n message to encrypt with RSA: ")
            
            try:
                encrypted_data = crypto.rsa_encrypt(message.encode('utf-8'), pubkey)
                
                print(f"\n RSA ENCRYPTION:")
                print(f"Original: {message}")
                print(f"Encrypted: {encrypted_data.hex()}")
                
                with open("rsa_encrypted.json", 'w') as f:
                    json.dump({
                        "encrypted_message": encrypted_data.hex()
                    }, f, indent=4)
                print("RSA encrypted data saved to: rsa_encrypted.json")
                
            except OverflowError:
                print(" message os too long chota kar ")
                print(" option ek aage se left ")
        
        elif choice == '5':
            
            print("koya to roya ")
            break
            
        else:
            print(" lawde number nahi aate kya ek se 5 ke beech me daal")

if __name__ == "__main__":
    main()