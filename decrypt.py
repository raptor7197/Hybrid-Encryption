
# def hybrid_decrypt(rsa_encrypted_message, privkey, aes_key):
#     """Double decryption: RSA then AES"""
#     print("\nDecryption Process:")
    
#     backend = default_backend()
#     aes_cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=backend)
    
#     # First decryption: RSA
#     rsa_decrypted_message = rsa.decrypt(rsa_encrypted_message, privkey)
#     print("Outer layer (RSA) decrypted.")
    
#     # Second decryption: AES
#     aes_decryptor = aes_cipher.decryptor()
#     decrypted_padded_message = aes_decryptor.update(rsa_decrypted_message) + aes_decryptor.finalize()
    
#     # Unpad the message
#     def unpad(data):
#         padding_length = data[-1]
#         return data[:-padding_length]
    
#     decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
#     print("Inner layer (AES) decrypted.")
#     print("Decrypted message:", decrypted_message)
    
#     return decrypted_message



# def main():
#     rsa_encrypted_message = input("Enter the RSA-encrypted message (hex): ")
#     privkey = input("Enter your private key for decryption: ")
#     aes_key = input("Enter your AES key for decryption (hex): ")
    
#     # Convert inputs to bytes
#     rsa_encrypted_message = bytes.fromhex(rsa_encrypted_message)
#     privkey = bytes.fromhex(privkey)
#     aes_key = bytes.fromhex(aes_key)
    
#     decrypted_message = hybrid_decrypt(rsa_encrypted_message, privkey, aes_key)
#     print("Decrypted message:", decrypted_message)



# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
"""
Hybrid Decryption Module (RSA + AES)
This file handles decryption operations.
"""

import rsa
import os
import pickle
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class HybridDecryption:
    def __init__(self):
        self.backend = default_backend()
    
    def load_private_key(self, key_path="keys/private_key.pkl"):
        """Load RSA private key from file"""
        try:
            with open(key_path, 'rb') as f:
                privkey = pickle.load(f)
            print(f"✓ Private key loaded from: {key_path}")
            return privkey
        except FileNotFoundError:
            print(f"❌ Private key not found at: {key_path}")
            return None
        except Exception as e:
            print(f"❌ Error loading private key: {e}")
            return None
    
    def load_encrypted_data(self, filename="encrypted_data.json"):
        """Load encrypted data from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            encrypted_message = bytes.fromhex(data["encrypted_message"])
            encrypted_aes_key = bytes.fromhex(data["encrypted_aes_key"])
            
            print(f"✓ Encrypted data loaded from: {filename}")
            return encrypted_message, encrypted_aes_key
        except FileNotFoundError:
            print(f"❌ Encrypted data file not found: {filename}")
            return None, None
        except Exception as e:
            print(f"❌ Error loading encrypted data: {e}")
            return None, None
    
    def rsa_decrypt(self, encrypted_data, privkey):
        """Decrypt data using RSA private key"""
        try:
            return rsa.decrypt(encrypted_data, privkey)
        except Exception as e:
            print(f"❌ RSA decryption failed: {e}")
            return None
    
    def unpad_message(self, padded_data):
        """Remove PKCS7 padding"""
        try:
            padding_length = padded_data[-1]
            return padded_data[:-padding_length]
        except Exception as e:
            print(f"❌ Unpadding failed: {e}")
            return None
    
    def aes_decrypt(self, encrypted_data, aes_key):
        """Decrypt data using AES-256-ECB"""
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            decrypted_data = self.unpad_message(decrypted_padded)
            
            if decrypted_data is None:
                return None
            
            return decrypted_data.decode('utf-8')
        except Exception as e:
            print(f"❌ AES decryption failed: {e}")
            return None
    
    def hybrid_decrypt(self, encrypted_message, encrypted_aes_key, privkey):
        """
        Hybrid decryption: RSA for AES key, then AES for message
        """
        print("\n=== Starting Hybrid Decryption ===")
        
        # Step 1: Decrypt AES key using RSA
        aes_key = self.rsa_decrypt(encrypted_aes_key, privkey)
        if aes_key is None:
            print("❌ Failed to decrypt AES key")
            return None
        print("✓ AES key decrypted with RSA")
        
        # Step 2: Decrypt message using AES
        decrypted_message = self.aes_decrypt(encrypted_message, aes_key)
        if decrypted_message is None:
            print("❌ Failed to decrypt message")
            return None
        print("✓ Message decrypted with AES")
        
        print("=== Hybrid Decryption Complete ===\n")
        return decrypted_message
    
    def decrypt_aes_only(self, filename="aes_encrypted.json"):
        """Decrypt AES-only encrypted data"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            encrypted_message = bytes.fromhex(data["encrypted_message"])
            aes_key = bytes.fromhex(data["aes_key"])
            
            decrypted_message = self.aes_decrypt(encrypted_message, aes_key)
            return decrypted_message
        except Exception as e:
            print(f"❌ Error in AES-only decryption: {e}")
            return None
    
    def decrypt_rsa_only(self, filename="rsa_encrypted.json", privkey_path="keys/private_key.pkl"):
        """Decrypt RSA-only encrypted data"""
        try:
            # Load private key
            privkey = self.load_private_key(privkey_path)
            if privkey is None:
                return None
            
            # Load encrypted data
            with open(filename, 'r') as f:
                data = json.load(f)
            
            encrypted_message = bytes.fromhex(data["encrypted_message"])
            
            # Decrypt
            decrypted_data = self.rsa_decrypt(encrypted_message, privkey)
            if decrypted_data is None:
                return None
            
            return decrypted_data.decode('utf-8')
        except Exception as e:
            print(f"❌ Error in RSA-only decryption: {e}")
            return None

def main():
    print("🔓 HYBRID DECRYPTION SYSTEM 🔓")
    print("=" * 50)
    
    crypto = HybridDecryption()
    
    while True:
        print("\nChoose decryption option:")
        print("1. Decrypt hybrid encrypted message (RSA + AES)")
        print("2. Decrypt AES-only encrypted message")
        print("3. Decrypt RSA-only encrypted message")
        print("4. Decrypt custom hybrid data")
        print("5. List available encrypted files")
        print("6. Exit")
        
        choice = input("\nYour choice (1-6): ").strip()
        
        if choice == '1':
            # Hybrid decryption
            print("\n--- Hybrid Decryption ---")
            
            # Load private key
            privkey = crypto.load_private_key()
            if privkey is None:
                print("💡 Make sure you have generated keys using encrypt.py first!")
                continue
            
            # Load encrypted data
            encrypted_message, encrypted_aes_key = crypto.load_encrypted_data()
            if encrypted_message is None or encrypted_aes_key is None:
                print("💡 Make sure you have encrypted data using encrypt.py first!")
                continue
            
            # Decrypt
            decrypted_message = crypto.hybrid_decrypt(encrypted_message, encrypted_aes_key, privkey)
            
            if decrypted_message:
                print(f"\n🎉 DECRYPTION SUCCESSFUL!")
                print(f"📄 Original message: {decrypted_message}")
            else:
                print("\n❌ Decryption failed!")
        
        elif choice == '2':
            # AES-only decryption
            print("\n--- AES-Only Decryption ---")
            
            decrypted_message = crypto.decrypt_aes_only()
            
            if decrypted_message:
                print(f"\n🎉 AES DECRYPTION SUCCESSFUL!")
                print(f"📄 Original message: {decrypted_message}")
            else:
                print("\n❌ AES decryption failed!")
        
        elif choice == '3':
            # RSA-only decryption
            print("\n--- RSA-Only Decryption ---")
            
            decrypted_message = crypto.decrypt_rsa_only()
            
            if decrypted_message:
                print(f"\n🎉 RSA DECRYPTION SUCCESSFUL!")
                print(f"📄 Original message: {decrypted_message}")
            else:
                print("\n❌ RSA decryption failed!")
        
        elif choice == '4':
            # Custom hybrid decryption
            print("\n--- Custom Hybrid Decryption ---")
            
            try:
                # Get file paths from user
                encrypted_file = input("Enter encrypted data file path (default: encrypted_data.json): ").strip()
                if not encrypted_file:
                    encrypted_file = "encrypted_data.json"
                
                privkey_file = input("Enter private key file path (default: keys/private_key.pkl): ").strip()
                if not privkey_file:
                    privkey_file = "keys/private_key.pkl"
                
                # Load private key
                privkey = crypto.load_private_key(privkey_file)
                if privkey is None:
                    continue
                
                # Load encrypted data
                encrypted_message, encrypted_aes_key = crypto.load_encrypted_data(encrypted_file)
                if encrypted_message is None or encrypted_aes_key is None:
                    continue
                
                # Decrypt
                decrypted_message = crypto.hybrid_decrypt(encrypted_message, encrypted_aes_key, privkey)
                
                if decrypted_message:
                    print(f"\n🎉 CUSTOM DECRYPTION SUCCESSFUL!")
                    print(f"📄 Original message: {decrypted_message}")
                else:
                    print("\n❌ Custom decryption failed!")
                    
            except KeyboardInterrupt:
                print("\n⏸️ Operation cancelled by user")
        
        elif choice == '5':
            # List files
            print("\n--- Available Files ---")
            
            files_to_check = [
                "encrypted_data.json",
                "aes_encrypted.json", 
                "rsa_encrypted.json",
                "keys/private_key.pkl",
                "keys/public_key.pkl"
            ]
            
            found_files = []
            for file_path in files_to_check:
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    found_files.append(f"✓ {file_path} ({size} bytes)")
                else:
                    found_files.append(f"❌ {file_path} (not found)")
            
            for file_info in found_files:
                print(file_info)
            
            if not any("✓" in f for f in found_files):
                print("\n💡 No encrypted files found. Use encrypt.py to create some!")
        
        elif choice == '6':
            print("\n👋 Thank you for using Hybrid Decryption System!")
            print("🔒 Keep your private keys secure!")
            break
            
        else:
            print("❌ Invalid choice! Please enter 1-6")

if __name__ == "__main__":
    main()