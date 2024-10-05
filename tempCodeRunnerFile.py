def decryption():
    print("\nDecryption Process:")

    encrypted_message = input("Enter the encrypted message: ")
    privkey_str = input("Enter the private key: ")

    # Convert the input string to bytes
    encrypted_message_bytes = bytes.fromhex(encrypted_message)
    
    # Recreate the private key object
    privkey = rsa.PrivateKey.load_pkcs1(privkey_str.encode())

    try:
        rsa_decrypted_message = rsa.decrypt(encrypted_message_bytes, privkey)
        print("Outer layer (RSA) decrypted.")

        aes_key = input("Enter the AES key: ")
        aes_key_bytes = bytes.fromhex(aes_key)

        backend = default_backend()
        aes_cipher = Cipher(algorithms.AES(aes_key_bytes), modes.ECB(), backend=backend)
        aes_decryptor = aes_cipher.decryptor()
        decrypted_padded_message = aes_decryptor.update(rsa_decrypted_message) + aes_decryptor.finalize()

        # Unpad the message
        def unpad(data):
            padding_length = data[-1]
            return data[:-padding_length]

        decrypted_message = unpad(decrypted_padded_message).decode('utf-8')
        print("Inner layer (AES) decrypted.")

        print("Decrypted message:", decrypted_message)
    except Exception as e:
        print(f"An error occurred during decryption: {str(e)}")


def main():
    print("Welcome to the Hybrid Encryption Demo")
    print("=====================================")
    
    while True:
        print("\nChoose an option:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            hybrid_encryption()
        elif choice == '2':
            decryption()
        elif choice == '3':
            print("Thank you for using the Hybrid Encryption Demo. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
