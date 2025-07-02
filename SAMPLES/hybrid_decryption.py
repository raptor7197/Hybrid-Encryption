
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
