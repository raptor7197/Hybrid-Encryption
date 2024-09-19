#!/usr/bin/python3
# from aes import aes


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)  # 16 bytes for AES-128
cipher = AES.new(key, AES.MODE_EAX)  # Using EAX mode for encryption

plaintext = b'This is a secret message.'
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

cipher_decrypt = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
decrypted = cipher_decrypt.decrypt_and_verify(ciphertext, tag)








# c = aes(0)
# print(c.dec_once(c.enc_once(0)))


