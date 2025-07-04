#!/usr/bin/python3

import rsa
import hashlib
import random
import math
from cryptography.fernet import Fernet 
from aes import aes
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# from Crypto

 
prime = set()

public_key = None
private_key = None
n = None


# def primefiller():
	
# 	seive = [True] * 250
# 	seive[0] = False
# 	seive[1] = False
# 	for i in range(2, 250):
# 		for j in range(i * 2, 250, i):
# 			seive[j] = False

# 	# Filling the prime numbers
# 	for i in range(len(seive)):
# 		if seive[i]:
# 			prime.add(i)


# def pickrandomprime():
# 	global prime
# 	k = random.randint(0, len(prime) - 1)
# 	it = iter(prime)
# 	for _ in range(k):
# 		next(it)

# 	ret = next(it)
# 	prime.remove(ret)
# 	return ret


# def setkeys():
# 	global public_key, private_key, n
# 	prime1 = pickrandomprime() 
# 	prime2 = pickrandomprime() 
# 	n = prime1 * prime2
# 	fi = (prime1 - 1) * (prime2 - 1)

# 	e = 2
# 	while True:
# 		if math.gcd(e, fi) == 1:
# 			break
# 		e += 1

# 	public_key = e

# 	d = 2
# 	while True:
# 		if (d * e) % fi == 1:
# 			break
# 		d += 1

# 	private_key = d


def encrypt(message):
	global public_key, n
	e = public_key
	encrypted_text = 1
	while e > 0:
		encrypted_text *= message
		encrypted_text %= n
		e -= 1
	return encrypted_text


def decrypt(encrypted_text):
	global private_key, n
	d = private_key
	decrypted = 1
	while d > 0:
		decrypted *= encrypted_text
		decrypted %= n
		d -= 1
	return decrypted


def encoder(message):
	encoded = []
	for letter in message:
		encoded.append(encrypt(ord(letter)))
	return encoded


def decoder(encoded):
	s = ''
	for num in encoded:
		s += chr(decrypt(num))
	return s


# {'sha3_512', 'blake2s', 'sha256', 'sha512', 'sha512_256', 'shake_256', 'md5', 'sha3_224', 'blake2b', 'sha384', 'sm3', 'sha3_256', 'sha3_384', 'sha1', 'shake_128', 'sha512_224', 'sha224', 'md5-sha1'}
# def rsa_test():
	# (pubkey, privkey) = rsa.newkeys(512)
	# (pubkey, privkey) = rsa.newkeys(2048, poolsize=15)
	
	# l = input("Enter Your message :")
	# message = l.encode('utf8')
	# print(message)
	# crypto = rsa.encrypt(message, pubkey)	
	# print(crypto)

	# print("----------------------------------------------------------------------------------------------------\n")
	# msg = 'hello this is a test message`'.encode()
	# hash = rsa.compute_hash(msg, 'SHA-512')
	# signature = rsa.sign(hash, privkey, 'SHA-512')
	# rsa.verify(msg, signature, pubkey)

	# output = rsa.decrypt(crypto, privkey)
	# print(message.decode('utf8'))


def rsa_example():
	(pubkey, privkey) = rsa.newkeys(2048, poolsize=15)
	print(privkey)
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
    
	key = os.urandom(32)
	print("Generated AES key:", key.hex())

	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

	message = input("Enter the message to encrypt by aes: ").encode('utf-8')
	print("Original message:", message.decode('utf-8'))
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







# Call the function
# rsa_example()
	

# def sha256():
# 	 print(hashlib.algorithms_available)
# 	 user_input = input("message for blake\n")
# 	 text = input("")
# 	 user_input = user_input.encode(f"{user_input}")
# 	 k = hashlib.sha256(f"{user_input}")
# 	 l = k.hexdigest()
# 	 print(l)
# 	 print("----------------------------------------------------------------------------------------------------\n")
# 	 blake = hashlib.blake2b()
# 	 blake.update(b'k')

# --------------------------------------------------------------

def rsa_private_key():
	from cryptography.hazmat.primitives.asymmetric import rsa
	private_key = rsa.generate_private_key(public_exponent=65537,key_size=4096,)
	print(private_key)


# def double_hash():
#     # key = Fernet.generate_key() 
#     # print(key)
# 	key = b'hbowEEfPOUblcMXR0opPhmW5bT1ZJzY7klohpElJz5M='
#     # print("-------------------------------------------------\n")
    
# 	f = Fernet(key)
# 	message = input("Enter the message: \n")
    
#     token = f.encrypt(message.encode())	
#     print(token) 
    
#     d = f.decrypt(token) 
#     print(d.decode())
#     print("-------------------------------------------------\n")
    
#     sha256_hash = hashlib.sha256(token)
#     sha256_digest = sha256_hash.hexdigest()
#     print(f"SHA-256 hash: {sha256_digest}")
    
    # Uncomment the following lines if you want to use them
    # print("\n")	
    # print("----------------------------------------------------------------------------------------------------")
    # print("\n")
    
    # blake2b_hash = hashlib.blake2b(token)  # Use 'token' instead of 'user_input'
    # blake2b_digest = blake2b_hash.hexdigest()  
    # print(f"BLAKE2b hash: {blake2b_digest}")

# Call the encrypt function to run the code
# encrypt()

# def sha256_and_blake2b():
    
    # user_input = input("Enter a message for SHA-256 and BLAKE2b:\n")
    

# Call the function
# sha256_and_blake2b()

# BLAKE2b hash: ffd734e0a0b92dcfabb70192cfd2ff033aa666a4f0dcbf44791f3c6433ad6c0b16fa62a12d4cc07772e7b25ae8dd2d88af44c7ef143a529b982c1aebd16a1872
# SHA-256 hash: d5a3669708dec2dd3f1bddd5b82747187a647803ef2183eeb6b1d71a561a01d7

# --------------------------------------------------------------

if __name__ == '__main__':

	# primefiller()
	# rsa_test()
	aes()
	rsa_example()
	# setkeys()
	# print("\n")
	# sha256()
	# double_hash()
	rsa_private_key()
	# sha256_and_blake2b()
	# predefined input down
	# message = ""
	# message = input("Enter your message\n")
	# coded = encoder(message)

	# print("Initial message:")
	# print(message)
	# print("\nThe encoded message : \n")
	# print("\n")
	# print(''.join(str(p) for p in coded))
	# to print the decoded message
	# print("\nThe decoded message : \n")
	# print(''.join(str(p) for p in decoder(coded)))
	
	
# 9e7a5ce504e78724d860b17f9f48186b5c234fcc347d5e305be4d7c204a61727
# ccfa7c21fa2122c45098bfa661ac0242907f83901aa6008ba645ae26b2f54f6d