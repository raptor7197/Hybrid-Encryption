#!/usr/bin/python3

import hashlib
import random
import math

 
prime = set()

public_key = None
private_key = None
n = None


def primefiller():
	
	seive = [True] * 250
	seive[0] = False
	seive[1] = False
	for i in range(2, 250):
		for j in range(i * 2, 250, i):
			seive[j] = False

	# Filling the prime numbers
	for i in range(len(seive)):
		if seive[i]:
			prime.add(i)


def pickrandomprime():
	global prime
	k = random.randint(0, len(prime) - 1)
	it = iter(prime)
	for _ in range(k):
		next(it)

	ret = next(it)
	prime.remove(ret)
	return ret


def setkeys():
	global public_key, private_key, n
	prime1 = pickrandomprime() 
	prime2 = pickrandomprime() 
	n = prime1 * prime2
	fi = (prime1 - 1) * (prime2 - 1)

	e = 2
	while True:
		if math.gcd(e, fi) == 1:
			break
		e += 1

	public_key = e

	d = 2
	while True:
		if (d * e) % fi == 1:
			break
		d += 1

	private_key = d


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
	# Calling the decrypting function decoding function
	for num in encoded:
		s += chr(decrypt(num))
	return s


# {'sha3_512', 'blake2s', 'sha256', 'sha512', 'sha512_256', 'shake_256', 'md5', 'sha3_224', 'blake2b', 'sha384', 'sm3', 'sha3_256', 'sha3_384', 'sha1', 'shake_128', 'sha512_224', 'sha224', 'md5-sha1'}


def sha256():
	 print(hashlib.algorithms_available)
	 k = hashlib.sha256(b"hello bhai kya hal chal  gaswnhjaheifuea pho*jndcokfegfa???$%^")
	 print(k.hexdigest())
	 print("----------------------------------------------------------------------------------------------------\n")
	 blake = hashlib.blake2b()
	 k = input("message for blake")
	 blake.update(b'k')
	#  print(hashlib.blake2b(k.hexdigest))


if __name__ == '__main__':
	primefiller()
	setkeys()
	sha256()
	# predefined input down
	# message = ""
	message = input("Enter your message\n")
	coded = encoder(message)

	print("Initial message:")
	print(message)
	print("\nThe encoded message : \n")
	# print("\n")
	print(''.join(str(p) for p in coded))
	# to print the decoded message
	print("\nThe decoded message : \n")
	print(''.join(str(p) for p in decoder(coded)))
	
	
# 9e7a5ce504e78724d860b17f9f48186b5c234fcc347d5e305be4d7c204a61727
# ccfa7c21fa2122c45098bfa661ac0242907f83901aa6008ba645ae26b2f54f6d