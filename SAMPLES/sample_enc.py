#!/usr/bin/python3

from Crypto.Cipher import RSA
import zlib
import base64
from Crypto.Cipher import PKCS1_OAEP
from pathlib import Path


def generate_new_key_pair():
    new_key = RSA.generate(4096, e=65537)

    private_key = new_key.exportKey("PEM")

    public_key = new_key.publickey().exportKey("PEM")

    private_key_path = Path('private.pem')
    private_key_path.touch(mode=0o600)
    private_key_path.write_bytes(private_key)

    public_key_path = Path('public.pem')
    public_key_path.touch(mode=0o664)
    public_key_path.write_bytes(public_key)


def encrypt_blob(blob, public_key):
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    blob = zlib.compress(blob)
    
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted = bytearray()

    while not end_loop:
        chunk = blob[offset:offset + chunk_size]

        
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += bytes(chunk_size - len(chunk))
        encrypted += rsa_key.encrypt(chunk)

        offset += chunk_size

    return base64.b64encode(encrypted)

def decrypt_blob(encrypted_blob, private_key):

    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted_blob = base64.b64decode(encrypted_blob)

    chunk_size = 512
    offset = 0
    decrypted = bytearray()

    while offset < len(encrypted_blob):
        chunk = encrypted_blob[offset: offset + chunk_size]

        decrypted += rsakey.decrypt(chunk)

        offset += chunk_size

    return zlib.decompress(decrypted)



private_key = Path('private.pem')
public_key = Path('public.pem')
unencrypted_file = Path('deadbeef.txt')
encrypted_file = unencrypted_file.with_suffix('.dat')

encrypted_msg = encrypt_blob(unencrypted_file.read_bytes(), public_key)
decrypt_blob(encrypted_msg, private_key)