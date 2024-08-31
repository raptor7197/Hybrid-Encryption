#!/usr/bin/python3
import hashlib



string = b"attempt 1 to develop hybrid encryption"

sha256 = hashlib.sha256()
sha256.update(string)
string_hash = sha256.hexdigest()
print(f"Hash:{string_hash}")
