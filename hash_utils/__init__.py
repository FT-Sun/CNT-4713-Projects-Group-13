import hashlib

def sha256_hash(message):
    hash_object = hashlib.sha256(message.encode('utf-8'))
    return hash_object.hexdigest()