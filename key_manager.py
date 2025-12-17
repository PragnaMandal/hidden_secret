# key_manager.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

PRIVATE_KEY_FILE = "rsa_private.pem"
PUBLIC_KEY_FILE  = "rsa_public.pem"

def generate_rsa_keypair(key_size: int = 3072):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    # write private key (PEM, no encryption - for assignment/demo; in production protect it)
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # write public key (PEM)
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return PRIVATE_KEY_FILE, PUBLIC_KEY_FILE

def load_private_key(path: str = PRIVATE_KEY_FILE):
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str = PUBLIC_KEY_FILE):
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def keys_exist():
    return os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE)
