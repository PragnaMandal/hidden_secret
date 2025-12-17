# core.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from key_manager import load_private_key, load_public_key

# ---- HYBRID ENCRYPTION ----
def encrypt_for_recipient(plaintext: bytes, recipient_public_key, aad: bytes = b"") -> bytes:
    """
    Returns a combined blob: rsa_encrypted_key_len(2 bytes) || rsa_encrypted_key || nonce(12) || ciphertext
    We return bytes; for CLI we can hex-encode when printing.
    """
    # generate random AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)  # includes tag

    # wrap AES key with RSA-OAEP
    rsa_encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    # pack lengths: 2-byte length of rsa_encrypted_key (big-endian)
    klen = len(rsa_encrypted_key).to_bytes(2, "big")
    return klen + rsa_encrypted_key + nonce + ciphertext

def decrypt_from_blob(blob: bytes, private_key, aad: bytes = b"") -> bytes:
    # parse klen
    if len(blob) < 2:
        raise ValueError("blob too short")
    klen = int.from_bytes(blob[:2], "big")
    offset = 2
    rsa_encrypted_key = blob[offset:offset+klen]; offset += klen
    nonce = blob[offset:offset+12]; offset += 12
    ciphertext = blob[offset:]

    # unwrap AES key
    aes_key = private_key.decrypt(
        rsa_encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext

# ---- SIGN / VERIFY ----
def sign_message(message: bytes, private_key) -> bytes:
    sig = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return sig

def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
