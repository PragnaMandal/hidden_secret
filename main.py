# main.py
from key_manager import generate_rsa_keypair, keys_exist, load_private_key, load_public_key
from core import encrypt_for_recipient, decrypt_from_blob, sign_message, verify_signature

def hex_in(x: str) -> bytes:
    return bytes.fromhex(x.strip())

def main():
    print("Asymmetric Encryption Demo (Hybrid RSA + AES-GCM)")
    print("Options:")
    print("1: generate-keys")
    print("2: encrypt (use recipient public key)")
    print("3: decrypt (use private key)")
    print("4: sign message")
    print("5: verify signature")
    choice = input("Choose option: ").strip()

    if choice == "1":
        priv, pub = generate_rsa_keypair()
        print(f"Keys generated: {priv}, {pub}")

    elif choice == "2":
        if not keys_exist():
            print("No keys found. Generate keys first.")
            return
        pub = load_public_key()
        text = input("Enter text to encrypt: ").encode()
        aad = input("AAD (optional): ").encode()
        blob = encrypt_for_recipient(text, pub, aad)
        print("Encrypted (hex):")
        print(blob.hex())

    elif choice == "3":
        if not keys_exist():
            print("No keys found. Generate keys first.")
            return
        priv = load_private_key()
        hex_blob = input("Enter encrypted blob (hex): ").strip()
        aad = input("AAD used during encryption: ").encode()
        try:
            plaintext = decrypt_from_blob(bytes.fromhex(hex_blob), priv, aad)
            print("Plaintext:", plaintext.decode())
        except Exception as e:
            print("Decryption failed:", e)

    elif choice == "4":
        if not keys_exist():
            print("No keys found. Generate keys first.")
            return
        priv = load_private_key()
        msg = input("Enter message to sign: ").encode()
        sig = sign_message(msg, priv)
        print("Signature (hex):")
        print(sig.hex())

    elif choice == "5":
        if not keys_exist():
            print("No keys found. Generate keys first.")
            return
        pub = load_public_key()
        msg = input("Enter message that was signed: ").encode()
        sig_hex = input("Enter signature (hex): ").strip()
        ok = verify_signature(msg, bytes.fromhex(sig_hex), pub)
        print("Signature valid?" , ok)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
