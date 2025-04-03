# generate_keys.py
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def main():
    # Generate a new private key
    private_key = Ed25519PrivateKey.generate()

    # Get the private key bytes
    private_key_bytes = private_key.private_bytes_raw()

    # Get the public key from the private key
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()

    # Convert the keys to hexadecimal strings
    private_key_hex = private_key_bytes.hex()
    public_key_hex = public_key_bytes.hex()

    # Print the keys in a format suitable for the .env file
    print(f"FASTAPI_WALLETAUTH_PRIVATE_KEY={private_key_hex}")
    print(f"FASTAPI_WALLETAUTH_PUBLIC_KEY={public_key_hex}")

if __name__ == "__main__":
    main()