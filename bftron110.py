import hashlib
import ecdsa
import base58
import os
import time
from tqdm import tqdm

def private_to_public_key(private_key):
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    return b'\04' + verifying_key.to_string()

def public_key_to_address(public_key):
    public_key_bytes = public_key[1:]
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    version_ripemd160_hash = b'\x41' + ripemd160_hash
    double_sha256 = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest()).digest()
    binary_address = version_ripemd160_hash + double_sha256[:4]
    return base58.b58encode(binary_address).decode()

def load_addresses(filename='tron.txt'):
    with open(filename, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_result(private_key_hex, address):
    with open('found.txt', 'a') as f:
        f.write(f'Private Key: {private_key_hex}\nAddress: {address}\n\n')

def main():
    # Load target addresses
    print("Loading target addresses...")
    try:
        target_addresses = load_addresses()
        print(f"Loaded {len(target_addresses)} addresses")
    except FileNotFoundError:
        print("Error: tron.txt not found. Please create it with target addresses.")
        return

    attempts = 0
    start_time = time.time()
    pbar = tqdm(total=None, desc="Searching", unit="keys")

    try:
        while True:
            # Generate random private key
            private_key = os.urandom(32)
            private_key_hex = private_key.hex()

            # Convert to public key
            public_key = private_to_public_key(private_key)

            # Get address
            address = public_key_to_address(public_key)

            # Check if address matches
            if address in target_addresses:
                print(f"\nFound match!")
                print(f"Address: {address}")
                print(f"Private Key: {private_key_hex}")
                save_result(private_key_hex, address)

            attempts += 1
            if attempts % 100 == 0:
                elapsed = time.time() - start_time
                speed = attempts / elapsed
                pbar.set_description(f"Speed: {speed:.2f} keys/s")
                pbar.update(100)

    except KeyboardInterrupt:
        print("\nStopping...")
        elapsed = time.time() - start_time
        print(f"\nStats:")
        print(f"Total attempts: {attempts:,}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print(f"Average speed: {attempts/elapsed:.2f} keys/s")

if __name__ == "__main__":
    main()
