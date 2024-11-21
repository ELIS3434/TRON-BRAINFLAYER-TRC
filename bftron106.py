import os
import ecdsa
import hashlib
import base58
from tronpy import Tron
from colorama import init, Fore
import math
import multiprocessing
from multiprocessing import Pool, Manager
from tqdm import tqdm
import logging

# Initialize Tron client
client = Tron()

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(level=logging.INFO)

# Sample private key with desired characteristics
SAMPLE_PRIVATE_KEY = bytes.fromhex('597fb3998b6470ed35dcd5074e5bd3a2d9f15ef4bb56c1639dceb0626476045e')

# Target metrics with wider tolerances
TARGET_ENTROPY = 4.88
TARGET_BIT_DIVERSITY = 53.52
ENTROPY_TOLERANCE = 4.0  # Wider tolerance for entropy
BIT_DIVERSITY_TOLERANCE = 4.0  # Wider tolerance for bit diversity

def analyze_sample_key():
    entropy = calculate_entropy(SAMPLE_PRIVATE_KEY)
    bit_diversity = calculate_bit_diversity(SAMPLE_PRIVATE_KEY)
    byte_pattern = get_byte_pattern(SAMPLE_PRIVATE_KEY)
    return entropy, bit_diversity, byte_pattern

def get_byte_pattern(data):
    """Analyze byte patterns in the private key"""
    patterns = {
        'high_bytes': sum(1 for b in data if b > 127),
        'low_bytes': sum(1 for b in data if b < 128),
        'zero_bytes': sum(1 for b in data if b == 0),
        'byte_ranges': [sum(1 for b in data if lower <= b < upper) 
                       for lower, upper in [(0,64), (64,128), (128,192), (192,256)]]
    }
    return patterns

def generate_private_key():
    """Generate a private key with similar characteristics to the sample"""
    while True:
        key = os.urandom(32)
        entropy = calculate_entropy(key)
        bit_diversity = calculate_bit_diversity(key)
        
        # Check if metrics match target values with wider tolerance
        if (abs(entropy - TARGET_ENTROPY) <= ENTROPY_TOLERANCE and 
            abs(bit_diversity - TARGET_BIT_DIVERSITY) <= BIT_DIVERSITY_TOLERANCE):
            
            # Additional check for byte pattern similarity
            key_pattern = get_byte_pattern(key)
            sample_pattern = get_byte_pattern(SAMPLE_PRIVATE_KEY)
            
            # Compare patterns with wider tolerance
            pattern_match = (
                abs(key_pattern['high_bytes'] - sample_pattern['high_bytes']) <= 4 and
                abs(key_pattern['low_bytes'] - sample_pattern['low_bytes']) <= 4 and
                all(abs(k - s) <= 4 for k, s in zip(key_pattern['byte_ranges'], 
                                                   sample_pattern['byte_ranges']))
            )
            
            if pattern_match:
                return key

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    return sk.get_verifying_key().to_string()

def public_key_to_address(public_key):
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    address = b'\x41' + ripemd160  # Version byte 0x41 for Tron
    checksum = hashlib.sha256(hashlib.sha256(address).digest()).digest()[:4]
    return base58.b58encode(address + checksum)

def check_address_balance(address):
    try:
        balance = client.get_account_balance(address)
        return balance
    except Exception as e:
        logging.error(f"Error checking balance: {e}")
        return None

def calculate_entropy(data):
    byte_counts = {}
    for byte in data:
        if byte in byte_counts:
            byte_counts[byte] += 1
        else:
            byte_counts[byte] = 1
    
    entropy = 0
    for count in byte_counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return entropy

def calculate_bit_diversity(data):
    bits = ''.join(format(byte, '08b') for byte in data)
    total_bits = len(bits)
    unique_bits = len(set(bits))
    return (unique_bits / total_bits) * 100

def process_chunk(args):
    target_address, start_idx, chunk_size, result_queue = args
    sample_pattern = get_byte_pattern(SAMPLE_PRIVATE_KEY)
    
    for _ in range(chunk_size):
        private_key = generate_private_key()
        entropy = calculate_entropy(private_key)
        bit_diversity = calculate_bit_diversity(private_key)
        
        public_key = private_key_to_public_key(private_key)
        generated_address = public_key_to_address(public_key).decode()

        if generated_address == target_address:
            balance = check_address_balance(target_address)
            result = {
                'address': target_address,
                'private_key': private_key.hex(),
                'balance': balance,
                'entropy': entropy,
                'bit_diversity': bit_diversity,
                'pattern': get_byte_pattern(private_key)
            }
            result_queue.put(result)
            return result
        
        # Log close pattern matches
        if (abs(entropy - TARGET_ENTROPY) <= ENTROPY_TOLERANCE/2):
            pattern = get_byte_pattern(private_key)
            logging.info(f'\nClose match found:')
            logging.info(f'Private Key: {private_key.hex()}')
            logging.info(f'Entropy: {entropy:.2f} bits')
            logging.info(f'Bit Diversity: {bit_diversity:.2f}%')
            logging.info(f'Pattern similarity: {pattern}')
    
    return None

def process_address(address, attempts_per_address, num_processes):
    chunk_size = attempts_per_address // num_processes
    manager = Manager()
    result_queue = manager.Queue()
    
    chunks = [(address, i * chunk_size, chunk_size, result_queue) 
              for i in range(num_processes)]
    
    with Pool(processes=num_processes) as pool:
        with tqdm(total=attempts_per_address, desc=f"Processing {address[:8]}...") as pbar:
            for _ in pool.imap_unordered(process_chunk, chunks):
                pbar.update(chunk_size)
                if not result_queue.empty():
                    return result_queue.get()
    
    return None

def main(input_file, output_file):
    # Analyze sample key patterns
    sample_entropy, sample_bit_diversity, sample_pattern = analyze_sample_key()
    
    logging.info(f"\nSample Key Analysis:")
    logging.info(f"Sample Key: {SAMPLE_PRIVATE_KEY.hex()}")
    logging.info(f"Entropy: {sample_entropy:.2f} bits")
    logging.info(f"Bit Diversity: {sample_bit_diversity:.2f}%")
    logging.info(f"Byte Pattern: {sample_pattern}\n")
    
    logging.info(f"Target Metrics:")
    logging.info(f"Entropy: {TARGET_ENTROPY} ± {ENTROPY_TOLERANCE} bits")
    logging.info(f"Bit Diversity: {TARGET_BIT_DIVERSITY} ± {BIT_DIVERSITY_TOLERANCE}%\n")

    with open(input_file, 'r') as file:
        addresses = [addr.strip() for addr in file.readlines() if addr.strip()]

    total_addresses = len(addresses)
    logging.info(f"Total addresses to process: {total_addresses}\n")

    num_processes = max(1, multiprocessing.cpu_count() - 1)
    attempts_per_address = 100000
    total_matches = 0

    logging.info(f"Using {num_processes} CPU cores for parallel processing")

    with open(output_file, 'w') as out_file:
        for index, address in enumerate(addresses, 1):
            logging.info(f"\nProcessing address {index}/{total_addresses}: {address}")
            
            result = process_address(address, attempts_per_address, num_processes)
            
            if result:
                total_matches += 1
                logging.info(
                    f'Match found! Address: {result["address"]}, '
                    f'Private Key: {result["private_key"]}, '
                    f'Balance: {result["balance"]}'
                )
                logging.info(f'Entropy: {result["entropy"]:.2f} bits')
                logging.info(f'Bit Diversity: {result["bit_diversity"]:.2f}%')
                logging.info(f'Pattern: {result["pattern"]}')
                
                out_file.write(
                    f'Address: {result["address"]}, '
                    f'Private Key: {result["private_key"]}, '
                    f'Balance: {result["balance"]}, '
                    f'Entropy: {result["entropy"]:.2f}, '
                    f'Bit Diversity: {result["bit_diversity"]:.2f}\n'
                )
            else:
                logging.info(f'No match found for address: {address}')

    logging.info(f"\nProcessing complete. Total matches found: {total_matches}")
    logging.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    input_file = 'tron.txt'  # Your input file with addresses
    output_file = 'found'  # Output file for found private keys
    main(input_file, output_file)
