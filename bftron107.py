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
import json
import time
from pathlib import Path

# Initialize Tron client
client = Tron()

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler('bftron.log'),
        logging.StreamHandler()
    ]
)

# Sample private key with desired characteristics
SAMPLE_PRIVATE_KEY = bytes.fromhex('597fb3998b6470ed35dcd5074e5bd3a2d9f15ef4bb56c1639dceb0626476045e')

# Target metrics with wider tolerances
TARGET_ENTROPY = 4.88
TARGET_BIT_DIVERSITY = 53.52
ENTROPY_TOLERANCE = 4.0
BIT_DIVERSITY_TOLERANCE = 4.0

# State management
STATE_FILE = 'bftron_state.json'
CHECKPOINT_INTERVAL = 10  # Save state every 10 addresses

class StateManager:
    def __init__(self, state_file):
        self.state_file = state_file
        self.state = self.load_state()
    
    def load_state(self):
        if Path(self.state_file).exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except:
                return self.get_initial_state()
        return self.get_initial_state()
    
    def get_initial_state(self):
        return {
            'last_address_index': 0,
            'processed_addresses': [],
            'total_attempts': 0,
            'last_update': time.time()
        }
    
    def save_state(self):
        self.state['last_update'] = time.time()
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f)
    
    def update_progress(self, address_index, address):
        self.state['last_address_index'] = address_index
        if address not in self.state['processed_addresses']:
            self.state['processed_addresses'].append(address)
        self.state['total_attempts'] += 1
        if address_index % CHECKPOINT_INTERVAL == 0:
            self.save_state()

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
    while True:
        key = os.urandom(32)
        entropy = calculate_entropy(key)
        bit_diversity = calculate_bit_diversity(key)
        
        if (abs(entropy - TARGET_ENTROPY) <= ENTROPY_TOLERANCE and 
            abs(bit_diversity - TARGET_BIT_DIVERSITY) <= BIT_DIVERSITY_TOLERANCE):
            
            key_pattern = get_byte_pattern(key)
            sample_pattern = get_byte_pattern(SAMPLE_PRIVATE_KEY)
            
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
    address = b'\x41' + ripemd160
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
    try:
        target_address, start_idx, chunk_size, result_queue, progress_queue = args
        local_progress = 0
        progress_update_interval = 1000  # Update progress every 1000 attempts
        
        for i in range(chunk_size):
            try:
                # Generate random private key
                private_key = os.urandom(32)
                entropy = calculate_entropy(private_key)
                
                # Only proceed if entropy is within range
                if abs(entropy - TARGET_ENTROPY) <= ENTROPY_TOLERANCE:
                    bit_diversity = calculate_bit_diversity(private_key)
                    
                    if abs(bit_diversity - TARGET_BIT_DIVERSITY) <= BIT_DIVERSITY_TOLERANCE:
                        try:
                            # Generate public key and address
                            public_key = private_key_to_public_key(private_key)
                            generated_address = public_key_to_address(public_key).decode()
                            
                            # Check if we found a match
                            if generated_address == target_address:
                                try:
                                    balance = check_address_balance(target_address)
                                    result = {
                                        'address': target_address,
                                        'private_key': private_key.hex(),
                                        'balance': balance,
                                        'entropy': entropy,
                                        'bit_diversity': bit_diversity
                                    }
                                    result_queue.put(result)
                                    return result
                                except Exception as e:
                                    logging.error(f"Error checking balance: {e}")
                            
                            # Log interesting matches
                            if abs(entropy - TARGET_ENTROPY) <= ENTROPY_TOLERANCE/2:
                                logging.info(f'\nClose match: {private_key.hex()}')
                                logging.info(f'Entropy: {entropy:.2f}, Diversity: {bit_diversity:.2f}%')
                        
                        except Exception as e:
                            logging.error(f"Error in key conversion: {e}")
                            continue
                
                # Update progress
                local_progress += 1
                if local_progress % progress_update_interval == 0:
                    progress_queue.put(progress_update_interval)
                    local_progress = 0
                
            except Exception as e:
                logging.error(f"Error in attempt {i}: {e}")
                continue
        
        # Send remaining progress
        if local_progress > 0:
            progress_queue.put(local_progress)
        
    except Exception as e:
        logging.error(f"Critical error in process_chunk: {e}")
    
    return None

def process_address(address, attempts_per_address, num_processes):
    chunk_size = attempts_per_address // num_processes
    manager = Manager()
    result_queue = manager.Queue()
    progress_queue = manager.Queue()
    
    chunks = [(address, i * chunk_size, chunk_size, result_queue, progress_queue) 
              for i in range(num_processes)]
    
    with Pool(processes=num_processes) as pool:
        total_progress = 0
        with tqdm(total=attempts_per_address, desc=f"Processing {address[:8]}...") as pbar:
            async_results = [pool.apply_async(process_chunk, (chunk,)) for chunk in chunks]
            
            while True:
                try:
                    # Update progress bar
                    while not progress_queue.empty():
                        progress = progress_queue.get_nowait()
                        pbar.update(progress)
                        total_progress += progress
                    
                    # Check if any process found a match
                    if not result_queue.empty():
                        result = result_queue.get_nowait()
                        if result:
                            return result
                    
                    # Check if all processes are done
                    if all(r.ready() for r in async_results):
                        results = [r.get() for r in async_results]
                        if any(results):
                            return next(r for r in results if r)
                        break
                    
                    time.sleep(0.1)  # Prevent CPU overload
                    
                except Exception as e:
                    logging.error(f"Error in progress tracking: {e}")
                    continue
    
    return None

def main(input_file, output_file):
    state_manager = StateManager(STATE_FILE)
    
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
        all_addresses = [addr.strip() for addr in file.readlines() if addr.strip()]

    # Resume from last position
    start_index = state_manager.state['last_address_index']
    addresses = all_addresses[start_index:]
    
    total_addresses = len(addresses)
    logging.info(f"Resuming from address {start_index + 1}")
    logging.info(f"Remaining addresses to process: {total_addresses}\n")

    num_processes = 4
    attempts_per_address = 1000
    total_matches = 0

    logging.info(f"Using {num_processes} CPU cores for parallel processing")

    output_mode = 'a' if start_index > 0 else 'w'
    with open(output_file, output_mode) as out_file:
        try:
            for index, address in enumerate(addresses, start=start_index + 1):
                logging.info(f"\nProcessing address {index}/{len(all_addresses)}: {address}")
                
                result = process_address(address, attempts_per_address, num_processes)
                state_manager.update_progress(index, address)
                
                if result:
                    total_matches += 1
                    logging.info(
                        f'Match found! Address: {result["address"]}, '
                        f'Private Key: {result["private_key"]}, '
                        f'Balance: {result["balance"]}'
                    )
                    logging.info(f'Entropy: {result["entropy"]:.2f} bits')
                    logging.info(f'Bit Diversity: {result["bit_diversity"]:.2f}%')
                    
                    out_file.write(
                        f'Address: {result["address"]}, '
                        f'Private Key: {result["private_key"]}, '
                        f'Balance: {result["balance"]}, '
                        f'Entropy: {result["entropy"]:.2f}, '
                        f'Bit Diversity: {result["bit_diversity"]:.2f}\n'
                    )
                    out_file.flush()  # Ensure immediate write
                else:
                    logging.info(f'No match found for address: {address}')
        
        except KeyboardInterrupt:
            logging.info("\nProcess interrupted by user. Progress saved.")
            state_manager.save_state()
            return
        
        except Exception as e:
            logging.error(f"\nError occurred: {e}")
            state_manager.save_state()
            raise

    state_manager.save_state()
    logging.info(f"\nProcessing complete. Total matches found: {total_matches}")
    logging.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    input_file = 'tron.txt'
    output_file = 'found'
    main(input_file, output_file)
