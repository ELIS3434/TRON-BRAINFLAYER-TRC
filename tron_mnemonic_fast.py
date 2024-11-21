import os
import multiprocessing
from multiprocessing import Pool, Manager, Value, Lock
from tqdm import tqdm
import time
import random
from mnemonic import Mnemonic
from hdwallet import HDWallet
from hdwallet.symbols import TRX
from typing import Dict, Optional, List, Set
import ctypes
import threading

class SharedCounter:
    """Thread-safe counter for tracking total attempts"""
    def __init__(self):
        self.val = Value(ctypes.c_uint64, 0)
        self.lock = Lock()

    def increment(self, n=1):
        with self.lock:
            self.val.value += n

    def value(self):
        with self.lock:
            return self.val.value

class TronWallet:
    def __init__(self):
        self.mnemo = Mnemonic("english")
        self._wordlist = self.mnemo.wordlist
        self._hdwallet = HDWallet(symbol=TRX)
        
    def generate_mnemonic(self) -> str:
        """Generate a 12-word mnemonic"""
        return self.mnemo.generate(strength=128)

    def get_address_from_mnemonic(self, mnemonic: str) -> Optional[str]:
        """Convert mnemonic to Tron address"""
        try:
            self._hdwallet.clean_derivation()
            self._hdwallet.from_mnemonic(mnemonic=mnemonic)
            self._hdwallet.from_path(f"m/44'/195'/0'/0/0")
            return self._hdwallet.p2pkh_address()
        except:
            return None

def process_chunk(args: tuple) -> Optional[Dict]:
    """Process a chunk of mnemonic generations"""
    target_addresses, chunk_size, result_queue, progress_queue, counter = args
    wallet = TronWallet()
    local_progress = 0
    progress_update_interval = 1000  # Increased for better performance
    
    start_time = time.time()
    last_update = start_time
    
    # Pre-generate mnemonics in batches for efficiency
    batch_size = 100
    while local_progress < chunk_size:
        try:
            # Generate batch of mnemonics
            mnemonics = [wallet.generate_mnemonic() for _ in range(batch_size)]
            addresses = []
            
            # Convert mnemonics to addresses in batch
            for mnemonic in mnemonics:
                address = wallet.get_address_from_mnemonic(mnemonic)
                if address:
                    addresses.append((address, mnemonic))
            
            # Check addresses against target set
            for address, mnemonic in addresses:
                if address in target_addresses:
                    result = {
                        'address': address,
                        'mnemonic': mnemonic,
                        'path': f"m/44'/195'/0'/0/0"
                    }
                    result_queue.put(result)
                    return result
            
            local_progress += batch_size
            counter.increment(batch_size)
            
            if local_progress >= progress_update_interval:
                current_time = time.time()
                speed = local_progress / (current_time - last_update)
                progress_queue.put((local_progress, speed))
                local_progress = 0
                last_update = current_time
                
        except Exception as e:
            continue
    
    if local_progress > 0:
        progress_queue.put((local_progress, 0))
    
    return None

def process_addresses(addresses: Set[str], total_attempts: int, num_processes: int) -> List[Dict]:
    """Process multiple addresses simultaneously"""
    chunk_size = total_attempts // num_processes
    manager = Manager()
    result_queue = manager.Queue()
    progress_queue = manager.Queue()
    counter = SharedCounter()
    
    chunks = [(addresses, chunk_size, result_queue, progress_queue, counter) 
             for _ in range(num_processes)]
    
    found_results = []
    start_time = time.time()
    
    with Pool(processes=num_processes) as pool:
        with tqdm(total=total_attempts, desc="Searching", unit='seeds', 
                 unit_scale=True) as pbar:
            
            async_results = [pool.apply_async(process_chunk, (chunk,)) 
                           for chunk in chunks]
            
            total_speed = 0
            speed_updates = 0
            last_count = 0
            
            while counter.value() < total_attempts:
                try:
                    # Update progress and speed
                    while not progress_queue.empty():
                        progress, speed = progress_queue.get_nowait()
                        if speed > 0:
                            total_speed += speed
                            speed_updates += 1
                            avg_speed = total_speed / speed_updates
                            elapsed = time.time() - start_time
                            eta = (total_attempts - counter.value()) / avg_speed if avg_speed > 0 else 0
                            
                            pbar.set_postfix({
                                'speed': f'{avg_speed:.0f}/s',
                                'elapsed': f'{elapsed:.1f}s',
                                'eta': f'{eta:.1f}s'
                            })
                    
                    # Update progress bar
                    current_count = counter.value()
                    if current_count > last_count:
                        pbar.update(current_count - last_count)
                        last_count = current_count
                    
                    # Check for results
                    while not result_queue.empty():
                        result = result_queue.get_nowait()
                        if result:
                            found_results.append(result)
                            # Don't stop, keep searching for more matches
                    
                    # Small sleep to prevent CPU overload
                    time.sleep(0.1)
                    
                except Exception as e:
                    continue
            
            # Get any remaining results
            for r in async_results:
                try:
                    result = r.get(timeout=1)
                    if result:
                        found_results.append(result)
                except:
                    pass
    
    return found_results

def main():
    # Configuration
    input_file = 'tron.txt'
    output_file = 'found_mnemonics.txt'
    total_attempts = 100_000_000  # 100 million attempts total
    num_processes = multiprocessing.cpu_count()
    
    print("\nTron Mnemonic Finder (Fast Version)")
    print("--------------------------------")
    
    # Load addresses into a set for O(1) lookup
    try:
        with open(input_file, 'r') as f:
            target_addresses = {line.strip() for line in f if line.strip()}
    except Exception as e:
        print(f"Error loading addresses: {str(e)}")
        return
    
    if not target_addresses:
        print("No addresses found in input file!")
        return
    
    print(f"Starting search with {num_processes} processes")
    print(f"Loaded {len(target_addresses)} addresses")
    print(f"Total attempts: {total_attempts:,}")
    print("Using 12-word mnemonics only")
    print("--------------------------------\n")
    
    try:
        results = process_addresses(target_addresses, total_attempts, num_processes)
        
        if results:
            print(f"\nFound {len(results)} matches!")
            
            # Save results
            try:
                with open(output_file, 'a') as f:
                    for result in results:
                        print(
                            f'\n!!! FOUND MATCH !!!\n'
                            f'Address: {result["address"]}\n'
                            f'Mnemonic: {result["mnemonic"]}\n'
                            f'Path: {result["path"]}'
                        )
                        
                        f.write(
                            f'Address: {result["address"]}, '
                            f'Mnemonic: {result["mnemonic"]}, '
                            f'Path: {result["path"]}\n'
                        )
            except Exception as e:
                print(f"Error saving results: {str(e)}")
        else:
            print(f"\nNo matches found after {total_attempts:,} attempts")
                
    except KeyboardInterrupt:
        print("\nStopping... (Ctrl+C pressed)")
    except Exception as e:
        print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
