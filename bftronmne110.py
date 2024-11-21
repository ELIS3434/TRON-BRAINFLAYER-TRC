import os
import multiprocessing
from multiprocessing import Pool, Manager, Value, Lock
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time
import random
from mnemonic import Mnemonic
from hdwallet import HDWallet
from hdwallet.symbols import TRX
from typing import Dict, Optional, List, Set, Union
import ctypes
import threading
import json
from datetime import datetime
import psutil
import signal
import sys

class SharedCounter:
    """Thread-safe counter for tracking total attempts"""
    def __init__(self, initial_value: int = 0):
        self.val = Value(ctypes.c_uint64, initial_value)
        self.lock = Lock()

    def increment(self, n: int = 1) -> None:
        with self.lock:
            self.val.value += n

    def value(self) -> int:
        with self.lock:
            return self.val.value

class EnhancedTronWallet:
    """Optimized Tron wallet implementation with caching and batch processing"""
    def __init__(self):
        self.mnemo = Mnemonic("english")
        self._wordlist = self.mnemo.wordlist
        self._hdwallet = HDWallet(symbol=TRX)
        self._cache = {}  # Simple mnemonic-to-address cache
        self._cache_size = 1000  # Maximum cache size
        
    def generate_mnemonic(self, strength: int = 128) -> str:
        """Generate a mnemonic phrase with specified strength"""
        return self.mnemo.generate(strength=strength)

    def get_address_from_mnemonic(self, mnemonic: str, path: str = "m/44'/195'/0'/0/0") -> Optional[str]:
        """Convert mnemonic to Tron address with caching"""
        cache_key = f"{mnemonic}:{path}"
        
        if cache_key in self._cache:
            return self._cache[cache_key]
            
        try:
            self._hdwallet.clean_derivation()
            self._hdwallet.from_mnemonic(mnemonic=mnemonic)
            self._hdwallet.from_path(path)
            address = self._hdwallet.p2pkh_address()
            
            # Cache management
            if len(self._cache) >= self._cache_size:
                # Remove a random item if cache is full
                self._cache.pop(random.choice(list(self._cache.keys())))
            self._cache[cache_key] = address
            
            return address
        except Exception:
            return None

class TronMnemonicEnhanced:
    def __init__(self):
        self.target_addresses = set()
        self.found_addresses = set()
        self.total_attempts = SharedCounter()
        self.start_time = time.time()
        self.session_found = 0
        self.checkpoint_interval = 300  # Save checkpoint every 5 minutes
        self.last_checkpoint = time.time()
        self.running = True
        self.setup_signal_handlers()

    def setup_signal_handlers(self) -> None:
        """Setup handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals"""
        print("\nGraceful shutdown initiated...")
        self.running = False
        self.save_checkpoint()
        sys.exit(0)

    def load_addresses(self, filename: str = 'tron.txt') -> None:
        """Load target addresses from file"""
        try:
            with open(filename, 'r') as f:
                self.target_addresses = {line.strip() for line in f if line.strip()}
            print(f"Loaded {len(self.target_addresses):,} addresses")
        except Exception as e:
            print(f"Error loading addresses: {e}")
            sys.exit(1)

    def load_checkpoint(self) -> None:
        """Load progress from checkpoint file"""
        try:
            if os.path.exists('mnemonic_checkpoint.json'):
                with open('mnemonic_checkpoint.json', 'r') as f:
                    data = json.load(f)
                    self.total_attempts = SharedCounter(data.get('total_attempts', 0))
                    self.found_addresses = set(data.get('found_addresses', []))
                    print(f"Loaded checkpoint: {self.total_attempts.value():,} previous attempts")
        except Exception as e:
            print(f"Error loading checkpoint: {e}")

    def save_checkpoint(self) -> None:
        """Save progress to checkpoint file"""
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'total_attempts': self.total_attempts.value(),
                'found_addresses': list(self.found_addresses),
            }
            with open('mnemonic_checkpoint.json', 'w') as f:
                json.dump(data, f, indent=2)
            self.last_checkpoint = time.time()
        except Exception as e:
            print(f"Error saving checkpoint: {e}")

    def save_result(self, result: Dict) -> None:
        """Save found mnemonic to file"""
        try:
            with open('found_mnemonics.txt', 'a') as f:
                f.write(
                    f"[{datetime.now().isoformat()}] "
                    f"Address: {result['address']}, "
                    f"Mnemonic: {result['mnemonic']}, "
                    f"Path: {result['path']}\n"
                )
            self.found_addresses.add(result['address'])
            self.session_found += 1
        except Exception as e:
            print(f"Error saving result: {e}")

    def process_chunk(self, args: tuple) -> Optional[Dict]:
        """Process a chunk of mnemonic generations with improved efficiency"""
        target_addresses, chunk_size, result_queue, progress_queue = args
        wallet = EnhancedTronWallet()
        local_progress = 0
        progress_update_interval = 1000
        
        start_time = time.time()
        last_update = start_time
        
        # Process in batches for better performance
        batch_size = 100
        while local_progress < chunk_size and self.running:
            try:
                # Generate and process batch
                mnemonics = [wallet.generate_mnemonic() for _ in range(batch_size)]
                for mnemonic in mnemonics:
                    address = wallet.get_address_from_mnemonic(mnemonic)
                    if address in target_addresses:
                        result = {
                            'address': address,
                            'mnemonic': mnemonic,
                            'path': f"m/44'/195'/0'/0/0"
                        }
                        result_queue.put(result)
                        return result
                
                local_progress += batch_size
                self.total_attempts.increment(batch_size)
                
                # Update progress periodically
                if local_progress >= progress_update_interval:
                    current_time = time.time()
                    speed = local_progress / (current_time - last_update)
                    progress_queue.put((local_progress, speed))
                    local_progress = 0
                    last_update = current_time
                
                # Check if it's time to save checkpoint
                if time.time() - self.last_checkpoint >= self.checkpoint_interval:
                    self.save_checkpoint()
                    
            except Exception as e:
                continue
        
        if local_progress > 0:
            progress_queue.put((local_progress, 0))
        
        return None

    def run(self, num_processes: Optional[int] = None) -> None:
        """Main execution method with improved process management"""
        if not self.target_addresses:
            print("No target addresses loaded. Please load addresses first.")
            return

        if num_processes is None:
            num_processes = max(1, multiprocessing.cpu_count() - 1)

        print(f"Starting search with {num_processes} processes...")
        
        manager = Manager()
        result_queue = manager.Queue()
        progress_queue = manager.Queue()
        
        chunk_size = 10000
        total_chunks = num_processes * 2

        with Pool(processes=num_processes) as pool:
            try:
                # Start progress monitoring in a separate thread
                with ThreadPoolExecutor(max_workers=1) as executor:
                    executor.submit(self.monitor_progress, progress_queue)
                
                while self.running:
                    args = [(self.target_addresses, chunk_size, result_queue, progress_queue)
                           for _ in range(total_chunks)]
                    
                    for result in pool.imap_unordered(self.process_chunk, args):
                        if result:
                            self.save_result(result)
                            print(f"\nFound match! Address: {result['address']}")
                            print(f"Mnemonic: {result['mnemonic']}")
                            
                    if not self.running:
                        break
                        
            except KeyboardInterrupt:
                print("\nStopping processes...")
                pool.terminate()
                pool.join()
                self.save_checkpoint()
                sys.exit(0)

    def monitor_progress(self, progress_queue) -> None:
        """Monitor and display progress with improved metrics"""
        total_progress = 0
        start_time = time.time()
        pbar = tqdm(total=None, unit='attempts', dynamic_ncols=True)
        
        while self.running:
            try:
                progress, speed = progress_queue.get(timeout=1)
                total_progress += progress
                
                elapsed = time.time() - start_time
                total_attempts = self.total_attempts.value()
                
                # Update progress bar with detailed statistics
                pbar.set_description(
                    f"Speed: {speed:,.0f}/s | "
                    f"Total: {total_attempts:,} | "
                    f"Found: {self.session_found} | "
                    f"Elapsed: {int(elapsed)}s"
                )
                pbar.update(progress)
                
            except Exception:
                continue

def main():
    finder = TronMnemonicEnhanced()
    finder.load_addresses()
    finder.load_checkpoint()
    finder.run()

if __name__ == "__main__":
    main()
