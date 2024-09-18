import os
import hashlib
from Crypto.Hash import RIPEMD160
import ecdsa
import base58
import multiprocessing
import time

# Generate a random private key
def generate_private_key():
    return os.urandom(32)

# Generate uncompressed public key
def private_key_to_uncompressed_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # Prefix for uncompressed
    return public_key

# Generate compressed public key
def private_key_to_compressed_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[63] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    return public_key

# Generate Bitcoin address from public key
def public_key_to_address(public_key):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    versioned_key_hash = b'\x00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_key_hash).digest()).digest()[:4]
    final_key = versioned_key_hash + checksum
    address = base58.b58encode(final_key)
    return address.decode('utf-8')

# Convert private key to WIF (uncompressed)
def private_key_to_wif_uncompressed(private_key):
    extended_key = b'\x80' + private_key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    wif = base58.b58encode(final_key)
    return wif.decode('utf-8')

# Convert private key to WIF (compressed)
def private_key_to_wif_compressed(private_key):
    extended_key = b'\x80' + private_key + b'\x01'  # 0x01 indicates compressed public key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    wif = base58.b58encode(final_key)
    return wif.decode('utf-8')

# Function to match addresses
def match_addresses(addresses, match_file, log_file, process_id, stats_queue):
    count = 0
    start_time = time.time()
    
    while True:
        try:
            private_key_bytes = generate_private_key()
            uncompressed_public_key = private_key_to_uncompressed_public_key(private_key_bytes)
            compressed_public_key = private_key_to_compressed_public_key(private_key_bytes)

            uncompressed_address = public_key_to_address(uncompressed_public_key)
            compressed_address = public_key_to_address(compressed_public_key)

            wif_uncompressed = private_key_to_wif_uncompressed(private_key_bytes)
            wif_compressed = private_key_to_wif_compressed(private_key_bytes)

            # Check if any address matches
            match_found = False
            if uncompressed_address in addresses:
                with open(match_file, 'a') as file:
                    file.write(f"{private_key_bytes.hex()}|{wif_uncompressed}|{uncompressed_address}\n")
                match_found = True
            
            if compressed_address in addresses:
                with open(match_file, 'a') as file:
                    file.write(f"{private_key_bytes.hex()}|{wif_compressed}|{compressed_address}\n")
                match_found = True
            
            if match_found:
                print(f"Process {process_id} - Match found. Exiting.")
                return
            
            count += 1
            if count % 1 == 0:  # Log every 1 keys
                elapsed_time = time.time() - start_time
                speed = count / elapsed_time
                stats_queue.put((process_id, count, elapsed_time, speed))
            
            # Write every key generated to the process-specific log file
            with open(f"/app/logs/process_log_{process_id}.log", 'a') as log:
                log.write(f"{private_key_bytes.hex()}|{wif_uncompressed}|{uncompressed_address}\n")
                log.write(f"{private_key_bytes.hex()}|{wif_compressed}|{compressed_address}\n")

        except Exception as e:
            print(f"\nProcess {process_id} - An error occurred: {e}")
            with open(f"/app/logs/process_log_{process_id}.log", 'a') as log:
                log.write(f"Process {process_id} - An error occurred: {e}\n")

def print_stats(stats_queue, num_processes):
    try:
        stats = {i+1: (0, 0, 0) for i in range(num_processes)}  # Initialize stats for each process
        while True:
            while not stats_queue.empty():
                process_id, count, elapsed_time, speed = stats_queue.get()
                stats[process_id] = (count, elapsed_time, speed)
            
            # Print all stats in a single line
            print("\033[H\033[J", end='')  # Clear the screen
            print(f"\n{'Process ID':<12}{'Keys Generated':<15}{'Time Elapsed (s)':<20}{'Speed (keys/s)':<15}")
            for pid, (count, elapsed_time, speed) in stats.items():
                print(f"Process {pid:<11}{count:<15}{elapsed_time:<20.2f}{speed:<15.2f}")
            
            # time.sleep(1)  # Sleep briefly to avoid busy waiting
    except KeyboardInterrupt:
        print("\nTerminating stats display.")

# Check addresses from file in parallel
def check_addresses_from_file(data_file, match_file, log_file, num_processes):
    try:
        with open(data_file, 'r') as file:
            addresses = [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"Failed to read addresses from file: {e}")
        return

    stats_queue = multiprocessing.Queue()
    processes = []
    for i in range(num_processes):
        p = multiprocessing.Process(target=match_addresses, args=(addresses, f"/app/results/{match_file}", log_file, i+1, stats_queue))
        p.start()
        processes.append(p)
    
    stats_printer = multiprocessing.Process(target=print_stats, args=(stats_queue, num_processes))
    stats_printer.start()

    for p in processes:
        p.join()
    
    stats_printer.terminate()

# Example usage
data_file = '/app/data.txt'  # Assuming data.txt is in the container
match_file = 'match.txt'  # Results file name
log_file = 'process_log'  # Base name for log files
num_processes = 10  # Set the number of processes (cores) you want to use
check_addresses_from_file(data_file, match_file, log_file, num_processes)
