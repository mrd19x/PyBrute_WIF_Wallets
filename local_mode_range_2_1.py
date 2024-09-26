import hashlib
import base58
import random
import time
import multiprocessing
import ecdsa
import csv
import os
from Crypto.Hash import SHA256, RIPEMD160

# SECP256k1 range constants
SECP256k1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140

# Hardcoded file paths
DATA_FILE = "data.txt"

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_private_key(start_hex, end_hex, temperature):
    """Generate a random private key within the specified hex range based on temperature."""
    start_range = int(start_hex, 16)
    end_range = int(end_hex, 16)

    # Hitung panjang karakter setelah '0x'
    hex_length = len(start_hex) - 2  # Subtracting 2 for '0x'
    
    # Membuat format awalan dengan nol
    zero_padding_length = 64 - hex_length  # Total length should be 64 characters
    zero_padding = '0' * zero_padding_length

    while True:
        # Generate random characters only for the part after '0x'
        random_suffix_length = 64 - len(zero_padding)  # Total length minus padding
        random_suffix = ''.join(random.choices('0123456789abcdef', k=random_suffix_length))

        # Generate the full private key hex
        private_key_hex = zero_padding + random_suffix

        # Convert to bytes
        private_key_bytes = bytes.fromhex(private_key_hex)

        # Check if the private key is of valid length
        if len(private_key_bytes) == 32 and 0 < int(private_key_hex, 16) < SECP256k1_ORDER:
            # print(f"Generated Private Key Hex: {private_key_hex}")  # Debug log
            return private_key_bytes
        else:
            print(f"Invalid Key: {private_key_hex}")  # Debug log

def private_key_to_wif(private_key):
    """Convert private key to Wallet Import Format (WIF)."""
    extended_key = b'\x80' + private_key  # Add network byte for mainnet (0x80)
    sha256_1 = hashlib.sha256(extended_key).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    checksum = sha256_2[:4]
    final_key = extended_key + checksum
    return base58.b58encode(final_key).decode('utf-8')

def private_key_to_uncompressed_public_key(private_key):
    """Convert private key to uncompressed public key."""
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()  # Uncompressed public key starts with 0x04

def public_key_to_address_p2pkh(public_key):
    """Convert public key to P2PKH Bitcoin address."""
    sha256_hash = SHA256.new(public_key).digest()
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    versioned_key_hash = b'\x00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_key_hash).digest()).digest()[:4]
    final_key = versioned_key_hash + checksum
    return base58.b58encode(final_key).decode('utf-8')

def save_generated_keys(process_id, keys):
    """Save the generated uncompressed private keys, WIFs, and addresses to a CSV file."""
    with open(f'generated_keys_uncompressed_{process_id}.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(keys)

def match_addresses_cpu(addresses, process_id, start_hex, end_hex, temperature, stats_queue):
    """Main function for each CPU to generate keys and check for matches."""
    count = 0
    start_time = time.time()

    # Initialize keys storage
    keys = []

    # Initialize CSV file for headers
    with open(f'generated_keys_uncompressed_{process_id}.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['PrivateKey (Hex)', 'WIF', 'Uncompressed Address'])  # Add header

    while True:
        try:
            # Generate random private key within specified range with temperature
            private_key_bytes = generate_private_key(start_hex, end_hex, temperature)

            # Convert private key to hex and WIF
            private_key_hex = private_key_bytes.hex()
            wif = private_key_to_wif(private_key_bytes)

            # Generate uncompressed public keys
            uncompressed_public_key = private_key_to_uncompressed_public_key(private_key_bytes)
            uncompressed_address = public_key_to_address_p2pkh(uncompressed_public_key)

            # Append the generated keys to the list
            keys.append([private_key_hex, wif, uncompressed_address])

            # Save generated keys every 10,000 keys
            count += 1
            if count % 10000 == 0:
                save_generated_keys(process_id, keys)
                print(f"Process {process_id} - Saved {count} keys to CSV.")
                keys = []  # Reset the storage for the next batch

            # Check if the generated address matches any in the provided list
            if uncompressed_address in addresses:
                print(f"Process {process_id} - Match found! Uncompressed Address: {uncompressed_address}, Hex: {private_key_hex}, WIF: {wif}")

            # Report statistics to the queue every 1000 keys
            if count % 1 == 0:
                elapsed_time = time.time() - start_time
                speed = count / elapsed_time
                stats_queue.put((process_id, count, elapsed_time, speed))

        except Exception as e:
            print(f"\nProcess {process_id} - An error occurred: {e}")

def print_stats(stats_queue, num_processes):
    """Print statistics for each process."""
    stats = {i + 1: (0, 0, 0) for i in range(num_processes)}
    print(f"\n{'Process ID':<12}{'Keys Generated':<15}{'Time Elapsed (s)':<20}{'Speed (keys/s)':<15}")
    
    while True:
        while not stats_queue.empty():
            process_id, count, elapsed_time, speed = stats_queue.get()
            stats[process_id] = (count, elapsed_time, speed)

        for pid in range(1, num_processes + 1):
            count, elapsed_time, speed = stats[pid]
            print(f"\033[{pid + 1};1HProcess {pid:<11}{count:<15}{elapsed_time:<20.2f}{speed:<15.2f}")

def check_addresses_from_file(num_processes, start_hex, end_hex, temperature):
    """Load addresses from file and start address matching process."""
    try:
        # Load addresses from file into RAM
        with open(DATA_FILE, 'r') as file:
            addresses = {line.strip() for line in file.readlines()}
    except Exception as e:
        print(f"Failed to read addresses from file: {e}")
        return

    stats_queue = multiprocessing.Queue()
    processes = []

    # Start the matching process
    for i in range(num_processes):
        p = multiprocessing.Process(target=match_addresses_cpu, args=(addresses, i + 1, start_hex, end_hex, temperature, stats_queue))
        p.start()
        processes.append(p)

    # Start the statistics printer process
    stats_printer = multiprocessing.Process(target=print_stats, args=(stats_queue, num_processes))
    stats_printer.start()

    # Wait for all processes to complete
    for p in processes:
        p.join()
    
    # Terminate the stats printer
    stats_printer.terminate()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Bitcoin Address Matcher with Range and Temperature')
    parser.add_argument('--start', type=str, required=True, help='Start of the range (hex format)')
    parser.add_argument('--end', type=str, required=True, help='End of the range (hex format)')
    parser.add_argument('--num_processes', type=int, default=4, help='Number of processes to spawn')
    parser.add_argument('--temperature', type=int, default=1, help='Temperature for randomness adjustment')
    args = parser.parse_args()

    clear_screen()  # Clear the console before starting

    start_hex = args.start
    end_hex = args.end
    temperature = args.temperature

    check_addresses_from_file(args.num_processes, start_hex, end_hex, temperature)
