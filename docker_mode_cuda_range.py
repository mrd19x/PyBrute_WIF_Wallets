import os
import hashlib
import base58
import argparse
import random
import time
import multiprocessing
import ecdsa
from Crypto.Hash import SHA256, RIPEMD160
from numba import cuda, uint8, uint32

# SECP256k1 range constants
SECP256k1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140

# Helper functions
def convertbits(data, frombits, tobits, pad=True):
    """Convert a bit stream to another bit stream."""
    acc = 0
    bits = 0
    result = []
    max_acc = (1 << tobits) - 1

    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & ((1 << tobits) - 1))

    if pad:
        if bits > 0:
            result.append((acc << (tobits - bits)) & ((1 << tobits) - 1))
    elif bits >= frombits or ((acc << (tobits - bits)) & ((1 << tobits) - 1)) != 0:
        raise ValueError('Input bit stream is not properly padded.')

    return result

def bech32_encode(hrp, data):
    """Encode a Bech32 string."""
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    
    def polymod(values):
        """Compute the checksum polynomial."""
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a146e1b]
        chk = 1
        for value in values:
            b = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ value
            for i in range(5):
                if (b >> i) & 1:
                    chk ^= GEN[i]
        return chk

    def bech32_hrp_expand(hrp):
        """Expand human-readable part."""
        hrp = [ord(x) >> 5 for x in hrp]
        hrp += [0]
        hrp += [ord(x) & 31 for x in hrp]
        return hrp

    def encode_bech32(data, hrp):
        """Encode Bech32 values into human-readable form."""
        data = list(data)
        chk = polymod(bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0])
        chk = ((chk >> 25) ^ 1) & 0x3ffffff
        return hrp + '1' + ''.join(alphabet[d] for d in data + [int(x) for x in f'{chk:06b}'])

    if len(data) < 6 or len(data) > 90:
        raise ValueError('Data length should be between 6 and 90 characters.')

    return encode_bech32(data, hrp)

def generate_private_key(start_range, end_range):
    """Generate a private key within the given range."""
    private_key = random.randint(start_range, end_range)
    if not (0 < private_key < SECP256k1_ORDER):
        raise ValueError(f"Private key {private_key} is out of range.")
    return int.to_bytes(private_key, 32, byteorder='big')

def private_key_to_uncompressed_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # Prefix for uncompressed
    return public_key

def private_key_to_compressed_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[63] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    return public_key

def public_key_to_address_p2pkh(public_key):
    sha256_hash = SHA256.new(public_key).digest()
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    versioned_key_hash = b'\x00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_key_hash).digest()).digest()[:4]
    final_key = versioned_key_hash + checksum
    address = base58.b58encode(final_key)
    return address.decode('utf-8')

def public_key_to_address_p2sh(public_key):
    sha256_hash = SHA256.new(public_key).digest()
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    script_pubkey = b'\x00\x14' + public_key_hash  # P2SH script (OP_HASH160 <pubKeyHash> OP_EQUAL)
    sha256_script = hashlib.sha256(script_pubkey).digest()
    ripemd160_script = RIPEMD160.new(sha256_script).digest()
    prefix = b'\x05'  # Mainnet prefix for P2SH
    versioned_key_hash = prefix + ripemd160_script
    checksum = hashlib.sha256(hashlib.sha256(versioned_key_hash).digest()).digest()[:4]
    final_key = versioned_key_hash + checksum
    address = base58.b58encode(final_key)
    return address.decode('utf-8')

def public_key_to_address_bech32(public_key):
    sha256_hash = SHA256.new(public_key).digest()
    converted_key = convertbits(sha256_hash, 8, 5)  # Convert to 5-bit array
    return bech32_encode("bc", [0] + converted_key)  # Mainnet prefix is "bc"

def private_key_to_wif_uncompressed(private_key):
    extended_key = b'\x80' + private_key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    wif = base58.b58encode(final_key)
    return wif.decode('utf-8')

def private_key_to_wif_compressed(private_key):
    extended_key = b'\x80' + private_key + b'\x01'  # 0x01 indicates compressed public key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    wif = base58.b58encode(final_key)
    return wif.decode('utf-8')

def match_addresses_gpu(addresses, match_file, log_file_compressed, log_file_uncompressed, process_id, stats_queue, start_range, end_range):
    count = 0
    start_time = time.time()
    
    while True:
        try:
            private_key_bytes = generate_private_key(start_range, end_range)
            uncompressed_public_key = private_key_to_uncompressed_public_key(private_key_bytes)
            compressed_public_key = private_key_to_compressed_public_key(private_key_bytes)

            uncompressed_address = public_key_to_address_p2pkh(uncompressed_public_key)
            compressed_address = public_key_to_address_p2pkh(compressed_public_key)

            wif_uncompressed = private_key_to_wif_uncompressed(private_key_bytes)
            wif_compressed = private_key_to_wif_compressed(private_key_bytes)

            # Check if any address matches
            match_found = False
            if uncompressed_address in addresses:
                with open(match_file, 'a') as file:
                    file.write(f"{wif_uncompressed}|{uncompressed_address}\n")
                match_found = True
            
            if compressed_address in addresses:
                with open(match_file, 'a') as file:
                    file.write(f"{wif_compressed}|{compressed_address}\n")
                match_found = True
            
            if match_found:
                print(f"Process {process_id} - Match found. Exiting.")
                return
            
            count += 1
            if count % 1 == 0:
                elapsed_time = time.time() - start_time
                speed = count / elapsed_time
                stats_queue.put((process_id, count, elapsed_time, speed))
            
            with open(f"{log_file_uncompressed}_{process_id}.log", 'a') as log_uncompressed:
                log_uncompressed.write(f"{wif_uncompressed}|{uncompressed_address}\n")
            with open(f"{log_file_compressed}_{process_id}.log", 'a') as log_compressed:
                log_compressed.write(f"{wif_compressed}|{compressed_address}\n")

        except Exception as e:
            print(f"\nProcess {process_id} - An error occurred: {e}")
            with open(f"{log_file_uncompressed}_{process_id}.log", 'a') as log_uncompressed:
                log_uncompressed.write(f"Process {process_id} - An error occurred: {e}\n")
            with open(f"{log_file_compressed}_{process_id}.log", 'a') as log_compressed:
                log_compressed.write(f"Process {process_id} - An error occurred: {e}\n")

def print_stats(stats_queue, num_processes):
    try:
        stats = {i+1: (0, 0, 0) for i in range(num_processes)}
        while True:
            while not stats_queue.empty():
                process_id, count, elapsed_time, speed = stats_queue.get()
                stats[process_id] = (count, elapsed_time, speed)
            
            print("\033[H\033[J", end='')
            print(f"\n{'Process ID':<12}{'Keys Generated':<15}{'Time Elapsed (s)':<20}{'Speed (keys/s)':<15}")
            for pid, (count, elapsed_time, speed) in stats.items():
                print(f"Process {pid:<11}{count:<15}{elapsed_time:<20.2f}{speed:<15.2f}")
            
            # time.sleep(1)
    except KeyboardInterrupt:
        print("\nTerminating stats display.")

def check_addresses_from_file(data_file, match_file, log_file_compressed, log_file_uncompressed, num_processes, start_range, end_range):
    try:
        with open(data_file, 'r') as file:
            addresses = [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"Failed to read addresses from file: {e}")
        return

    stats_queue = multiprocessing.Queue()
    processes = []
    if start_range is not None and end_range is not None:
        range_size = (end_range - start_range + 1) // num_processes
        for i in range(num_processes):
            proc_start_range = start_range + i * range_size
            proc_end_range = start_range + (i + 1) * range_size - 1
            if i == num_processes - 1:
                proc_end_range = end_range
            p = multiprocessing.Process(target=match_addresses_gpu, args=(addresses, match_file, log_file_compressed, log_file_uncompressed, i+1, stats_queue, proc_start_range, proc_end_range))
            p.start()
            processes.append(p)
    else:
        # Random search
        for i in range(num_processes):
            p = multiprocessing.Process(target=match_addresses_gpu, args=(addresses, match_file, log_file_compressed, log_file_uncompressed, i+1, stats_queue, 0, SECP256k1_ORDER))
            p.start()
            processes.append(p)

    stats_printer = multiprocessing.Process(target=print_stats, args=(stats_queue, num_processes))
    stats_printer.start()

    for p in processes:
        p.join()
    
    stats_printer.terminate()

# Parse command-line arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Bitcoin Address Matcher with Range')
    parser.add_argument('--start', type=str, help='Start of the keyspace range in hexadecimal (e.g., 0x20000000000000000)')
    parser.add_argument('--end', type=str, help='End of the keyspace range in hexadecimal (e.g., 0x3ffffffffffffffff)')
    parser.add_argument('--num_processes', type=int, required=True, help='Number of processes to use')
    args = parser.parse_args()

    start_range = int(args.start, 16) if args.start else None
    end_range = int(args.end, 16) if args.end else None

    data_file = 'data.txt'
    match_file = 'match.txt'
    log_file_compressed = 'process_log_compressed'
    log_file_uncompressed = 'process_log_uncompressed'
    num_processes = args.num_processes

    check_addresses_from_file(data_file, match_file, log_file_compressed, log_file_uncompressed, num_processes, start_range, end_range)
