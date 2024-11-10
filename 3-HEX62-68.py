import hashlib
import base58
import time
import concurrent.futures
import threading

def sha256(data):
    """Return the SHA-256 hash of the input data."""
    return hashlib.sha256(data).digest()

def ripemd160(data):
    """Return the RIPEMD-160 hash of the input data."""
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def hex_to_wif(hex_key, compressed=True):
    """Convert a hexadecimal private key to WIF format."""
    extended_key = bytearray.fromhex('80' + hex_key)
    if compressed:
        extended_key.append(0x01)
    checksum = sha256(sha256(extended_key))[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')

def pubkey_to_address(pubkey):
    """Generate a Bitcoin address from the public key."""
    sha256_hash = sha256(pubkey)
    ripemd160_hash = ripemd160(sha256_hash)
    extended_ripemd160 = b'\x00' + ripemd160_hash
    checksum = sha256(sha256(extended_ripemd160))[:4]
    address = base58.b58encode(extended_ripemd160 + checksum)
    return address.decode('utf-8')

def process_range(start_int, end_int, address_target, start_time, lock, thread_id):
    """Process a range of hex keys and check for target address."""
    addresses_processed = 0
    for i in range(start_int, end_int + 1):
        hex_key = hex(i)[2:].zfill(64)  # Format to the correct length
        # Generate WIF (compressed and uncompressed)
        wif_compressed = hex_to_wif(hex_key, compressed=True)
        wif_uncompressed = hex_to_wif(hex_key, compressed=False)

        # Generate public key and address (simplified, real implementation would use ECC)
        pubkey_compressed = b'\x03' + bytes.fromhex(hex_key)[:32]  # Placeholder for compressed pubkey
        pubkey_uncompressed = b'\x04' + bytes.fromhex(hex_key)  # Placeholder for uncompressed pubkey

        # Generate addresses from public keys
        address_compressed = pubkey_to_address(pubkey_compressed)
        address_uncompressed = pubkey_to_address(pubkey_uncompressed)

        if address_compressed == address_target:
            with lock:
                print(f"\nThread {thread_id} - Address ditemukan! WIF Compressed: {wif_compressed}, Address: {address_compressed}")
                print(f"Waktu yang dibutuhkan: {time.time() - start_time:.2f} detik")
            return

        if address_uncompressed == address_target:
            with lock:
                print(f"\nThread {thread_id} - Address ditemukan! WIF Uncompressed: {wif_uncompressed}, Address: {address_uncompressed}")
                print(f"Waktu yang dibutuhkan: {time.time() - start_time:.2f} detik")
            return
        
        addresses_processed += 1

        # Every 1000 addresses processed, update the console with progress and speed
        if addresses_processed % 1000 == 0:
            elapsed_time = time.time() - start_time
            processing_speed = addresses_processed / elapsed_time if elapsed_time > 0 else 0

            with lock:
                # Print status on a specific line for each thread (without overwriting other threads' output)
                print(f"\rThread {thread_id} - Hex: {hex_key} | Kecepatan: {processing_speed:.2f} address/detik", end='', flush=True)

def main():
    start_hex = input("Masukkan nilai start_hex (62-68 karakter): ").strip()
    end_hex = input("Masukkan nilai end_hex (62-68 karakter): ").strip()
    address_target = input("Masukkan target address: ").strip()
    core_cpu = int(input("Masukkan jumlah core CPU yang digunakan: ").strip())

    # Convert hex strings to integers for iteration
    start_int = int(start_hex, 16)
    end_int = int(end_hex, 16)

    # Calculate the range of addresses to be processed
    total_range = end_int - start_int + 1
    chunk_size = total_range // core_cpu  # Split the range among the cores

    # Start processing
    start_time = time.time()

    # Lock to ensure only one thread prints to console at a time
    lock = threading.Lock()

    # Prepare the initial empty lines in the console
    for i in range(core_cpu):
        print(f"Thread {i+1} - Hex: ", end='', flush=True)  # Print empty lines for each core

    # Use ThreadPoolExecutor to process the ranges in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=core_cpu) as executor:
        futures = []
        for i in range(core_cpu):
            # Calculate the range for each thread
            thread_start = start_int + i * chunk_size
            # Ensure the last thread gets the remaining addresses
            thread_end = start_int + (i + 1) * chunk_size - 1 if i < core_cpu - 1 else end_int
            futures.append(executor.submit(process_range, thread_start, thread_end, address_target, start_time, lock, i + 1))

        # Wait for all threads to finish
        for future in concurrent.futures.as_completed(futures):
            future.result()  # This ensures that the threads are executed and finished

    print("\nProses konversi selesai tanpa menemukan address yang cocok.")

if __name__ == "__main__":
    main()
