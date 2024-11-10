import hashlib
import base58
import time
import cupy as cp  # Import CuPy untuk komputasi di GPU
import threading

def sha256_gpu(data):
    """Return the SHA-256 hash of the input data using GPU (CuPy)."""
    # Convert the data into a CuPy array
    data_array = cp.array(data)
    # Compute SHA256 on the GPU (this can be optimized, but using hashlib for simplicity)
    return hashlib.sha256(data_array).digest()  # Use standard hashlib (CuPy doesn't directly support SHA-256)

def ripemd160_gpu(data):
    """Return the RIPEMD-160 hash using GPU."""
    # For the sake of illustration, using CPU for RIPEMD-160 as there's no native CuPy support
    h = hashlib.new('ripemd160')
    h.update(cp.asnumpy(data))  # Convert CuPy array back to NumPy for hashing
    return h.digest()

def pubkey_to_address_gpu(pubkey):
    """Generate a Bitcoin address from the public key using GPU."""
    sha256_hash = sha256_gpu(pubkey)
    ripemd160_hash = ripemd160_gpu(sha256_hash)
    extended_ripemd160 = b'\x00' + ripemd160_hash
    checksum = sha256_gpu(extended_ripemd160)[:4]
    address = base58.b58encode(extended_ripemd160 + checksum)
    return address.decode('utf-8')

def process_range_gpu(start_int, end_int, address_target, start_time, lock, thread_id):
    """Process a range of hex keys on the GPU and check for the target address."""
    addresses_processed = 0
    for i in range(start_int, end_int + 1):
        hex_key = hex(i)[2:].zfill(64)  # Format to the correct length
        pubkey_compressed = b'\x03' + bytes.fromhex(hex_key)[:32]
        pubkey_uncompressed = b'\x04' + bytes.fromhex(hex_key)
        
        # Generate addresses from public keys using GPU
        address_compressed = pubkey_to_address_gpu(pubkey_compressed)
        address_uncompressed = pubkey_to_address_gpu(pubkey_uncompressed)

        if address_compressed == address_target:
            with lock:
                print(f"\nThread {thread_id} - Address ditemukan! WIF Compressed: {address_compressed}")
                print(f"Waktu yang dibutuhkan: {time.time() - start_time:.2f} detik")
            return

        if address_uncompressed == address_target:
            with lock:
                print(f"\nThread {thread_id} - Address ditemukan! WIF Uncompressed: {address_uncompressed}")
                print(f"Waktu yang dibutuhkan: {time.time() - start_time:.2f} detik")
            return

        addresses_processed += 1

        # Update progress periodically
        if addresses_processed % 1000 == 0:
            elapsed_time = time.time() - start_time
            processing_speed = addresses_processed / elapsed_time if elapsed_time > 0 else 0
            with lock:
                print(f"\rThread {thread_id} - Kecepatan: {processing_speed:.2f} address/detik", end='', flush=True)

def main():
    start_hex = input("Masukkan nilai start_hex (62-68 karakter): ").strip()
    end_hex = input("Masukkan nilai end_hex (62-68 karakter): ").strip()
    address_target = input("Masukkan target address: ").strip()

    # Menggunakan GPU otomatis
    print(f"\nMenggunakan GPU untuk perhitungan. Deteksi alamat dimulai...\n")

    start_int = int(start_hex, 16)
    end_int = int(end_hex, 16)

    # Menggunakan kunci pembagian berdasarkan jumlah thread
    total_range = end_int - start_int + 1
    chunk_size = total_range // 2  # 2 thread sebagai contoh

    start_time = time.time()

    lock = threading.Lock()

    # Start threads
    with threading.ThreadPoolExecutor(max_workers=2) as executor:
        futures = []
        for i in range(2):  # 2 threads, bisa ditambah sesuai kebutuhan
            thread_start = start_int + i * chunk_size
            thread_end = start_int + (i + 1) * chunk_size - 1 if i < 2 - 1 else end_int
            futures.append(executor.submit(process_range_gpu, thread_start, thread_end, address_target, start_time, lock, i + 1))

        for future in futures:
            future.result()

    print("\nProses konversi selesai tanpa menemukan address yang cocok.")

if __name__ == "__main__":
    main()
