import hashlib
import base58
import time

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
    # Step 1: Add network byte (0x80 for mainnet)
    extended_key = bytearray.fromhex('80' + hex_key)

    # Step 2: Append compressed flag if needed
    if compressed:
        extended_key.append(0x01)

    # Step 3: Perform double SHA-256 hashing for checksum
    checksum = sha256(sha256(extended_key))[:4]

    # Step 4: Create the final WIF
    wif = base58.b58encode(extended_key + checksum)

    return wif.decode('utf-8')

def pubkey_to_address(pubkey):
    """Generate a Bitcoin address from the public key."""
    # Step 1: Perform SHA-256 hashing on the public key
    sha256_hash = sha256(pubkey)

    # Step 2: Perform RIPEMD-160 hashing on the SHA-256 hash
    ripemd160_hash = ripemd160(sha256_hash)

    # Step 3: Add network byte (0x00 for mainnet addresses)
    extended_ripemd160 = b'\x00' + ripemd160_hash

    # Step 4: Perform double SHA-256 hashing for checksum
    checksum = sha256(sha256(extended_ripemd160))[:4]

    # Step 5: Create the final address
    address = base58.b58encode(extended_ripemd160 + checksum)

    return address.decode('utf-8')

def main():
    start_hex = input("Masukkan nilai start_hex (62-68 karakter): ").strip()
    end_hex = input("Masukkan nilai end_hex (62-68 karakter): ").strip()
    address_target = input("Masukkan target address: ").strip()

    # Convert hex strings to integers for iteration
    start_int = int(start_hex, 16)
    end_int = int(end_hex, 16)

    # Calculate the range of addresses to be processed
    address_range = end_int - start_int + 1

    # Print out the details for the user
    print(f"\nMemulai proses konversi...\n")
    print(f"Total address dalam rentang: {address_range}")
    
    # Start processing addresses
    start_time = time.time()

    # Iterate through the range of hex values
    for i in range(start_int, end_int + 1):
        hex_key = hex(i)[2:].zfill(len(start_hex))  # Keep the original length
        # Generate WIF (compressed and uncompressed)
        wif_compressed = hex_to_wif(hex_key, compressed=True)
        wif_uncompressed = hex_to_wif(hex_key, compressed=False)

        # Generate public key and address (simplified, real implementation would use ECC)
        pubkey_compressed = b'\x03' + bytes.fromhex(hex_key)[:32]  # Placeholder for compressed pubkey
        pubkey_uncompressed = b'\x04' + bytes.fromhex(hex_key)  # Placeholder for uncompressed pubkey

        # Generate addresses from public keys
        address_compressed = pubkey_to_address(pubkey_compressed)
        address_uncompressed = pubkey_to_address(pubkey_uncompressed)

        # Check if either address matches the target address
        if address_compressed == address_target:
            print(f"\nAddress ditemukan! WIF Compressed: {wif_compressed}, Address: {address_compressed}")
            print(f"Waktu yang dibutuhkan: {time.time() - start_time:.2f} detik")
            return  # Stop the loop when target address is found

        if address_uncompressed == address_target:
            print(f"\nAddress ditemukan! WIF Uncompressed: {wif_uncompressed}, Address: {address_uncompressed}")
            print(f"Waktu yang dibutuhkan: {time.time() - start_time:.2f} detik")
            return  # Stop the loop when target address is found

        # Display current processing speed every 1000 addresses
        if i % 1000 == 0:
            elapsed_time = time.time() - start_time
            addresses_processed = i - start_int + 1
            processing_speed = addresses_processed / elapsed_time if elapsed_time > 0 else 0
            
            # Print the update on the same line
            print(f"\rHex: {hex_key} | Kecepatan: {processing_speed:.2f} address/detik", end='')

    print("\nProses konversi selesai tanpa menemukan address yang cocok.")

if __name__ == "__main__":
    main()
