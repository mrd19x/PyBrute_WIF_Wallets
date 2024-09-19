import hashlib
import base58
import argparse

def private_key_to_wif(private_key_hex, compressed=True):
    """
    Convert a private key in hexadecimal format to WIF (Wallet Import Format).
    
    :param private_key_hex: Private key in hexadecimal string format
    :param compressed: Whether to use compressed WIF format (default is True)
    :return: WIF (Wallet Import Format) string
    """
    # Convert the hexadecimal private key to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # Add prefix 0x80 for mainnet
    extended_key = b'\x80' + private_key_bytes
    
    # If compressed, add 0x01 to the end
    if compressed:
        extended_key += b'\x01'
    
    # Double SHA-256 hash of the extended key
    sha256_1 = hashlib.sha256(extended_key).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    
    # Add the first 4 bytes of the second SHA-256 hash as a checksum
    checksum = sha256_2[:4]
    
    # Append the checksum to the extended key
    final_key = extended_key + checksum
    
    # Encode the final key in Base58
    wif = base58.b58encode(final_key).decode('utf-8')
    
    return wif

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Private Key to WIF (Wallet Import Format)")
    parser.add_argument("private_key", type=str, help="Private key in hexadecimal format")
    parser.add_argument("--compressed", action="store_true", help="Use compressed WIF format")
    
    args = parser.parse_args()
    
    wif = private_key_to_wif(args.private_key, args.compressed)
    print(f"WIF: {wif}")
