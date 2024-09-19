import hashlib
import base58
import argparse
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import SHA256, RIPEMD160

# Helper functions
def private_key_to_wif_uncompressed(private_key):
    extended_key = b'\x80' + private_key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    return base58.b58encode(final_key).decode('utf-8')

def private_key_to_wif_compressed(private_key):
    extended_key = b'\x80' + private_key + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    return base58.b58encode(final_key).decode('utf-8')

def private_key_to_uncompressed_public_key(private_key):
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()
    return public_key

def private_key_to_compressed_public_key(private_key):
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
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
    return base58.b58encode(final_key).decode('utf-8')

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
    return base58.b58encode(final_key).decode('utf-8')

def process_private_keys(private_key_file, output_file):
    with open(private_key_file, 'r') as f:
        private_keys = [line.strip() for line in f]

    with open(output_file, 'w') as out_f:
        for hex_key in private_keys:
            private_key_bytes = bytes.fromhex(hex_key)
            
            # Generate WIFs
            wif_uncompressed = private_key_to_wif_uncompressed(private_key_bytes)
            wif_compressed = private_key_to_wif_compressed(private_key_bytes)

            # Generate public keys
            uncompressed_public_key = private_key_to_uncompressed_public_key(private_key_bytes)
            compressed_public_key = private_key_to_compressed_public_key(private_key_bytes)

            # Generate addresses
            uncompressed_address = public_key_to_address_p2pkh(uncompressed_public_key)
            compressed_address = public_key_to_address_p2pkh(compressed_public_key)
            p2sh_address = public_key_to_address_p2sh(compressed_public_key)

            # Write to output file
            out_f.write(f"Private Key (hex): {hex_key}\n")
            out_f.write(f"WIF Uncompressed: {wif_uncompressed}\n")
            out_f.write(f"WIF Compressed: {wif_compressed}\n")
            out_f.write(f"P2PKH Uncompressed Address: {uncompressed_address}\n")
            out_f.write(f"P2PKH Compressed Address: {compressed_address}\n")
            out_f.write(f"P2SH Address: {p2sh_address}\n")
            out_f.write("\n")  # Blank line for separation

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Private Key to Address/WIF Compiler')
    parser.add_argument('--source', type=str, required=True, help='Input file containing private keys in hex format')
    parser.add_argument('--output', type=str, default='output.txt', help='Output file to store results')
    args = parser.parse_args()

    process_private_keys(args.source, args.output)
