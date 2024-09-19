import base58
import hashlib
import ecdsa
from Crypto.Hash import SHA256, RIPEMD160
import argparse

def wif_to_private_key(wif):
    """Convert WIF to private key."""
    decoded = base58.b58decode(wif)
    
    # Remove the 0x80 prefix
    extended_key = decoded[1:-4]
    
    # Check if the last byte is 0x01 (compressed) and remove it if present
    if len(extended_key) == 33:
        private_key_bytes = extended_key[:-1]
    else:
        private_key_bytes = extended_key
    
    return private_key_bytes

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
        hrp = [ord(x) for x in hrp]
        hrp += [0]
        hrp += [x & 31 for x in hrp]
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

def main():
    parser = argparse.ArgumentParser(description='Convert WIF to Bitcoin Addresses')
    parser.add_argument('wif', type=str, help='Wallet Import Format (WIF) key')
    args = parser.parse_args()
    
    wif = args.wif
    private_key_bytes = wif_to_private_key(wif)
    
    uncompressed_public_key = private_key_to_uncompressed_public_key(private_key_bytes)
    compressed_public_key = private_key_to_compressed_public_key(private_key_bytes)
    
    # Generate addresses
    p2pkh_uncompressed_address = public_key_to_address_p2pkh(uncompressed_public_key)
    p2pkh_compressed_address = public_key_to_address_p2pkh(compressed_public_key)
    p2sh_address = public_key_to_address_p2sh(uncompressed_public_key)  # P2SH generally uses uncompressed key
    bech32_address = public_key_to_address_bech32(uncompressed_public_key)  # Bech32 generally uses uncompressed key

    print(f"Private Key (hex): {private_key_bytes.hex()}")
    print(f"Uncompressed Address (P2PKH): {p2pkh_uncompressed_address}")
    print(f"Compressed Address (P2PKH): {p2pkh_compressed_address}")
    print(f"P2SH Address: {p2sh_address}")
    print(f"Bech32 Address: {bech32_address}")

if __name__ == "__main__":
    main()
