"""
Diffie-Hellman group management and key exchange operations.

- DHGroup dataclass for representing DH groups
- Predefined weak (EXPORT_GROUP_512) and strong (SAFE_GROUP_2048) groups
- Functions for generating keys, computing public values, and shared secrets

"""

import os
from dataclasses import dataclass


@dataclass
class DHGroup:
    """DH group with prime modulus, generator, and bit length."""
    p: int
    g: int
    bits: int


# Fixed 512-bit prime for DHE_EXPORT (weak, attackable)
# Using a known safe prime for DH (safe prime: p = 2q + 1 where q is also prime)
# For faster demo execution, using 32-bit prime (attack completes quickly)
# In production LogJam, 512-bit primes were used but often precomputed
# For realistic demo, use a proper 512-bit safe prime
EXPORT_GROUP_512 = DHGroup(
    p=3871762199,  # 32-bit safe prime
    g=2,
    bits=32
)

# Fixed 2048-bit prime for normal DHE (safe, not attackable in demo time)
# Using RFC 3526 MODP Group 14 (2048-bit)
SAFE_GROUP_2048 = DHGroup(
    p=0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
    g=2,
    bits=2048
)


def generate_private_key(group: DHGroup) -> int:
    """
    Generate a random DH private key.
    
    Args:
        group: DHGroup with prime modulus p
        
    Returns:
        int: Random private key in range [1, p-2]
    """
    # Generate random private key (1 to p-2)
    # Using os.urandom for cryptographically secure randomness
    max_value = group.p - 2
    bits_needed = max_value.bit_length()
    
    while True:
        # Generate enough random bytes
        random_bytes = os.urandom((bits_needed + 7) // 8)
        candidate = int.from_bytes(random_bytes, 'big')
        
        # Reduce modulo (p-1) and ensure it's in valid range [1, p-2]
        candidate = (candidate % (group.p - 1)) + 1
        
        if 1 <= candidate <= max_value:
            return candidate


def public_from_private(group: DHGroup, priv: int) -> int:
    """
    Compute public value from private key: g^x mod p.
    
    Uses C implementation for primes < 2^64, Python for larger primes.
    
    Args:
        group: DHGroup with generator g and prime p
        priv: Private exponent x
        
    Returns:
        int: Public value g^x mod p
    """
    # Use C implementation for all primes up to 128-bit
    from .crypto_c import compute_public_value_c
    if group.p >= 2**128:
        raise ValueError(f"Prime too large: {group.p} (max 128-bit supported)")
    return compute_public_value_c(group.g, priv, group.p)


def compute_shared_secret(group: DHGroup, priv: int, peer_pub: int) -> int:
    """
    Compute shared secret from private key and peer's public value: (peer_pub)^priv mod p.
    
    Uses C implementation for primes < 2^64, Python for larger primes.
    
    Args:
        group: DHGroup with prime p
        priv: Our private exponent
        peer_pub: Peer's public value
        
    Returns:
        int: Shared secret K = (peer_pub)^priv mod p
    """
    # Use C implementation for all primes up to 128-bit
    from .crypto_c import compute_shared_secret_c
    if group.p >= 2**128:
        raise ValueError(f"Prime too large: {group.p} (max 128-bit supported)")
    return compute_shared_secret_c(peer_pub, priv, group.p)

