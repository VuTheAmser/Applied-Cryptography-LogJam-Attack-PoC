"""
Key derivation functions for master secret and session keys.

- derive_master_secret(): Derive master secret from DH shared secret and randoms
- derive_session_keys(): Derive session keys (encryption, decryption, MAC) from master secret

Uses simplified PRF based on HMAC-SHA256 (not full TLS PRF for demo simplicity).
"""

import hmac
import hashlib


def derive_master_secret(cr: bytes, sr: bytes, shared_secret: int) -> bytes:
    """
    Derive master secret from client random, server random, and shared secret.
    
    Uses a simplified PRF based on HMAC-SHA256.
    
    Args:
        cr: Client random (32 bytes)
        sr: Server random (32 bytes)
        shared_secret: DH shared secret K (integer)
        
    Returns:
        bytes: Master secret (48 bytes typical)
    """
    # Convert shared secret to bytes (big-endian, enough bytes to represent it)
    k_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    # Simplified PRF: HMAC-SHA256(key=shared_secret, data=cr||sr)
    # In real TLS, this is more complex, but for demo we simplify
    data = cr + sr
    master_secret = hmac.new(k_bytes, data, hashlib.sha256).digest()
    
    # Expand to 48 bytes (TLS master secret size) using HKDF-like expansion
    if len(master_secret) < 48:
        # Use HKDF expand if needed
        output = bytearray(master_secret)
        counter = 1
        while len(output) < 48:
            data_i = data + bytes([counter])
            additional = hmac.new(k_bytes, data_i, hashlib.sha256).digest()
            output.extend(additional)
            counter += 1
        master_secret = bytes(output[:48])
    
    return master_secret[:48]


def derive_session_keys(master_secret: bytes) -> dict:
    """
    Derive session keys (encryption, decryption, MAC) from master secret.
    
    Uses simplified key derivation based on HMAC-SHA256.
    
    Args:
        master_secret: Master secret bytes (typically 48 bytes)
        
    Returns:
        dict: Dictionary with keys:
            - 'encryption': bytes - Key for encrypting data
            - 'decryption': bytes - Key for decrypting data  
            - 'mac': bytes - MAC key (if needed)
    """
    # In real TLS, keys are derived using a more complex PRF
    # For demo, we use simple HMAC-based derivation
    
    # Derive encryption key (16 bytes for AES-128, or 32 for AES-256)
    # For demo, we'll use 16 bytes (AES-128 equivalent)
    encryption_label = b"encryption_key"
    encryption_key = hmac.new(master_secret, encryption_label, hashlib.sha256).digest()[:16]
    
    # Derive decryption key (same size)
    decryption_label = b"decryption_key"
    decryption_key = hmac.new(master_secret, decryption_label, hashlib.sha256).digest()[:16]
    
    # Derive MAC key (16 bytes)
    mac_label = b"mac_key"
    mac_key = hmac.new(master_secret, mac_label, hashlib.sha256).digest()[:16]
    
    return {
        'encryption': encryption_key,
        'decryption': decryption_key,
        'mac': mac_key
    }

