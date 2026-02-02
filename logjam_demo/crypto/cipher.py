"""
Simple encryption/decryption for demo purposes.

- encrypt(): XOR encryption (symmetric, deterministic for demo)
- decrypt(): XOR decryption (same as encryption for XOR cipher)

Uses XOR encryption for simplicity. In production TLS, AES or similar symmetric ciphers would be used.
"""

def encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data using XOR cipher (simple and deterministic for demo).
    
    For demo purposes, uses XOR which is simple and deterministic.
    In production, would use AES or similar.
    
    Args:
        data: Plaintext bytes to encrypt
        key: Encryption key bytes
        
    Returns:
        bytes: Encrypted ciphertext
    """
    if not key:
        raise ValueError("Encryption key cannot be empty")
    
    # Simple XOR encryption (for demo)
    # Repeat key if needed to match data length
    key_repeated = (key * ((len(data) // len(key)) + 1))[:len(data)]
    ciphertext = bytes(a ^ b for a, b in zip(data, key_repeated))
    
    return ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    Decrypt data using XOR cipher (same as encryption for XOR).
    
    Args:
        data: Ciphertext bytes to decrypt
        key: Decryption key bytes
        
    Returns:
        bytes: Decrypted plaintext
    """
    # XOR is symmetric, so decryption is the same as encryption
    return encrypt(data, key)

