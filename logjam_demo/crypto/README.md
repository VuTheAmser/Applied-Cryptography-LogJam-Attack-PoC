# Crypto Module

This module contains all cryptographic primitives used in the LogJam attack demonstration.

## Structure

```
crypto/
├── README.md           # This file
├── dh.py              # Diffie-Hellman key exchange
├── dlog_attack.py     # Discrete logarithm attack
├── kdf.py             # Key derivation functions
├── cipher.py          # Encryption/decryption
├── crypto_c.py        # Python wrapper for C functions
└── native/            # C implementation (for performance)
    ├── c_dh.c         # C crypto implementation
    ├── c_dh.h         # C header file
    ├── c_dh.so        # Compiled shared library
    └── build.sh       # Build script
```

## Python Modules

### `dh.py` - Diffie-Hellman Key Exchange
- **DHGroup**: Dataclass representing a DH group (prime `p`, generator `g`, bit length)
- **EXPORT_GROUP_512**: Weak 36-bit group for demo (fast to break)
- **SAFE_GROUP_2048**: Strong 2048-bit group (not breakable in demo time)
- **generate_private_key()**: Generate random DH private key
- **public_from_private()**: Compute public value g^x mod p
- **compute_shared_secret()**: Compute shared secret (peer_pub)^priv mod p

### `dlog_attack.py` - Discrete Logarithm Attack
- **baby_step_giant_step()**: Solve g^x = h (mod p) for x
- **break_dh_key()**: Break DH key exchange by recovering shared secret

### `kdf.py` - Key Derivation Functions
- **derive_master_secret()**: Derive master secret from client/server randoms and shared secret
- **derive_session_keys()**: Derive session keys (encryption, decryption, MAC) from master secret

### `cipher.py` - Encryption/Decryption
- **encrypt()**: XOR encryption (simple for demo)
- **decrypt()**: XOR decryption (same as encryption for XOR)

### `crypto_c.py` - C Library Wrapper
- Python wrapper using `ctypes` to call C functions
- Provides: `mod_pow()`, `compute_public_value_c()`, `compute_shared_secret_c()`, `baby_step_giant_step_c()`

## C Implementation (`native/`)

The C implementation provides optimized performance for:
- Modular exponentiation (fast power computation)
- Diffie-Hellman operations
- Discrete logarithm attack (baby-step giant-step algorithm)

### Building

```bash
cd logjam_demo/crypto/native
./build.sh
```

This will compile `c_dh.c` into `c_dh.so` shared library.

### Requirements

- **gcc** compiler
- **libm** (math library)

Installation:
- macOS: `xcode-select --install`
- Linux: `sudo apt-get install build-essential`

## Usage

All Python modules are imported automatically. The C library is loaded automatically when available.

Example:
```python
from logjam_demo.crypto.dh import DHGroup, generate_private_key, public_from_private
from logjam_demo.crypto.dlog_attack import break_dh_key

# Use weak group for demo
group = EXPORT_GROUP_512

# Generate keys
priv = generate_private_key(group)
pub = public_from_private(group, priv)

# Attacker breaks the key
recovered_secret = break_dh_key(group, group.g, server_pub, client_pub)
```

## Implementation Notes

1. **C Implementation Required**: The Python code requires the C library to be built. If not found, the program will exit with an error.

2. **64-bit Limit**: The C implementation uses `uint64_t`, limiting primes to < 2^64. For larger primes, the implementation would need 128-bit or arbitrary precision arithmetic.

3. **Demo Primes**: Uses 36-bit prime for fast demo execution (~1-2 seconds). For realistic demonstration, use 512-bit prime (may take hours/days).

4. **Simplifications**: 
   - XOR encryption instead of AES
   - Simplified PRF instead of full TLS PRF
   - Single-threaded discrete log attack

