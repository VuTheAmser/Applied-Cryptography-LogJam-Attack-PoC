# Applied-Cryptography-LogJam-Attack-PoC
## LogJam Attack Proof-of-Concept Demonstration

This project implements a proof-of-concept demonstration of the **LogJam attack**, a cryptographic attack that exploits weak Diffie-Hellman (DH) key exchange in TLS connections. The attack demonstrates how a Man-in-the-Middle (MitM) attacker can downgrade TLS connections to use export-grade cipher suites with weak 512-bit DH parameters, then break the key exchange to decrypt encrypted traffic.

### Overview

The LogJam attack (CVE-2015-4000) allows an attacker to:
1. **Downgrade** TLS handshakes to use export-grade cipher suites (DHE_EXPORT)
2. **Force** the use of weak 512-bit Diffie-Hellman groups
3. **Break** the discrete logarithm problem on the weak group
4. **Recover** the shared secret and decrypt all encrypted traffic

This demonstration simulates the attack with three entities:
- **ClientBrowser**: A TLS client that supports both strong (DHE) and weak (DHE_EXPORT) cipher suites
- **TLSServer**: A vulnerable TLS server that prefers DHE_EXPORT when available
- **MitMAttacker**: A man-in-the-middle attacker that downgrades connections and breaks weak DH

### Project Structure

```
SC4010---Applied-Cryptography/
├── README.md
├── requirements.txt
├── .gitignore
└── logjam_demo/
    ├── crypto/               # Cryptographic primitives
    │   ├── README.md        # Crypto module documentation
    │   ├── dh.py            # DH group management and key exchange
    │   ├── dlog_attack.py   # Discrete logarithm attack (baby-step giant-step)
    │   ├── kdf.py           # Key derivation functions
    │   ├── cipher.py        # Encryption/decryption (XOR for demo)
    │   ├── crypto_c.py      # Python wrapper for C crypto functions
    │   └── native/          # C implementation (for performance)
    │       ├── c_dh.c       # C implementation of crypto operations
    │       ├── c_dh.h       # C header file
    │       ├── c_dh.so      # Compiled shared library
    │       └── build.sh     # Build script for C library
    ├── protocol/            # TLS protocol structures
    │   ├── messages.py      # TLS message dataclasses
    │   └── tls_state.py     # Common TLS utilities
    ├── entities/            # TLS entities
    │   ├── client.py        # ClientBrowser implementation
    │   ├── server.py        # TLSServer implementation
    │   └── attacker.py      # MitMAttacker implementation
    └── simulator/           # Demo orchestration (CLI)
        ├── handshake.py     # Handshake sequence orchestration
        └── __main__.py      # CLI entry point
```

### Requirements

- **Python 3.8+**
- **C compiler** (gcc/clang) for building crypto library
  - macOS: `xcode-select --install`
  - Linux: `sudo apt-get install build-essential`
  - Windows: Install Visual Studio Build Tools

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd SC4010---Applied-Cryptography
   ```

2. Verify Python version:
   ```bash
   python3 --version  # Should be 3.8 or higher
   ```

3. Build the C crypto library:
   ```bash
   cd logjam_demo/crypto/native
   ./build.sh
   cd ../../..
   ```

### Usage

#### Running the CLI Demo

**Basic command:**
```bash
python -m logjam_demo.simulator
```

**With custom credentials:**
```bash
python -m logjam_demo.simulator --username bob --password secret123
```


#### Expected Output

The demo will show:
1. Handshake sequence with all TLS messages
2. Attacker downgrading ClientHello to DHE_EXPORT
3. Server responding with weak DH parameters
4. Attacker performing discrete logarithm attack
5. Recovered credentials and attack statistics

### Implementation Details

#### Discrete Logarithm Attack

The attack uses the **baby-step giant-step** algorithm to solve:
```
g^y ≡ gy (mod p)
```

Where:
- `p` is the weak prime modulus (36-bit for fast demo, 512-bit for realistic)
- `g` is the generator (typically 2)
- `gy` is the server's public value
- `y` is the server's private exponent (recovered by attacker)

Time complexity: O(√p) operations. For fast demo, a 36-bit prime is used. For realistic demonstration, use 512-bit prime (may take hours/days).

#### Key Derivation

Uses simplified PRF based on HMAC-SHA256:
- Master secret derived from (client_random, server_random, shared_secret)
- Session keys derived from master secret using HMAC with different labels

#### Encryption

Uses simple XOR encryption for demo purposes. In production, TLS uses AES or similar symmetric ciphers.

### Technical Notes

1. **Weak Primes**: For fast demo, uses 36-bit prime. In practice, real LogJam exploited 512-bit primes. Many servers used the same weak primes, allowing attackers to precompute discrete logs.

2. **Attack Timing**: The demo uses a 36-bit prime for fast execution (~1-2 seconds on M2 MacBook). For realistic demonstration, modify `EXPORT_GROUP_512` in `logjam_demo/crypto/dh.py` to use a 512-bit prime.

3. **Real LogJam**: The real LogJam attack (2015) affected millions of servers and exploited weak export-grade cipher suites that were mandated for US export regulations in the 1990s.

### Limitations

This is an **educational demonstration** and has several simplifications:
- Uses XOR encryption instead of AES
- Simplified key derivation (not full TLS PRF)
- Simulated network (direct function calls, not sockets)
- Fixed weak primes (in practice, many were reused)
- Single-threaded discrete log attack (real attacks use parallel computation)

### Security Implications

This demonstration illustrates why:
1. **Export-grade cryptography** is dangerous and should be disabled
2. **Weak DH groups** (512-bit) are vulnerable to nation-state actors
3. **Forward secrecy** requires strong, unique DH parameters
4. **Modern TLS** (1.2+, TLS 1.3) should be used with strong cipher suites

### References

- [LogJam Paper](https://weakdh.org/)
- [CVE-2015-4000](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000)
- [Diffie-Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
