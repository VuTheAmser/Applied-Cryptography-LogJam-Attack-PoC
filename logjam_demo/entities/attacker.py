"""MitMAttacker implementation - Man-in-the-Middle attacker."""

import sys
import time
from typing import Optional

from ..protocol.messages import (
    ClientHello, ServerHello, ServerKeyExchange,
    ClientKeyExchange, EncryptedHTTP
)
from ..crypto.dh import EXPORT_GROUP_512, DHGroup
from ..crypto.dlog_attack import baby_step_giant_step
from ..crypto.kdf import derive_master_secret, derive_session_keys
from ..crypto.cipher import decrypt
from ..protocol.tls_state import parse_http_post_body


class MitMAttacker:
    """Man-in-the-Middle attacker that downgrades and breaks weak DH."""
    
    def __init__(self) -> None:
        """Initialize MitMAttacker with export group configuration."""
        self.export_group = EXPORT_GROUP_512
        self.original_client_hello: Optional[ClientHello] = None
        self.downgraded_client_hello: Optional[ClientHello] = None
        self.server_hello: Optional[ServerHello] = None
        self.server_key_exchange: Optional[ServerKeyExchange] = None
        self.client_key_exchange: Optional[ClientKeyExchange] = None
        self.client_random: Optional[bytes] = None
        self.server_random: Optional[bytes] = None
        self.recovered_y: Optional[int] = None  # Server DH private exponent
        self.shared_secret: Optional[int] = None  # Computed shared secret K
        self.master_secret: Optional[bytes] = None
        self.session_keys: Optional[dict] = None
        self.attack_start_time: Optional[float] = None
        self.attack_duration: Optional[float] = None
    
    def intercept_client_hello(self, ch: ClientHello) -> ClientHello:
        """
        Intercept and downgrade ClientHello message.
        
        Args:
            ch: Original ClientHello from client
        
        Returns:
            ClientHello: Downgraded ClientHello with only export-grade suites
        """
        # Store original
        self.original_client_hello = ch
        self.client_random = ch.client_random
        
        # FR-A1: Downgrade - strip non-export suites
        downgraded = ClientHello(
            client_random=ch.client_random,
            cipher_suites=["DHE_EXPORT"]  # Only export-grade
        )
        
        self.downgraded_client_hello = downgraded
        print("[MITM] Downgrading ClientHello: removing strong ciphers")
        sys.stdout.flush()
        
        return downgraded
    
    def intercept_server_hello(self, sh: ServerHello) -> ServerHello:
        """
        Intercept and relay ServerHello message.
        
        Args:
            sh: ServerHello from server
        
        Returns:
            ServerHello: Same ServerHello (forwarded as-is)
        """
        self.server_hello = sh
        self.server_random = sh.server_random
        print(f"[MITM] ServerHello intercepted: {sh.selected_cipher_suite}")
        sys.stdout.flush()
        return sh
    
    def intercept_server_key_exchange(self, ske: ServerKeyExchange) -> ServerKeyExchange:
        """
        Intercept and record ServerKeyExchange message.
        
        Args:
            ske: ServerKeyExchange from server
        
        Returns:
            ServerKeyExchange: Same ServerKeyExchange (forwarded as-is)
        
        Raises:
            Warning: If p is not 512-bit (attack may be slow)
        """
        self.server_key_exchange = ske
        
        # Validate that p is weak (small enough to attack)
        p_bits = ske.p.bit_length()
        # For demo, accept any prime <= 512 bits (real LogJam used 512-bit)
        if p_bits > 512:
            import warnings
            warnings.warn(f"Prime is {p_bits}-bit, larger than 512-bit. Attack may be very slow or infeasible.")
        
        print(f"[MITM] Weak DH: p={p_bits}-bit, g={ske.g}, gy={ske.gy}")
        sys.stdout.flush()
        
        return ske
    
    def intercept_client_key_exchange(self, ckx: ClientKeyExchange) -> None:
        """
        Intercept ClientKeyExchange and trigger attack.
        
        Args:
            ckx: ClientKeyExchange from client
        
        Raises:
            RuntimeError: If ServerKeyExchange not yet intercepted
        """
        if self.server_key_exchange is None:
            raise RuntimeError("Must intercept ServerKeyExchange first")
        
        self.client_key_exchange = ckx
        self.attack_start_time = time.time()
        
        # Automatically trigger attack
        self.perform_logjam_attack(ckx.gx)
    
    def perform_logjam_attack(self, client_pub_gx: int) -> None:
        """
        Perform discrete log attack to break 512-bit DH.
        
        Args:
            client_pub_gx: Client public value g^x mod p
        
        Raises:
            RuntimeError: If ServerKeyExchange not yet intercepted
            ValueError: If discrete log attack fails
        """
        if self.server_key_exchange is None:
            raise RuntimeError("Must intercept ServerKeyExchange first")
        
        # Extract parameters
        p = self.server_key_exchange.p
        g = self.server_key_exchange.g
        gy = self.server_key_exchange.gy
        
        # Record attack start time if not already set
        if self.attack_start_time is None:
            self.attack_start_time = time.time()
        
        print(f"[MITM] Starting discrete log attack on {p.bit_length()}-bit group...")
        sys.stdout.flush()
        print(f"[MITM] Solving: g^y ≡ {gy} (mod p) for y")
        sys.stdout.flush()
        
        # FR-A3: Run discrete log attack on gy to recover y
        try:
            # Solve g^y ≡ gy (mod p) for y
            y = baby_step_giant_step(p, g, gy, verbose=True)
            self.recovered_y = y
            
            # Compute shared secret: K = (gx)^y mod p - use C implementation
            from ..crypto.crypto_c import mod_pow
            if p >= 2**128:
                raise ValueError(f"Prime too large: {p} (max 128-bit supported)")
            self.shared_secret = mod_pow(client_pub_gx, y, p)
            verify_gy = mod_pow(g, y, p)
            if verify_gy != gy:
                print(f"[MITM] WARNING: Verification failed! g^y mod p = {verify_gy}, expected {gy}")
                sys.stdout.flush()
            else:
                print(f"[MITM] Verified: g^y mod p = gy (recovered y is correct)")
                sys.stdout.flush()
            
            # Record attack duration
            self.attack_duration = time.time() - self.attack_start_time
            
            # Log attack statistics
            print(f"[MITM] Attack completed in {self.attack_duration:.2f} seconds")
            sys.stdout.flush()
            print(f"[MITM] Recovered server private exponent y: {self.recovered_y}")
            sys.stdout.flush()
            print(f"[MITM] Computed shared secret K: {self.shared_secret}")
            sys.stdout.flush()
            
        except ValueError as e:
            raise ValueError(f"Discrete log attack failed: {e}")
        
        # Automatically derive keys
        self.derive_keys()
    
    def derive_keys(self) -> None:
        """
        Derive master secret and session keys from recovered shared secret.
        
        Raises:
            RuntimeError: If required values not yet computed
        """
        if self.client_random is None or self.server_random is None or self.shared_secret is None:
            raise RuntimeError("Must have client_random, server_random, and shared_secret set")
        
        # Derive master secret from (cr, sr, shared_secret)
        self.master_secret = derive_master_secret(
            self.client_random,
            self.server_random,
            self.shared_secret
        )
        
        # Derive session keys
        self.session_keys = derive_session_keys(self.master_secret)
        
        print(f"[MITM] Derived master secret: {self.master_secret.hex()}")
        sys.stdout.flush()
    
    def decrypt_http(self, enc_http: EncryptedHTTP) -> dict:
        """
        Decrypt intercepted HTTP request using recovered keys.
        
        Args:
            enc_http: EncryptedHTTP message containing ciphertext
        
        Returns:
            dict: Decrypted and parsed HTTP request
        
        Raises:
            RuntimeError: If keys not yet derived
            ValueError: If decryption fails or HTTP parsing fails
        """
        if self.session_keys is None:
            raise RuntimeError("Must complete logjam attack and derive keys first")
        
        # Decrypt ciphertext - use encryption key since XOR is symmetric
        # The client encrypts with 'encryption' key, so we decrypt with 'encryption' key too
        encryption_key = self.session_keys['encryption']
        plaintext_bytes = decrypt(enc_http.ciphertext, encryption_key)
        
        # Debug: Check if decryption produces valid UTF-8
        # Try to decode and handle errors gracefully
        try:
            plaintext = plaintext_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            # If decoding fails, try to see what we got
            # This might indicate key mismatch
            raise ValueError(
                f"Failed to decode decrypted data: {e}. "
                f"This usually means the decryption key doesn't match the encryption key. "
                f"Decrypted bytes (first 50): {plaintext_bytes[:50].hex()}"
            )
        
        # Extract HTTP body
        if '\r\n\r\n' in plaintext:
            body = plaintext.split('\r\n\r\n', 1)[1]
        elif '\n\n' in plaintext:
            body = plaintext.split('\n\n', 1)[1]
        else:
            body = plaintext
        
        # Parse HTTP POST body
        parsed = parse_http_post_body(body)
        
        # Log recovered credentials
        print(f"[MITM] *** ATTACK SUCCESSFUL ***")
        sys.stdout.flush()
        print(f"[MITM] Recovered username: {parsed['username']}")
        sys.stdout.flush()
        print(f"[MITM] Recovered password: {parsed['password']}")
        sys.stdout.flush()
        
        return parsed
    
    def get_attack_stats(self) -> dict:
        """
        Get attack statistics for demo output.
        
        Returns:
            dict: Attack statistics including timing, parameters, and recovered data
        
        Raises:
            RuntimeError: If attack not yet performed
        """
        if self.attack_duration is None or self.server_key_exchange is None:
            raise RuntimeError("Must complete logjam attack first")
        
        stats = {
            'duration': self.attack_duration,
            'prime_p': self.server_key_exchange.p,
            'prime_bits': self.server_key_exchange.p.bit_length(),
            'generator_g': self.server_key_exchange.g,
            'server_public_gy': self.server_key_exchange.gy,
            'recovered_y': self.recovered_y,
            'shared_secret': self.shared_secret,
        }
        
        if self.client_key_exchange:
            stats['client_public_gx'] = self.client_key_exchange.gx
        
        if self.master_secret:
            stats['master_secret_hex'] = self.master_secret.hex()
        
        if self.session_keys:
            stats['session_keys'] = {
                'encryption_key_hex': self.session_keys['encryption'].hex(),
                'decryption_key_hex': self.session_keys['decryption'].hex(),
                'mac_key_hex': self.session_keys['mac'].hex()
            }
        
        return stats
    
    def forward_to_server(self, enc_http: EncryptedHTTP) -> EncryptedHTTP:
        """
        Re-encrypt and forward HTTP to server.
        
        In simple option, forwards as-is since client and server use same weak group.
        
        Args:
            enc_http: EncryptedHTTP from client
        
        Returns:
            EncryptedHTTP: Forwarded HTTP (as-is in simple option)
        """
        # Forward as-is (client and server use same weak group)
        return enc_http

