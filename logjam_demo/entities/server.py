"""TLSServer implementation - TLS server entity."""

import os
import sys
from typing import Optional

from ..protocol.messages import (
    ClientHello, ServerHello, ServerKeyExchange,
    ClientKeyExchange, EncryptedHTTP
)
from ..crypto.dh import (
    DHGroup, EXPORT_GROUP_512, SAFE_GROUP_2048,
    generate_private_key, public_from_private, compute_shared_secret
)
from ..crypto.kdf import derive_master_secret, derive_session_keys
from ..crypto.cipher import decrypt
from ..protocol.tls_state import validate_dh_parameters, parse_http_post_body


class TLSServer:
    """TLS server that supports DHE_EXPORT (vulnerable configuration)."""
    
    def __init__(self, prefer_export: bool = True) -> None:
        """
        Initialize TLSServer.
        
        Args:
            prefer_export: If True, prefer DHE_EXPORT when available (default: True)
        """
        self.prefer_export = prefer_export
        self.sr: Optional[bytes] = None  # Server random
        self.client_random: Optional[bytes] = None
        self.selected_cipher_suite: Optional[str] = None
        self.group: Optional[DHGroup] = None
        self.priv: Optional[int] = None  # Server DH private exponent y
        self.pub: Optional[int] = None  # Server DH public value g^y mod p
        self.client_pub: Optional[int] = None  # Client DH public value g^x mod p
        self.shared_secret: Optional[int] = None  # Computed shared secret K
        self.master_secret: Optional[bytes] = None
        self.session_keys: Optional[dict] = None
    
    def process_client_hello(self, ch: ClientHello) -> tuple[ServerHello, ServerKeyExchange]:
        """
        Process ClientHello and select cipher suite.
        
        Args:
            ch: ClientHello message containing client_random and cipher_suites
        
        Returns:
            tuple[ServerHello, ServerKeyExchange]: ServerHello and ServerKeyExchange messages
        
        Raises:
            ValueError: If no supported cipher suites provided
        """
        if not ch.cipher_suites:
            raise ValueError("ClientHello must contain at least one cipher suite")
        
        # Generate fresh server random
        self.sr = os.urandom(32)
        self.client_random = ch.client_random
        
        # Select cipher suite
        # If DHE_EXPORT is present and prefer_export, choose it
        if self.prefer_export and "DHE_EXPORT" in ch.cipher_suites:
            self.selected_cipher_suite = "DHE_EXPORT"
        else:
            # Choose first supported suite
            supported = ["DHE_EXPORT", "DHE"]
            for suite in ch.cipher_suites:
                if suite in supported:
                    self.selected_cipher_suite = suite
                    break
        
        if self.selected_cipher_suite is None:
            raise ValueError(f"No supported cipher suites in {ch.cipher_suites}")
        
        # Create ServerHello
        server_hello = ServerHello(
            server_random=self.sr,
            selected_cipher_suite=self.selected_cipher_suite
        )
        
        # Generate ServerKeyExchange
        server_key_exchange = self.create_server_key_exchange()
        
        return (server_hello, server_key_exchange)
    
    def create_server_key_exchange(self) -> ServerKeyExchange:
        """
        Generate ServerKeyExchange with DH parameters.
        
        Returns:
            ServerKeyExchange: Contains p, g, gy (server DH public value)
        
        Raises:
            RuntimeError: If cipher suite not yet selected
        """
        if self.selected_cipher_suite is None:
            raise RuntimeError("Must select cipher suite first")
        
        # Select DH group based on chosen cipher suite
        # Use 512-bit for DHE_EXPORT, 2048-bit for DHE
        if self.selected_cipher_suite == "DHE_EXPORT":
            self.group = EXPORT_GROUP_512
        elif self.selected_cipher_suite == "DHE":
            self.group = SAFE_GROUP_2048
        else:
            raise ValueError(f"Unknown cipher suite: {self.selected_cipher_suite}")
        
        # Generate server DH private key y
        self.priv = generate_private_key(self.group)
        
        # Compute g^y mod p
        self.pub = public_from_private(self.group, self.priv)
        
        # Return ServerKeyExchange
        return ServerKeyExchange(
            p=self.group.p,
            g=self.group.g,
            gy=self.pub
        )
    
    def process_client_key_exchange(self, ckx: ClientKeyExchange) -> None:
        """
        Process ClientKeyExchange and compute shared secret.
        
        Args:
            ckx: ClientKeyExchange message containing gx
        
        Raises:
            RuntimeError: If DH key exchange not yet performed
            ValueError: If gx is invalid
        """
        if self.priv is None or self.group is None:
            raise RuntimeError("Must create ServerKeyExchange first")
        
        # Validate gx
        validate_dh_parameters(self.group.p, self.group.g, ckx.gx)
        
        # Store client public value
        self.client_pub = ckx.gx
        
        # Compute shared secret K = (gx)^y mod p
        self.shared_secret = compute_shared_secret(self.group, self.priv, self.client_pub)
    
    def derive_keys(self) -> None:
        """
        Derive master secret and session keys.
        
        Raises:
            RuntimeError: If required values not yet computed
        """
        if self.client_random is None or self.sr is None or self.shared_secret is None:
            raise RuntimeError("Must have client_random, sr, and shared_secret set")
        
        # Derive master secret from (cr, sr, shared_secret)
        self.master_secret = derive_master_secret(self.client_random, self.sr, self.shared_secret)
        
        # Derive session keys
        self.session_keys = derive_session_keys(self.master_secret)
    
    def process_encrypted_http(self, enc_http: EncryptedHTTP) -> dict:
        """
        Decrypt and process HTTP request.
        
        Args:
            enc_http: EncryptedHTTP message containing ciphertext
        
        Returns:
            dict: Parsed HTTP request with username, password, raw_request
        
        Raises:
            RuntimeError: If keys not yet derived
            ValueError: If decryption fails or HTTP parsing fails
        """
        if self.session_keys is None:
            raise RuntimeError("Must derive keys first")
        
        # Decrypt ciphertext - use encryption key since XOR is symmetric
        # The client encrypts with 'encryption' key, so we decrypt with 'encryption' key too
        encryption_key = self.session_keys['encryption']
        plaintext_bytes = decrypt(enc_http.ciphertext, encryption_key)
        
        # Decode to string
        try:
            plaintext = plaintext_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError(
                f"Failed to decode decrypted data: {e}. "
                f"This usually means the decryption key doesn't match the encryption key. "
                f"Decrypted bytes (first 50): {plaintext_bytes[:50].hex()}"
            )
        
        # Extract HTTP body (everything after first blank line)
        if '\r\n\r\n' in plaintext:
            body = plaintext.split('\r\n\r\n', 1)[1]
        elif '\n\n' in plaintext:
            body = plaintext.split('\n\n', 1)[1]
        else:
            body = plaintext
        
        # Parse HTTP POST body
        parsed = parse_http_post_body(body)
        
        # Log recovered credentials
        print(f"[SERVER] Received credentials: username={parsed['username']}, password={parsed['password']}")
        sys.stdout.flush()
        
        return parsed

