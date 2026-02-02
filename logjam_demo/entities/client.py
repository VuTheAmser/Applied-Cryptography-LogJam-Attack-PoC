"""ClientBrowser implementation - TLS client entity."""

import os
from typing import Optional

from ..protocol.messages import (
    ClientHello, ServerHello, ServerKeyExchange,
    ClientKeyExchange, EncryptedHTTP
)
from ..crypto.dh import DHGroup, generate_private_key, public_from_private, compute_shared_secret
from ..crypto.kdf import derive_master_secret, derive_session_keys
from ..crypto.cipher import encrypt
from ..protocol.tls_state import validate_dh_parameters, create_http_post_request


class ClientBrowser:
    """TLS client that initiates handshake with DHE/DHE_EXPORT support."""
    
    def __init__(self) -> None:
        """
        Initialize ClientBrowser with fresh client random.
        
        Sets initial state variables to None.
        """
        # State tracking
        self.cr = os.urandom(32)  # Client random
        self.sr: Optional[bytes] = None  # Server random
        self.supported_ciphers = ["DHE", "DHE_EXPORT"]
        self.chosen_cipher_suite: Optional[str] = None
        self.group: Optional[DHGroup] = None
        self.priv: Optional[int] = None  # Client DH private exponent x
        self.pub: Optional[int] = None  # Client DH public value g^x mod p
        self.server_pub: Optional[int] = None  # Server DH public value g^y mod p
        self.shared_secret: Optional[int] = None  # Computed shared secret K
        self.master_secret: Optional[bytes] = None
        self.session_keys: Optional[dict] = None
    
    def create_client_hello(self) -> ClientHello:
        """
        Generate ClientHello message.
        
        Returns:
            ClientHello: Contains client_random and list of supported cipher suites
        """
        return ClientHello(
            client_random=self.cr,
            cipher_suites=self.supported_ciphers.copy()
        )
    
    def process_server_hello(self, sh: ServerHello) -> None:
        """
        Process ServerHello message.
        
        Args:
            sh: ServerHello message containing server_random and selected_cipher_suite
        
        Raises:
            ValueError: If cipher suite not supported
        """
        if sh.selected_cipher_suite not in self.supported_ciphers:
            raise ValueError(f"Server selected unsupported cipher suite: {sh.selected_cipher_suite}")
        
        self.sr = sh.server_random
        self.chosen_cipher_suite = sh.selected_cipher_suite
    
    def process_server_key_exchange(self, ske: ServerKeyExchange) -> None:
        """
        Process ServerKeyExchange and initiate DH key exchange.
        
        Args:
            ske: ServerKeyExchange message containing p, g, gy
        
        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If ServerHello not processed yet
        """
        if self.sr is None:
            raise RuntimeError("Must process ServerHello first")
        
        # Validate parameters (minimal check)
        validate_dh_parameters(ske.p, ske.g, ske.gy)
        
        # Create DH group from parameters
        bits = ske.p.bit_length()
        self.group = DHGroup(p=ske.p, g=ske.g, bits=bits)
        
        # Generate client DH private key x
        self.priv = generate_private_key(self.group)
        
        # Compute g^x mod p
        self.pub = public_from_private(self.group, self.priv)
        
        # Store server public value
        self.server_pub = ske.gy
        
        # Compute shared secret K = (gy)^x mod p
        self.shared_secret = compute_shared_secret(self.group, self.priv, self.server_pub)
    
    def create_client_key_exchange(self) -> ClientKeyExchange:
        """
        Generate ClientKeyExchange message.
        
        Returns:
            ClientKeyExchange: Contains gx (client public value)
        
        Raises:
            RuntimeError: If key exchange not yet performed
        """
        if self.pub is None:
            raise RuntimeError("Must process ServerKeyExchange first")
        
        return ClientKeyExchange(gx=self.pub)
    
    def derive_keys(self) -> None:
        """
        Derive master secret and session keys.
        
        Raises:
            RuntimeError: If required values not yet computed
        """
        if self.cr is None or self.sr is None or self.shared_secret is None:
            raise RuntimeError("Must have cr, sr, and shared_secret set")
        
        # Derive master secret from (cr, sr, shared_secret)
        self.master_secret = derive_master_secret(self.cr, self.sr, self.shared_secret)
        
        # Derive session keys
        self.session_keys = derive_session_keys(self.master_secret)
    
    def create_encrypted_http_request(self, username: str, password: str) -> EncryptedHTTP:
        """
        Create encrypted HTTP POST request.
        
        Args:
            username: Username for login
            password: Password for login
        
        Returns:
            EncryptedHTTP: Contains encrypted HTTP POST body
        
        Raises:
            RuntimeError: If keys not yet derived
        """
        if self.session_keys is None:
            raise RuntimeError("Must derive keys first")
        
        # Create HTTP POST body
        http_body = create_http_post_request(username, password)
        body_bytes = http_body.encode('utf-8')
        
        # Encrypt body using session keys
        encryption_key = self.session_keys['encryption']
        ciphertext = encrypt(body_bytes, encryption_key)
        
        return EncryptedHTTP(ciphertext=ciphertext)

