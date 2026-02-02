"""TLS message structures as dataclasses."""

from dataclasses import dataclass
from typing import List


@dataclass
class ClientHello:
    """ClientHello message from client to server."""
    client_random: bytes
    cipher_suites: List[str]
    
    def __repr__(self) -> str:
        return f"ClientHello(cipher_suites={self.cipher_suites}, cr_len={len(self.client_random)})"


@dataclass
class ServerHello:
    """ServerHello message from server to client."""
    server_random: bytes
    selected_cipher_suite: str
    
    def __repr__(self) -> str:
        return f"ServerHello(cipher_suite={self.selected_cipher_suite}, sr_len={len(self.server_random)})"


@dataclass
class ServerKeyExchange:
    """ServerKeyExchange message with DH parameters."""
    p: int  # DH prime modulus
    g: int  # DH generator
    gy: int  # Server public value g^y mod p
    
    def __repr__(self) -> str:
        return f"ServerKeyExchange(p={self.p.bit_length()}-bit, g={self.g}, gy=...)"


@dataclass
class ClientKeyExchange:
    """ClientKeyExchange message with client DH public value."""
    gx: int  # Client public value g^x mod p
    
    def __repr__(self) -> str:
        return f"ClientKeyExchange(gx=...)"


@dataclass
class EncryptedHTTP:
    """Encrypted HTTP request/response."""
    ciphertext: bytes
    
    def __repr__(self) -> str:
        return f"EncryptedHTTP(ciphertext_len={len(self.ciphertext)})"

