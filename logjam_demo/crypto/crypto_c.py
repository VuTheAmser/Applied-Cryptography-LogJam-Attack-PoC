"""
Python wrapper for C crypto functions using ctypes.

This module loads the compiled C shared library (c_dh.so) and provides Python
wrappers for all C cryptographic functions. The C implementation provides
significant performance improvements over pure Python.

Functions:
- mod_pow(): Modular exponentiation
- compute_public_value_c(): Compute DH public value
- compute_shared_secret_c(): Compute DH shared secret
- baby_step_giant_step_c(): Discrete logarithm attack

Note: The C library must be built before this module can be used.
Build with: cd logjam_demo/crypto/native && ./build.sh
"""

import ctypes
import sys
from pathlib import Path

# Load the C library - REQUIRED
_c_lib = None
_lib_path = Path(__file__).parent / "native" / "c_dh.so"

if not _lib_path.exists():
    print(f"[ERROR] C crypto library not found: {_lib_path}")
    print(f"[ERROR] Please build it first: cd logjam_demo/crypto/native && ./build.sh")
    sys.exit(1)

try:
    _c_lib = ctypes.CDLL(str(_lib_path))
    
    # Define function signatures
    _c_lib.mod_pow.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    _c_lib.mod_pow.restype = ctypes.c_uint64
    
    _c_lib.compute_public_value.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    _c_lib.compute_public_value.restype = ctypes.c_uint64
    
    _c_lib.compute_shared_secret.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    _c_lib.compute_shared_secret.restype = ctypes.c_uint64
    
    _c_lib.baby_step_giant_step.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int]
    _c_lib.baby_step_giant_step.restype = ctypes.c_uint64
    
    # 128-bit versions
    _c_lib.compute_public_value_128.argtypes = [ctypes.c_uint64] * 6
    _c_lib.compute_public_value_128.restype = ctypes.c_uint64
    
    _c_lib.compute_shared_secret_128.argtypes = [ctypes.c_uint64] * 6
    _c_lib.compute_shared_secret_128.restype = ctypes.c_uint64
    
    _c_lib.baby_step_giant_step_128.argtypes = [ctypes.c_uint64] * 7
    _c_lib.baby_step_giant_step_128.restype = ctypes.c_uint64
    
except Exception as e:
    print(f"[ERROR] Failed to load C crypto library: {e}")
    print(f"[ERROR] Please rebuild: cd logjam_demo/crypto/native && ./build.sh")
    sys.exit(1)


def _split_128(value: int):
    """Split 128-bit value into high and low 64-bit parts."""
    return (value >> 64) & 0xFFFFFFFFFFFFFFFF, value & 0xFFFFFFFFFFFFFFFF


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation - C implementation supports up to 128-bit."""
    if mod >= 2**128:
        raise ValueError(f"Modulus too large: {mod} (max 128-bit supported)")
    if mod < 2**64:
        return _c_lib.mod_pow(base, exp, mod)
    else:
        # Use 128-bit version
        g_h, g_l = _split_128(base)
        x_h, x_l = _split_128(exp)
        p_h, p_l = _split_128(mod)
        return _c_lib.compute_public_value_128(g_h, g_l, x_h, x_l, p_h, p_l)


def compute_public_value_c(g: int, x: int, p: int) -> int:
    """Compute public value - C implementation supports up to 128-bit."""
    if p >= 2**128:
        raise ValueError(f"Prime too large: {p} (max 128-bit supported)")
    if p < 2**64:
        return _c_lib.compute_public_value(g, x, p)
    else:
        # Use 128-bit version
        g_h, g_l = _split_128(g)
        x_h, x_l = _split_128(x)
        p_h, p_l = _split_128(p)
        return _c_lib.compute_public_value_128(g_h, g_l, x_h, x_l, p_h, p_l)


def compute_shared_secret_c(peer_pub: int, priv: int, p: int) -> int:
    """Compute shared secret - C implementation supports up to 128-bit."""
    if p >= 2**128:
        raise ValueError(f"Prime too large: {p} (max 128-bit supported)")
    if p < 2**64:
        return _c_lib.compute_shared_secret(peer_pub, priv, p)
    else:
        # Use 128-bit version
        pub_h, pub_l = _split_128(peer_pub)
        priv_h, priv_l = _split_128(priv)
        p_h, p_l = _split_128(p)
        return _c_lib.compute_shared_secret_128(pub_h, pub_l, priv_h, priv_l, p_h, p_l)


def baby_step_giant_step_c(p: int, g: int, h: int, verbose: bool = False) -> int:
    """Baby-step giant-step - C implementation supports up to 128-bit."""
    if p >= 2**128:
        raise ValueError(f"Prime too large: {p} (max 128-bit supported)")
    if p < 2**64:
        result = _c_lib.baby_step_giant_step(p, g, h, 1 if verbose else 0)
    else:
        # Use 128-bit version
        p_h, p_l = _split_128(p)
        g_h, g_l = _split_128(g)
        h_h, h_l = _split_128(h)
        result = _c_lib.baby_step_giant_step_128(p_h, p_l, g_h, g_l, h_h, h_l, 1 if verbose else 0)
    
    if result == 0:
        raise ValueError(f"Discrete logarithm not found for h={h} in group (g={g}, p={p})")
    return result

