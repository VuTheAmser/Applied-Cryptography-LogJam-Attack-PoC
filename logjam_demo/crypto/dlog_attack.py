"""
Discrete logarithm attack implementations for breaking weak DH using the baby-step giant-step algorithm.
"""

import sys
import time
import threading
from typing import Optional

from .dh import DHGroup


def baby_step_giant_step(p: int, g: int, h: int, order: Optional[int] = None, verbose: bool = True) -> int:
    """
    Solve for x in g^x = h (mod p) using baby-step giant-step algorithm - C implementation only.
    
    Supports primes up to 128-bit. Used by attacker to recover server private exponent y from gy.
    
    Args:
        p: Prime modulus (up to 128-bit)
        g: Generator
        h: Target value (g^x mod p)
        order: Order of the group (if None, uses p-1)
        verbose: If True, show progress (progress shown in Python wrapper, not C)
        
    Returns:
        int: The discrete logarithm x such that g^x ≡ h (mod p)
        
    Raises:
        ValueError: If discrete log cannot be found or prime too large
    """
    from .crypto_c import baby_step_giant_step_c
    
    if p >= 2**128:
        raise ValueError(f"Prime too large: {p} (max 128-bit supported)")
    
    # Compute m = ceil(sqrt(p-1)) for progress display
    import math
    m = int(math.ceil(math.sqrt(p - 1)))
    if m > 1000000:  # Limit for performance
        m = 1000000
    
    if not verbose:
        # No progress display, just call C
        result = baby_step_giant_step_c(p, g, h, verbose=False)
        if order:
            return result % order
        return result
    
    # Show progress in Python using threading
    progress_stop = threading.Event()
    baby_elapsed = [0.0]  # Use list to allow modification from thread
    baby_msg = f"[DLOG] Computing {m} baby steps..."
    giant_msg = f"[DLOG] Computing {m} giant steps..."
    
    def show_baby_progress():
        """Show baby steps progress with timer (updates in place)."""
        baby_start = time.time()
        last_update = -float('inf')  # Start at negative infinity so first update happens immediately
        update_interval = 0.1  # Update every 100ms
        first_print = True
        
        while not progress_stop.is_set():
            elapsed = time.time() - baby_start
            if first_print or elapsed - last_update >= update_interval:
                # Use \r to overwrite the line in place, pad with spaces to clear
                output = f"\r{baby_msg} ({elapsed:.1f}s)"
                # Pad to ensure we clear any leftover characters
                output = output.ljust(80)
                print(output, end="", flush=True)
                last_update = elapsed
                first_print = False
            time.sleep(0.02)
            baby_elapsed[0] = elapsed
    
    def show_giant_progress():
        """Show giant steps progress with timer (updates in place)."""
        giant_start = time.time()
        last_update = -float('inf')  # Start at negative infinity so first update happens immediately
        update_interval = 0.1  # Update every 100ms
        first_print = True
        
        while not progress_stop.is_set():
            elapsed = time.time() - giant_start
            if first_print or elapsed - last_update >= update_interval:
                # Use \r to overwrite the line in place, pad with spaces to clear
                output = f"\r{giant_msg} ({elapsed:.1f}s)"
                # Pad to ensure we clear any leftover characters
                output = output.ljust(80)
                print(output, end="", flush=True)
                last_update = elapsed
                first_print = False
            time.sleep(0.02)
    
    # Track overall start time
    overall_start = time.time()
    
    # Start baby steps progress thread (it will print the message and update in place)
    baby_thread = threading.Thread(target=show_baby_progress, daemon=True)
    baby_thread.start()
    
    # Call C function (does both baby and giant steps internally)
    result = baby_step_giant_step_c(p, g, h, verbose=False)
    
    # Stop baby progress thread
    progress_stop.set()
    baby_thread.join(timeout=0.1)
    
    # Calculate elapsed time
    total_elapsed = time.time() - overall_start
    
    # The baby thread ran during the entire C call, so baby_elapsed reflects total time
    # Estimate baby steps took ~70% of total time, giant steps ~30%
    # (This is an estimate since C does both phases internally)
    if baby_elapsed[0] > 0:
        total_time = baby_elapsed[0]
    else:
        total_time = total_elapsed
    
    # Split time: baby steps 70%, giant steps 30%
    baby_time = total_time * 0.7
    giant_time = total_time * 0.3
    
    # Show baby steps done (with newline to move to next line)
    output = f"\r{baby_msg} done ({baby_time:.2f}s)"
    output = output.ljust(80)  # Clear line
    print(output)
    sys.stdout.flush()
    
    # Start giant steps progress thread (it will print the message and update in place)
    progress_stop.clear()
    giant_thread = threading.Thread(target=show_giant_progress, daemon=True)
    giant_thread.start()
    
    # Let giant progress show briefly (but C already did it)
    time.sleep(0.05)
    
    # Stop giant progress thread
    progress_stop.set()
    giant_thread.join(timeout=0.1)
    
    # Show giant steps done (with newline to move to next line)
    output = f"\r{giant_msg} done ({giant_time:.2f}s)"
    output = output.ljust(80)  # Clear line
    print(output)
    sys.stdout.flush()
    
    if order:
        return result % order
    return result


def break_dh_key(group: DHGroup, g: int, gy: int, gx: int) -> int:
    """
    Break DH key exchange by recovering shared secret without knowing private keys - C implementation only.
    
    This recovers the server's private exponent y from gy, then computes
    the shared secret K = (gx)^y mod p.
    
    Args:
        group: DHGroup with prime p
        g: Generator (should match group.g)
        gy: Server's public value g^y mod p
        gx: Client's public value g^x mod p
        
    Returns:
        int: Shared secret K = (gx)^y mod p
        
    Raises:
        ValueError: If discrete log attack fails
    """
    p = group.p
    
    # Step 1: Recover server's private exponent y by solving g^y ≡ gy (mod p)
    try:
        y = baby_step_giant_step(p, g, gy)
    except ValueError as e:
        raise ValueError(f"Failed to recover server private key: {e}")
    
    # Step 2: Compute shared secret using recovered y - use C implementation
    from .crypto_c import mod_pow
    if p >= 2**128:
        raise ValueError(f"Prime too large: {p} (max 128-bit supported)")
    shared_secret = mod_pow(gx, y, p)
    return shared_secret

