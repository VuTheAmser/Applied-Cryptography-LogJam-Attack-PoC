from ..entities.client import ClientBrowser
from ..entities.server import TLSServer
from ..entities.attacker import MitMAttacker


def run_demo(username: str = "alice", password: str = "p@ssw0rd") -> None:
    """
    Orchestrate the full LogJam attack demonstration.
    
    Executes the complete handshake sequence with downgrade and attack.
    
    Args:
        username: Username for demo HTTP request (default: "alice")
        password: Password for demo HTTP request (default: "p@ssw0rd")
    """
    print("=" * 100)
    print("LOGJAM ATTACK DEMONSTRATION")
    print("=" * 100)
    print()
    
    # Initialize entities
    print("[DEMO] Initializing entities...")
    client = ClientBrowser()
    server = TLSServer(prefer_export=True)  # Vulnerable: prefers DHE_EXPORT
    mitm = MitMAttacker()
    print(" All entities initialized")
    print()
    
    # Step 1: ClientHello
    print("[1] Client - ClientHello([DHE, DHE_EXPORT])")
    ch = client.create_client_hello()
    print(f"     Original cipher suites: {ch.cipher_suites}")
    
    # Step 2: Attacker downgrades ClientHello
    print("[2] Attacker - Downgrading ClientHello")
    ch_to_server = mitm.intercept_client_hello(ch)
    print(f"     Downgraded cipher suites: {ch_to_server.cipher_suites}")
    print()
    
    # Step 3: Server processes downgraded ClientHello
    print("[3] Server - Processing downgraded ClientHello")
    sh, ske = server.process_client_hello(ch_to_server)
    print(f"     Selected cipher suite: {sh.selected_cipher_suite}")
    print(f"     ServerKeyExchange: {ske.p.bit_length()}-bit prime")
    print()
    
    # Step 4: Attacker intercepts ServerHello and ServerKeyExchange
    print("[4] Attacker - Intercepting ServerHello and ServerKeyExchange")
    sh_to_client = mitm.intercept_server_hello(sh)
    ske_to_client = mitm.intercept_server_key_exchange(ske)
    print("      Messages intercepted and recorded")
    print()
    
    # Step 5: Client processes ServerHello
    print("[5] Client - Processing ServerHello")
    client.process_server_hello(sh_to_client)
    print(f"     Selected cipher suite: {client.chosen_cipher_suite}")
    
    # Step 6: Client processes ServerKeyExchange
    print("[6] Client - Processing ServerKeyExchange")
    client.process_server_key_exchange(ske_to_client)
    print(f"     Client generated DH keys (x, g^x)")
    print()
    
    # Step 7: Client generates ClientKeyExchange
    print("[7] Client - ClientKeyExchange(g^x)")
    ckx = client.create_client_key_exchange()
    print(f"     Client public value g^x generated")
    
    # Step 8: Attacker intercepts ClientKeyExchange and performs attack
    print("[8] Attacker - Intercepting ClientKeyExchange and performing LogJam attack")
    print("     Starting discrete log attack...")
    mitm.intercept_client_key_exchange(ckx)
    print()
    
    # Step 9: Server processes ClientKeyExchange
    print("[9] Server - Processing ClientKeyExchange")
    server.process_client_key_exchange(ckx)
    print(f"     Server computed shared secret")
    print()
    
    # Step 10: Both sides derive keys
    print("[10] Client - Deriving session keys")
    client.derive_keys()
    print(f"       [OK] Client derived master secret and session keys")
    
    print("[11] Server - Deriving session keys")
    server.derive_keys()
    print(f"       [OK] Server derived master secret and session keys")
    print()
    
    # Step 11: Attacker has already derived keys (from perform_logjam_attack)
    print("[12] Attacker - Already derived keys from recovered shared secret")
    
    # Verify shared secrets match
    if client.shared_secret == mitm.shared_secret:
        print(f"       [OK] Shared secrets match: {client.shared_secret}")
    else:
        print(f"       [ERROR] Shared secrets DON'T match!")
        print(f"         Client:   {client.shared_secret}")
        print(f"         Attacker: {mitm.shared_secret}")
        print(f"         Difference: {abs(client.shared_secret - mitm.shared_secret)}")
        
        # Verify master secrets
        if client.master_secret == mitm.master_secret:
            print(f"       [OK] Master secrets match (despite different shared secrets?)")
        else:
            print(f"       [ERROR] Master secrets also don't match")
    
    print()
    
    # Step 12: Client sends encrypted HTTP request
    print(f"[13] Client - Sending encrypted HTTP POST (username={username}, password=***)")
    enc_http = client.create_encrypted_http_request(username, password)
    print(f"       Encrypted HTTP request sent (length: {len(enc_http.ciphertext)} bytes)")
    print()
    
    # Step 13: Attacker decrypts HTTP request
    print("[14] Attacker - Decrypting intercepted HTTP request")
    http_plain = mitm.decrypt_http(enc_http)
    print()
    
    # Step 14: Optionally forward to server
    print("[15] Attacker - Forwarding HTTP request to server")
    enc_http_to_server = mitm.forward_to_server(enc_http)
    server_response = server.process_encrypted_http(enc_http_to_server)
    print("      HTTP forwarded to server")
    print()
    
    # Step 15: Display attack statistics
    print("=" * 100)
    print("ATTACK STATISTICS")
    print("=" * 100)
    stats = mitm.get_attack_stats()
    print(f"Attack Duration:        {stats['duration']:.2f} seconds")
    print(f"Prime (p):              {stats['prime_bits']}-bit")
    print(f"Generator (g):          {stats['generator_g']}")
    print(f"Server Public (g^y):    {hex(stats['server_public_gy'])}")
    print(f"Client Public (g^x):    {hex(stats['client_public_gx'])}")
    print(f"Recovered y:            {stats['recovered_y']}")
    print(f"Shared Secret (K):      {hex(stats['shared_secret'])}")
    print(f"Master Secret (hex):    {stats['master_secret_hex']}")
    print()
    print("Recovered Credentials:")
    print(f"  Username: {http_plain['username']}")
    print(f"  Password: {http_plain['password']}")
    print()
    print("=" * 100)
    print("DEMO COMPLETE")
    print("=" * 100)


if __name__ == "__main__":
    run_demo()

