"""Common TLS state management and utility functions."""


def validate_dh_parameters(p: int, g: int, public_value: int) -> bool:
    """
    Validate DH parameters (minimal validation for demo).
    
    Args:
        p: Prime modulus
        g: Generator
        public_value: Public value to validate (g^x mod p)
        
    Returns:
        bool: True if parameters are valid
        
    Raises:
        ValueError: If parameters are invalid
    """
    if p <= 0:
        raise ValueError(f"Invalid prime p: {p}")
    if g <= 0:
        raise ValueError(f"Invalid generator g: {g}")
    if not (1 <= public_value < p):
        raise ValueError(f"Invalid public value: {public_value} not in range [1, {p-1}]")
    return True


def parse_http_post_body(body: str) -> dict:
    """
    Parse HTTP POST body (query string format) to extract username and password.
    
    Args:
        body: HTTP POST body string, e.g., "username=alice&password=secret"
        
    Returns:
        dict: Dictionary with 'username' and 'password' keys
        
    Raises:
        ValueError: If parsing fails
    """
    # Split by & to get key=value pairs
    pairs = body.split('&')
    result = {}
    
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)  # Split on first = only
            result[key] = value
    
    if 'username' not in result or 'password' not in result:
        raise ValueError(f"Missing username or password in HTTP body: {body}")
    
    return {
        'username': result['username'],
        'password': result['password'],
        'raw_request': body
    }


def create_http_post_request(username: str, password: str) -> str:
    """
    Create HTTP POST request string.
    
    Args:
        username: Username for login
        password: Password for login
        
    Returns:
        str: HTTP POST request string
    """
    # Simple HTTP POST format
    body = f"username={username}&password={password}"
    return f"POST /login HTTP/1.1\r\n\r\n{body}"

