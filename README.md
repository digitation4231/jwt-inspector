# JWT Inspector v2.0

A comprehensive security-focused CLI tool for JWT analysis, vulnerability detection, and penetration testing.

## Features

### Core Functionality
- **JWT Decoding**: Decode and analyze JWT structure with detailed output
- **Signature Verification**: Support for multiple algorithms (HS256/384/512, RS256/384/512, ES256/384/512)
- **Bruteforce Attack**: Dictionary-based attacks on weak HMAC secrets
- **Vulnerability Detection**: Identify common JWT security issues
- **Security Analysis**: Comprehensive security assessment and recommendations

### Supported Algorithms
- **HMAC**: HS256, HS384, HS512
- **RSA**: RS256, RS384, RS512 (requires cryptography library)
- **ECDSA**: ES256, ES384, ES512 (requires cryptography library)
- **None**: Detects and warns about insecure 'none' algorithm

### Security Checks
- Insecure algorithm detection ('none')
- Token expiration validation
- Missing critical claims detection
- Sensitive data exposure warnings
- Algorithm confusion attack protection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/digitation4231/jwt-inspector.git
cd jwt-inspector
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic JWT Decoding
```bash
python jwt_inspector.py --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... --decode
```

### Signature Verification
```bash
# HMAC verification
python jwt_inspector.py --token <JWT> --verify --key mysecret

# RSA verification (requires public key)
python jwt_inspector.py --token <JWT> --verify --key "$(cat public.pem)" --algorithm RS256

# Force specific algorithm
python jwt_inspector.py --token <JWT> --verify --key mysecret --algorithm HS256
```

### Bruteforce Attack
```bash
# Basic bruteforce
python jwt_inspector.py --token <JWT> --bruteforce --wordlist common_secrets.txt

# Limited attempts
python jwt_inspector.py --token <JWT> --bruteforce --wordlist passwords.txt --max-attempts 5000

# With debug output
python jwt_inspector.py --token <JWT> --bruteforce --wordlist passwords.txt --debug
```

### Combined Operations
```bash
# Decode and verify in one command
python jwt_inspector.py --token <JWT> --decode --verify --key mysecret --stats
```

## Advanced Options

| Option | Description |
|--------|-------------|
| `--decode` | Decode and analyze JWT structure |
| `--verify` | Verify JWT signature |
| `--bruteforce` | Bruteforce HMAC secret key |
| `--key` | Secret key or public key for verification |
| `--algorithm` | Force specific algorithm |
| `--wordlist` | Path to wordlist file |
| `--max-attempts` | Maximum bruteforce attempts (default: 10000) |
| `--debug` | Enable debug logging |
| `--stats` | Show operation statistics |

## Example Output

### Decoding Analysis
```
JWT ANALYSIS REPORT
============================================================

JWT HEADER:
----------------------------------------
{
  "alg": "HS256",
  "typ": "JWT"
}

JWT PAYLOAD:
----------------------------------------
{
  "exp": 1640995200,
  "exp_formatted": "2022-01-01 00:00:00 UTC",
  "iat": 1640908800,
  "iat_formatted": "2021-12-31 00:00:00 UTC",
  "sub": "user123"
}

SIGNATURE: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

SECURITY ANALYSIS:
   • Token has expired
   • Missing 'iss' (issuer) claim
   • Missing 'aud' (audience) claim
```

### Successful Bruteforce
```
Starting bruteforce attack...
Wordlist: common_secrets.txt
Max attempts: 10000

SUCCESS! Key found: 'secret123'
Key verification confirmed

STATISTICS:
   Tokens processed: 1
   Bruteforce attempts: 1337
   Vulnerabilities found: 3
```

## Security Features

### Vulnerability Detection
- **Algorithm Confusion**: Detects potential RS256/HS256 confusion attacks
- **Weak Secrets**: Identifies tokens using common weak secrets
- **Missing Claims**: Warns about missing security-critical claims
- **Expired Tokens**: Validates token expiration
- **Sensitive Data**: Detects potentially sensitive information in payload

### Safe Implementation
- **Constant-time Comparison**: Prevents timing attacks in signature verification
- **Proper Error Handling**: Comprehensive error handling and validation
- **Memory Safety**: Secure handling of cryptographic operations
- **Rate Limiting**: Built-in limits for bruteforce operations


## Dependencies

- **Python 3.7+**
- **cryptography**: For RSA/ECDSA signature verification (optional)
- **rich**: Enhanced output formatting (optional)
- **tqdm**: Progress bars for bruteforce (optional)

## Security Warning

This tool is designed for:
- Security testing of your own applications
- Educational purposes and learning
- Authorized penetration testing
- Security research

**DO NOT USE** for:
- Unauthorized access to systems
- Attacking systems without permission
- Malicious activities

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.


