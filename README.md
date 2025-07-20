# JWT Inspector 

A security-focused CLI tool to inspect, decode, tamper, and bruteforce JSON Web Tokens (JWTs).

## Features
- Decode JWTs (Header, Payload, Signature)
- Check for insecure algorithms (e.g., `none`)
- Verify HMAC / RSA signatures
- Bruteforce HS256 secrets using custom wordlists
- Modify claims and re-sign tokens
- Send test requests with manipulated JWTs

## Usage

```bash
python jwt_inspector.py --token <JWT> --decode
python jwt_inspector.py --token <JWT> --verify --key mysecret
python jwt_inspector.py --token <JWT> --bruteforce --wordlist wordlists/common_secrets.txt
```
## Warning

This tool is for educational and ethical use only. Do not use it against systems without permission.


