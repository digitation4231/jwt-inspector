# JWT Inspector 🔐

A security-focused CLI tool to inspect, decode, tamper, and bruteforce JSON Web Tokens (JWTs).

## Features
- ✅ Decode JWTs (Header, Payload, Signature)
- ✅ Check for insecure algorithms (e.g., `none`)
- 🔐 Verify HMAC / RSA signatures
- 💥 Bruteforce HS256 secrets using custom wordlists
- 🎯 Modify claims and re-sign tokens
- 🌐 Send test requests with manipulated JWTs

## Usage

```bash
python jwt_inspector.py --token <JWT> --decode
python jwt_inspector.py --token <JWT> --verify --key mysecret
python jwt_inspector.py --token <JWT> --bruteforce --wordlist wordlists/common_secrets.txt
```
## Warning

This tool is for educational and ethical use only. Do not use it against systems without permission.

## GPT Explanation

## 🔐 What is a JWT?
JWT (JSON Web Token) is a compact, URL-safe token format used for authentication and data exchange between parties. It consists of three parts:

Header – Specifies the algorithm used (alg) and token type (typ).

Payload – Contains the claims or data (e.g., user ID, roles).

Signature – Used to verify the token hasn’t been tampered with.

A JWT looks like this:

```php-template
<base64url-encoded header>.<base64url-encoded payload>.<base64url-encoded signature>
```
Example
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCIsImFkbWluIjp0cnVlfQ.XYZ_SIGNATURE
```




