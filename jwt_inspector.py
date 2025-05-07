import base64
import json
import argparse
import hmac
import hashlib
import os
from typing import Optional

def b64_decode(data):
    padding = '=' * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except Exception as e:
        return f"[Error decoding base64]: {e}".encode()

def decode_jwt(token: str):
    parts = token.strip().split('.')
    if len(parts) != 3:
        return {"error": "Invalid JWT format. Must have 3 parts."}

    header_b64, payload_b64, signature_b64 = parts
    header_json = b64_decode(header_b64)
    payload_json = b64_decode(payload_b64)

    try:
        header = json.loads(header_json)
        payload = json.loads(payload_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON in JWT."}

    alg = header.get('alg', '').lower()
    warnings = []
    if alg == 'none':
        warnings.append("Insecure algorithm 'none' used.")
    if not signature_b64 and alg != 'none':
        warnings.append("Missing signature with algorithm not set to 'none'.")

    return {
        "header": header,
        "payload": payload,
        "signature_b64": signature_b64,
        "warnings": warnings
    }

def verify_jwt(token: str, key: str) -> bool:
    parts = token.strip().split('.')
    if len(parts) != 3:
        return False

    header_b64, payload_b64, signature_b64 = parts
    header_json = b64_decode(header_b64)
    try:
        header = json.loads(header_json)
    except json.JSONDecodeError:
        return False

    alg = header.get('alg', '').lower()
    if alg != 'hs256':
        return False  # For now only support HS256

    message = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(key.encode(), message, hashlib.sha256).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode()

    return hmac.compare_digest(signature_b64, expected_sig_b64)

def bruteforce_jwt(token: str, wordlist_path: str) -> Optional[str]:
    if not os.path.exists(wordlist_path):
        return "Wordlist file not found."

    with open(wordlist_path, 'r', encoding='utf-8') as file:
        for line in file:
            candidate = line.strip()
            if verify_jwt(token, candidate):
                return candidate
    return None

def main():
    parser = argparse.ArgumentParser(description="JWT Inspector - Decode, Verify, and Bruteforce JWTs")
    parser.add_argument('--token', help="JWT token", required=True)
    parser.add_argument('--decode', action='store_true', help="Decode JWT")
    parser.add_argument('--verify', action='store_true', help="Verify JWT with provided key")
    parser.add_argument('--key', help="Key to verify the JWT (HS256 only)")
    parser.add_argument('--bruteforce', action='store_true', help="Bruteforce weak secret key")
    parser.add_argument('--wordlist', help="Path to wordlist for bruteforce")
    args = parser.parse_args()

    if args.decode:
        result = decode_jwt(args.token)
        if "error" in result:
            print(f"❌ {result['error']}")
        else:
            print("\n=== 🧠 JWT Header ===")
            print(json.dumps(result['header'], indent=4))
            print("\n=== 📦 JWT Payload ===")
            print(json.dumps(result['payload'], indent=4))
            print("\n=== 🔑 Signature (base64) ===")
            print(result['signature_b64'] or "[none]")
            if result['warnings']:
                print("\n⚠️  Warnings:")
                for w in result['warnings']:
                    print(f"- {w}")

    if args.verify and args.key:
        if verify_jwt(args.token, args.key):
            print("\n✅ Signature is valid.")
        else:
            print("\n❌ Signature is invalid.")

    if args.bruteforce and args.wordlist:
        found_key = bruteforce_jwt(args.token, args.wordlist)
        if found_key is None:
            print("\n❌ No matching key found in wordlist.")
        elif isinstance(found_key, str) and found_key.startswith("Wordlist"):
            print(f"\n❌ {found_key}")
        else:
            print(f"\n✅ Key found: {found_key}")

if __name__ == "__main__":
    main()
