#!/usr/bin/env python3
"""
JWT Inspector - A comprehensive security-focused CLI tool for JWT analysis.

This tool provides functionality to:
- Decode JWT tokens and inspect their contents
- Verify JWT signatures using various algorithms (HS256, HS384, HS512, RS256, ES256)
- Bruteforce weak HMAC secrets
- Detect common JWT vulnerabilities and security issues
- Generate and modify JWT tokens

Author: JWT Inspector
Version: 2.0
License: MIT
"""

import base64
import json
import argparse
import hmac
import hashlib
import os
import sys
import logging
import time
from typing import Optional, Dict, Any, Union, List, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum

# Try to import cryptographic libraries for RSA/ECDSA support
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.warning("Cryptography library not available. RSA and ECDSA verification disabled.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class JWTAlgorithm(Enum):
    """Supported JWT algorithms."""
    NONE = "none"
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"


@dataclass
class JWTValidationResult:
    """Result of JWT validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    algorithm: Optional[str] = None
    key_found: Optional[str] = None


@dataclass
class JWTDecodeResult:
    """Result of JWT decoding."""
    header: Optional[Dict[str, Any]]
    payload: Optional[Dict[str, Any]]
    signature: Optional[str]
    errors: List[str]
    warnings: List[str]
    security_issues: List[str]


class JWTInspectorError(Exception):
    """Custom exception for JWT Inspector errors."""
    pass


class JWTInspector:
    """
    Main JWT Inspector class that handles all JWT operations.
    
    This class provides comprehensive JWT analysis including:
    - Decoding and validation
    - Signature verification
    - Security vulnerability detection
    - Bruteforce attacks on weak secrets
    """

    SUPPORTED_ALGORITHMS = {
        JWTAlgorithm.HS256: hashlib.sha256,
        JWTAlgorithm.HS384: hashlib.sha384,
        JWTAlgorithm.HS512: hashlib.sha512,
    }

    INSECURE_ALGORITHMS = [JWTAlgorithm.NONE]
    WEAK_SECRETS = ["secret", "password", "123456", "jwt", "key", ""]

    def __init__(self, debug: bool = False):
        """
        Initialize JWT Inspector.
        
        Args:
            debug: Enable debug logging
        """
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
        
        self.stats = {
            'tokens_processed': 0,
            'bruteforce_attempts': 0,
            'vulnerabilities_found': 0
        }

    @staticmethod
    def safe_b64_decode(data: str) -> Tuple[bytes, List[str]]:
        """
        Safely decode base64url data with proper padding and error handling.
        
        Args:
            data: Base64url encoded string
            
        Returns:
            Tuple of (decoded_bytes, list_of_errors)
        """
        errors = []
        
        if not data:
            errors.append("Empty base64 data")
            return b"", errors
            
        try:
            # Add proper padding for base64url
            padding_needed = 4 - (len(data) % 4)
            if padding_needed != 4:
                data += '=' * padding_needed
                
            # Decode using urlsafe base64
            decoded = base64.urlsafe_b64decode(data)
            return decoded, errors
            
        except Exception as e:
            errors.append(f"Base64 decoding failed: {str(e)}")
            return b"", errors

    def validate_token_format(self, token: str) -> Tuple[List[str], List[str], List[str]]:
        """
        Validate JWT token format and structure.
        
        Args:
            token: JWT token string
            
        Returns:
            Tuple of (parts, errors, warnings)
        """
        errors = []
        warnings = []
        
        if not token or not isinstance(token, str):
            errors.append("Token must be a non-empty string")
            return [], errors, warnings
            
        # Remove whitespace
        token = token.strip()
        
        # Split into parts
        parts = token.split('.')
        
        if len(parts) != 3:
            errors.append(f"Invalid JWT format. Expected 3 parts, got {len(parts)}")
            return [], errors, warnings
            
        # Check for empty parts
        for i, part in enumerate(parts):
            part_names = ["header", "payload", "signature"]
            if not part and i != 2:  # Signature can be empty for 'none' algorithm
                warnings.append(f"Empty {part_names[i]} part")
                
        return parts, errors, warnings

    def analyze_security_issues(self, header: Dict[str, Any], payload: Dict[str, Any]) -> List[str]:
        """
        Analyze JWT for common security vulnerabilities.
        
        Args:
            header: JWT header
            payload: JWT payload
            
        Returns:
            List of security issues found
        """
        issues = []
        
        # Check algorithm
        alg = header.get('alg', '').upper()
        
        if alg == 'NONE':
            issues.append("CRITICAL: Algorithm set to 'none' - no signature verification")
            
        if alg not in [e.value for e in JWTAlgorithm]:
            issues.append(f"Unknown algorithm: {alg}")
            
        # Check for algorithm confusion vulnerabilities
        if alg.startswith('RS') or alg.startswith('ES'):
            issues.append(f"Public key algorithm ({alg}) - ensure proper key validation")
            
        # Check expiration
        if 'exp' in payload:
            try:
                exp_time = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
                current_time = datetime.now(timezone.utc)
                
                if exp_time < current_time:
                    issues.append("Token has expired")
                elif (exp_time - current_time).total_seconds() > 86400 * 365:  # 1 year
                    issues.append("Token has very long expiration (>1 year)")
            except (ValueError, TypeError):
                issues.append("Invalid expiration timestamp format")
                
        # Check for missing critical claims
        if 'iss' not in payload:
            issues.append("Missing 'iss' (issuer) claim")
            
        if 'aud' not in payload:
            issues.append("Missing 'aud' (audience) claim")
            
        # Check for sensitive data in payload
        sensitive_keys = ['password', 'secret', 'key', 'token', 'private']
        for key in payload.keys():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                issues.append(f"Potentially sensitive data in claim: {key}")
                
        return issues

    def decode_jwt(self, token: str) -> JWTDecodeResult:
        """
        Decode JWT token and analyze its components.
        
        Args:
            token: JWT token string
            
        Returns:
            JWTDecodeResult with decoded components and analysis
        """
        self.stats['tokens_processed'] += 1
        
        parts, errors, warnings = self.validate_token_format(token)
        
        if errors:
            return JWTDecodeResult(
                header=None,
                payload=None,
                signature=None,
                errors=errors,
                warnings=warnings,
                security_issues=[]
            )
            
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode header
        header_bytes, header_errors = self.safe_b64_decode(header_b64)
        errors.extend(header_errors)
        
        header = None
        if header_bytes:
            try:
                header = json.loads(header_bytes.decode('utf-8'))
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON in header: {str(e)}")
            except UnicodeDecodeError as e:
                errors.append(f"Invalid UTF-8 in header: {str(e)}")
                
        # Decode payload
        payload_bytes, payload_errors = self.safe_b64_decode(payload_b64)
        errors.extend(payload_errors)
        
        payload = None
        if payload_bytes:
            try:
                payload = json.loads(payload_bytes.decode('utf-8'))
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON in payload: {str(e)}")
            except UnicodeDecodeError as e:
                errors.append(f"Invalid UTF-8 in payload: {str(e)}")
                
        # Analyze security issues
        security_issues = []
        if header and payload:
            security_issues = self.analyze_security_issues(header, payload)
            if security_issues:
                self.stats['vulnerabilities_found'] += len(security_issues)
                
        return JWTDecodeResult(
            header=header,
            payload=payload,
            signature=signature_b64,
            errors=errors,
            warnings=warnings,
            security_issues=security_issues
        )

    def verify_hmac_signature(self, token: str, key: str, algorithm: JWTAlgorithm) -> bool:
        """
        Verify HMAC-based JWT signature.
        
        Args:
            token: JWT token
            key: Secret key
            algorithm: HMAC algorithm to use
            
        Returns:
            True if signature is valid
        """
        parts = token.strip().split('.')
        if len(parts) != 3:
            return False
            
        header_b64, payload_b64, signature_b64 = parts
        
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            logger.warning(f"Algorithm {algorithm.value} not supported for HMAC verification")
            return False
            
        try:
            # Create message to sign
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            
            # Generate expected signature
            hash_func = self.SUPPORTED_ALGORITHMS[algorithm]
            expected_sig = hmac.new(
                key.encode('utf-8'), 
                message, 
                hash_func
            ).digest()
            
            # Encode as base64url without padding
            expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode('utf-8')
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(signature_b64, expected_sig_b64)
            
        except Exception as e:
            logger.debug(f"HMAC verification failed: {str(e)}")
            return False

    def verify_rsa_signature(self, token: str, public_key_pem: str, algorithm: str) -> bool:
        """
        Verify RSA-based JWT signature.
        
        Args:
            token: JWT token
            public_key_pem: RSA public key in PEM format
            algorithm: RSA algorithm (RS256, RS384, RS512)
            
        Returns:
            True if signature is valid
        """
        if not CRYPTO_AVAILABLE:
            logger.error("Cryptography library not available for RSA verification")
            return False
            
        parts = token.strip().split('.')
        if len(parts) != 3:
            return False
            
        header_b64, payload_b64, signature_b64 = parts
        
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # Decode signature
            signature_bytes, _ = self.safe_b64_decode(signature_b64)
            if not signature_bytes:
                return False
                
            # Create message to verify
            message = f"{header_b64}.{payload_b64}".encode('utf-8')
            
            # Select hash algorithm
            hash_algorithms = {
                'RS256': hashes.SHA256(),
                'RS384': hashes.SHA384(),
                'RS512': hashes.SHA512()
            }
            
            if algorithm not in hash_algorithms:
                logger.error(f"Unsupported RSA algorithm: {algorithm}")
                return False
                
            # Verify signature
            public_key.verify(
                signature_bytes,
                message,
                PKCS1v15(),
                hash_algorithms[algorithm]
            )
            return True
            
        except InvalidSignature:
            return False
        except Exception as e:
            logger.debug(f"RSA verification failed: {str(e)}")
            return False

    def verify_jwt(self, token: str, key: str, algorithm: Optional[str] = None) -> JWTValidationResult:
        """
        Verify JWT signature with comprehensive validation.
        
        Args:
            token: JWT token
            key: Secret key or public key (for RSA/ECDSA)
            algorithm: Force specific algorithm (optional)
            
        Returns:
            JWTValidationResult with validation details
        """
        errors = []
        warnings = []
        
        # Decode token to get algorithm
        decode_result = self.decode_jwt(token)
        if decode_result.errors:
            return JWTValidationResult(
                is_valid=False,
                errors=decode_result.errors,
                warnings=decode_result.warnings
            )
            
        header_alg = decode_result.header.get('alg', '').upper() if decode_result.header else None
        
        # Use algorithm from header if not specified
        if not algorithm:
            algorithm = header_alg
        elif algorithm.upper() != header_alg:
            warnings.append(f"Algorithm mismatch: header={header_alg}, specified={algorithm.upper()}")
            
        if not algorithm:
            errors.append("No algorithm specified")
            return JWTValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings
            )
            
        algorithm = algorithm.upper()
        
        # Handle 'none' algorithm
        if algorithm == 'NONE':
            # For 'none' algorithm, signature should be empty
            parts = token.strip().split('.')
            is_valid = len(parts) == 3 and not parts[2]
            if not is_valid:
                errors.append("Invalid 'none' algorithm token - signature must be empty")
            else:
                warnings.append("Token uses 'none' algorithm - no cryptographic security")
            
            return JWTValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                algorithm=algorithm
            )
            
        # HMAC algorithms
        if algorithm in ['HS256', 'HS384', 'HS512']:
            try:
                jwt_alg = JWTAlgorithm(algorithm)
                is_valid = self.verify_hmac_signature(token, key, jwt_alg)
            except ValueError:
                errors.append(f"Unsupported HMAC algorithm: {algorithm}")
                is_valid = False
                
        # RSA algorithms
        elif algorithm in ['RS256', 'RS384', 'RS512']:
            is_valid = self.verify_rsa_signature(token, key, algorithm)
            
        else:
            errors.append(f"Unsupported algorithm: {algorithm}")
            is_valid = False
            
        return JWTValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            algorithm=algorithm
        )

    def bruteforce_jwt(self, token: str, wordlist_path: str, max_attempts: int = 10000) -> JWTValidationResult:
        """
        Bruteforce JWT secret key using wordlist.
        
        Args:
            token: JWT token
            wordlist_path: Path to wordlist file
            max_attempts: Maximum number of attempts
            
        Returns:
            JWTValidationResult with found key if successful
        """
        errors = []
        warnings = []
        
        # Validate inputs
        if not os.path.exists(wordlist_path):
            errors.append(f"Wordlist file not found: {wordlist_path}")
            return JWTValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings
            )
            
        # Get algorithm from token
        decode_result = self.decode_jwt(token)
        if decode_result.errors or not decode_result.header:
            errors.append("Cannot decode token for bruteforce")
            return JWTValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings
            )
            
        algorithm = decode_result.header.get('alg', '').upper()
        
        if algorithm not in ['HS256', 'HS384', 'HS512']:
            errors.append(f"Bruteforce only supports HMAC algorithms, got: {algorithm}")
            return JWTValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings
            )
            
        logger.info(f"Starting bruteforce attack on {algorithm} token...")
        start_time = time.time()
        attempts = 0
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    if attempts >= max_attempts:
                        warnings.append(f"Reached maximum attempts limit: {max_attempts}")
                        break
                        
                    candidate = line.strip()
                    if not candidate:
                        continue
                        
                    attempts += 1
                    self.stats['bruteforce_attempts'] += 1
                    
                    # Test candidate
                    try:
                        jwt_alg = JWTAlgorithm(algorithm)
                        if self.verify_hmac_signature(token, candidate, jwt_alg):
                            elapsed = time.time() - start_time
                            logger.info(f"Key found after {attempts} attempts in {elapsed:.2f} seconds")
                            
                            return JWTValidationResult(
                                is_valid=True,
                                errors=[],
                                warnings=warnings,
                                algorithm=algorithm,
                                key_found=candidate
                            )
                    except Exception as e:
                        logger.debug(f"Error testing candidate '{candidate}': {str(e)}")
                        
                    # Progress update every 1000 attempts
                    if attempts % 1000 == 0:
                        logger.info(f"Tested {attempts} candidates...")
                        
        except IOError as e:
            errors.append(f"Error reading wordlist: {str(e)}")
            
        elapsed = time.time() - start_time
        logger.info(f"Bruteforce completed: {attempts} attempts in {elapsed:.2f} seconds")
        
        return JWTValidationResult(
            is_valid=False,
            errors=errors,
            warnings=warnings,
            algorithm=algorithm
        )

    def get_stats(self) -> Dict[str, int]:
        """Get inspector statistics."""
        return self.stats.copy()


def format_timestamp(timestamp: Union[int, float]) -> str:
    """Format Unix timestamp for display."""
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"
    except (ValueError, TypeError):
        return f"Invalid timestamp: {timestamp}"


def print_decode_result(result: JWTDecodeResult) -> None:
    """Print formatted decode result."""
    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"   {error}")
        return
        
    print("\n" + "="*60)
    print("JWT ANALYSIS REPORT")
    print("="*60)
    
    # Header
    if result.header:
        print("\nJWT HEADER:")
        print("-" * 40)
        print(json.dumps(result.header, indent=2, sort_keys=True))
        
    # Payload
    if result.payload:
        print("\nJWT PAYLOAD:")
        print("-" * 40)
        
        # Format special claims
        formatted_payload = result.payload.copy()
        for claim in ['exp', 'iat', 'nbf']:
            if claim in formatted_payload and isinstance(formatted_payload[claim], (int, float)):
                formatted_payload[f"{claim}_formatted"] = format_timestamp(formatted_payload[claim])
                
        print(json.dumps(formatted_payload, indent=2, sort_keys=True))
        
    # Signature
    print(f"\nSIGNATURE: {result.signature or '[none]'}")
    
    # Warnings
    if result.warnings:
        print("\nWARNINGS:")
        for warning in result.warnings:
            print(f"   • {warning}")
            
    # Security Issues
    if result.security_issues:
        print("\nSECURITY ANALYSIS:")
        for issue in result.security_issues:
            print(f"   • {issue}")
    else:
        print("\nNo obvious security issues detected")


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="JWT Inspector v2.0 - Comprehensive JWT Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --token eyJ0eXAiOiJKV1Q... --decode
  %(prog)s --token eyJ0eXAiOiJKV1Q... --verify --key mysecret
  %(prog)s --token eyJ0eXAiOiJKV1Q... --bruteforce --wordlist common.txt
  %(prog)s --token eyJ0eXAiOiJKV1Q... --verify --key "$(cat public.pem)" --algorithm RS256
        """
    )
    
    # Required arguments
    parser.add_argument('--token', 
                       help='JWT token to analyze', 
                       required=True)
    
    # Operations
    parser.add_argument('--decode', 
                       action='store_true',
                       help='Decode and analyze JWT structure')
    
    parser.add_argument('--verify', 
                       action='store_true',
                       help='Verify JWT signature')
    
    parser.add_argument('--bruteforce', 
                       action='store_true',
                       help='Bruteforce HMAC secret key')
    
    # Parameters
    parser.add_argument('--key', 
                       help='Secret key or public key for verification')
    
    parser.add_argument('--algorithm', 
                       help='Force specific algorithm (HS256, HS384, HS512, RS256, etc.)')
    
    parser.add_argument('--wordlist', 
                       help='Path to wordlist for bruteforce attack')
    
    parser.add_argument('--max-attempts', 
                       type=int, 
                       default=10000,
                       help='Maximum bruteforce attempts (default: 10000)')
    
    # Options
    parser.add_argument('--debug', 
                       action='store_true',
                       help='Enable debug logging')
    
    parser.add_argument('--stats', 
                       action='store_true',
                       help='Show statistics after operations')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not any([args.decode, args.verify, args.bruteforce]):
        parser.error("Must specify at least one operation: --decode, --verify, or --bruteforce")
        
    if args.verify and not args.key:
        parser.error("--verify requires --key")
        
    if args.bruteforce and not args.wordlist:
        parser.error("--bruteforce requires --wordlist")
    
    # Initialize inspector
    inspector = JWTInspector(debug=args.debug)
    
    try:
        # Decode operation
        if args.decode:
            print("Decoding JWT token...")
            result = inspector.decode_jwt(args.token)
            print_decode_result(result)
            
        # Verify operation
        if args.verify:
            print(f"\nVerifying JWT signature...")
            result = inspector.verify_jwt(args.token, args.key, args.algorithm)
            
            if result.errors:
                print("Verification failed:")
                for error in result.errors:
                    print(f"   • {error}")
            elif result.is_valid:
                print(f"Signature is VALID ({result.algorithm})")
            else:
                print(f"Signature is INVALID ({result.algorithm})")
                
            if result.warnings:
                print("\nWarnings:")
                for warning in result.warnings:
                    print(f"   • {warning}")
                    
        # Bruteforce operation
        if args.bruteforce:
            print(f"\nStarting bruteforce attack...")
            print(f"Wordlist: {args.wordlist}")
            print(f"Max attempts: {args.max_attempts}")
            
            result = inspector.bruteforce_jwt(args.token, args.wordlist, args.max_attempts)
            
            if result.errors:
                print("Bruteforce failed:")
                for error in result.errors:
                    print(f"   • {error}")
            elif result.key_found:
                print(f"SUCCESS! Key found: '{result.key_found}'")
                
                # Verify the found key
                verify_result = inspector.verify_jwt(args.token, result.key_found)
                if verify_result.is_valid:
                    print("Key verification confirmed")
                else:
                    print("Key verification failed (unexpected)")
            else:
                print("No matching key found in wordlist")
                
            if result.warnings:
                print("\nWarnings:")
                for warning in result.warnings:
                    print(f"   • {warning}")
        
        # Show statistics
        if args.stats:
            stats = inspector.get_stats()
            print(f"\nSTATISTICS:")
            print(f"   Tokens processed: {stats['tokens_processed']}")
            print(f"   Bruteforce attempts: {stats['bruteforce_attempts']}")
            print(f"   Vulnerabilities found: {stats['vulnerabilities_found']}")
            
    except KeyboardInterrupt:
        print("\n\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
