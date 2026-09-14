"""
Cryptographic hashing module for forensic evidence preservation.
Computes deterministic SHA-256 fingerprints on raw, unnormalized email bytes.
"""

import hashlib


def calculate_sha256(data: bytes) -> str:
    """
    Calculate the deterministic SHA-256 hexadecimal digest of raw email bytes.
    Preserves exact byte representation with zero normalization.

    Args:
        data: Raw byte content.

    Returns:
        Lowercase hexadecimal SHA-256 digest string.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"calculate_sha256 expects bytes or bytearray, got {type(data).__name__}")
    return hashlib.sha256(data).hexdigest()
