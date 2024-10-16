"""
The cryptography implementations for TLS.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """
    Generates an Ed25519 (private, public) keypair.
    """
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    return (priv_key.private_bytes_raw(), pub_key.public_bytes_raw())
