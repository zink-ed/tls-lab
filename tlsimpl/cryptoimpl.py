"""
The cryptography implementations for TLS.
"""

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tlsimpl import util


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """
    Generates an X25519 (private, public) keypair.
    """
    priv_key = X25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    return (priv_key.private_bytes_raw(), pub_key.public_bytes_raw())


def derive_shared_x25519_key(privkey: bytes, peer_pubkey: bytes) -> bytes:
    """
    Derive a shared key from private key and peer's public key.
    """

    priv = X25519PrivateKey.from_private_bytes(privkey)
    pub = X25519PublicKey.from_public_bytes(peer_pubkey)
    return priv.exchange(pub)


def sha384_hkdf_extract(salt: bytes, data: bytes) -> bytes:
    """
    Performs a SHA384 HKDF extraction.
    """
    return hmac.digest(salt, data, hashlib.sha384)


def labeled_sha384_hkdf(
    secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """
    Performs a TLS 1.3 labeled SHA384 HKDF key derivation.

    Specified in RFC8446 section 7.1.
    """
    constructed_label = (
        util.pack(length, 2)
        + util.pack_varlen(b"tls13 " + label, 1)
        + util.pack_varlen(context, 1)
    )
    return HKDFExpand(
        algorithm=hashes.SHA384(), length=length, info=constructed_label
    ).derive(secret)


@dataclass
class AESParams:
    """
    AES-GCM parameters using an incrementing sequence number to be XORed with initial nonce.
    """

    original_secret: bytes
    key: bytes
    initial_nonce: int
    seq_num: int = 0

    def get_nonce(self) -> bytes:
        """
        Gets a new per-record nonce and increments the sequence number.

        Specified in RFC8446 section 5.3.
        """
        nonce = self.initial_nonce ^ self.seq_num
        nonce = util.pack(nonce,12)
        self.seq_num += 1
        # TODO: derive the nonce
        return nonce

    def encrypt(self, msg: bytes, aad: bytes | None) -> bytes:
        """
        Encrypts a message with AES-GCM with optional AAD.
        """
        return AESGCM(self.key).encrypt(self.get_nonce(), msg, aad)

    def decrypt(self, msg: bytes, aad: bytes | None) -> bytes:
        """
        Decrypts a message with AES-GCM with optional AAD.
        """
        return AESGCM(self.key).decrypt(self.get_nonce(), msg, aad)


def derive_handshake_params(
    shared_secret: bytes, transcript_hash: bytes
) -> tuple[bytes, AESParams, AESParams]:
    """
    Given the shared secret and transcript hash, return a (handshake secret, client params, server params) tuple.

    Used for handshake key derivation.
    """
    # TODO: derive necessary secrets

    early_secret = sha384_hkdf_extract(b'', b'\x00'*48)
    empty_hash = hashlib.sha384(b'').digest()
    hello_hash = transcript_hash

    derived_secret = labeled_sha384_hkdf(early_secret, b"derived", empty_hash, 48)
    handshake_secret = sha384_hkdf_extract(derived_secret, shared_secret)
    client_secret = labeled_sha384_hkdf(handshake_secret, b"c hs traffic", hello_hash, 48)
    server_secret = labeled_sha384_hkdf(handshake_secret, b"s hs traffic", hello_hash, 48)
    client_key = labeled_sha384_hkdf(client_secret, b"key", b"", 32)
    server_key = labeled_sha384_hkdf(server_secret, b"key", b"",32)
    client_iv = labeled_sha384_hkdf(client_secret, b"iv", b"", 12)
    server_iv = labeled_sha384_hkdf(server_secret, b"iv", b"", 12)

    client_params = AESParams(client_secret, client_key, util.unpack(client_iv))
    server_params = AESParams(server_secret, server_key, util.unpack(server_iv))
    return (handshake_secret, client_params, server_params)


def derive_application_params(
    handshake_secret: bytes, transcript_hash: bytes
) -> tuple[AESParams, AESParams]:
    """
    Given the shared secret and transcript hash, return a (client params, server params) tuple.

    Used for application key derivation.
    """
    # TODO: derive client/server key/iv

    empty_hash = hashlib.sha384(b'').digest()

    derived_secret = labeled_sha384_hkdf(handshake_secret, b"derived", empty_hash, 48)
    master_secret = sha384_hkdf_extract(derived_secret, b"\x00" * 48)
    client_secret = labeled_sha384_hkdf(master_secret, b"c ap traffic", transcript_hash, 48)
    server_secret = labeled_sha384_hkdf(master_secret, b"s ap traffic", transcript_hash, 48)

    client_application_key = labeled_sha384_hkdf(client_secret, b"key", b"", 32)
    server_application_key = labeled_sha384_hkdf(server_secret, b"key", b"",32)
    client_application_iv = labeled_sha384_hkdf(client_secret, b"iv", b"", 12)
    server_application_iv = labeled_sha384_hkdf(server_secret, b"iv", b"", 12)
    
    client_params = AESParams(client_secret, client_application_key, util.unpack(client_application_iv))
    server_params = AESParams(server_secret, server_application_key, util.unpack(server_application_iv))
    return (client_params, server_params)


def verify_cert(cert_der: bytes, cert_sig: bytes) -> bool:
    """
    Given a certificate in DER format, and a signature, check that a certificate is valid.

    Signature should signed using RSA-PSS-RSAE-SHA256.
    """
    # TODO: verify certificate

    # We are skipping this according to the slides

    return True


def compute_finish(secret: bytes, transcript_hash: bytes) -> bytes:
    """
    Computes the digest to be used/verified for client/server finish.

    Takes in the client/server secret as well as the transcript hash.
    """
    # TODO: compute HMAC
    finished_key = labeled_sha384_hkdf(secret, b'finished', b'',48)
    verify_data = hmac.new(finished_key, transcript_hash, hashlib.sha384).digest()

    return verify_data
