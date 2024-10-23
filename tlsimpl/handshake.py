"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *


def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the X25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    packet = []
    # TODO: construct the packet data
    sock.send_handshake_record(HandshakeType.CLIENT_HELLO, b"".join(packet))


def recv_server_hello(sock: client.TLSSocket) -> bytes:
    """
    Parses the TLS v1.3 server hello.

    Returns the pubkey of the server.

    Specified in RFC8446 section 4.1.3.
    """
    (ty, data) = sock.recv_handshake_record()
    assert ty == HandshakeType.SERVER_HELLO
    # TODO: parse server hello and find server pubkey
    peer_pubkey = b"???"
    return peer_pubkey


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_x25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    peer_pubkey = recv_server_hello(sock)
    shared_secret = cryptoimpl.derive_shared_x25519_key(
        key_exchange_keypair[0], peer_pubkey
    )
    transcript_hash = sock.transcript_hash.digest()
    (sock.client_params, sock.server_params) = cryptoimpl.derive_aes_params(
        shared_secret, transcript_hash
    )
    # receive an encrypted handshake record to verify decryption works
    print("got record:", sock.recv_handshake_record())
