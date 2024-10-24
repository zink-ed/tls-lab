"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *
from tlsimpl.util import *
import os

def extension(publickey):

    # supported groups
    data = b'\x00\x1d'
    sup_gr = pack_varlen(data)
    sup_gr = pack_varlen(sup_gr)
    sup_gr = b'\x00\x0a' + sup_gr

    # signature algorithms
    rsa = b'\x08\x04'
    sig_alg = pack_varlen(rsa)
    sig_alg = pack_varlen(sig_alg)
    sig_alg = b'\x00\x0d' + sig_alg

    # supported versions
    end = b'\x03\x04'
    sup_ver = pack_varlen(end, 1)
    sup_ver = pack_varlen(sup_ver)
    sup_ver = b'\x00\x2b' + sup_ver

    # key share
    key_sh = pack_varlen(publickey)
    key_sh = b'\x00\x1d' + key_sh
    key_sh = pack_varlen(key_sh)
    key_sh = pack_varlen(key_sh)
    key_sh = b'\x00\x33' + key_sh

    return sup_gr + sig_alg + sup_ver + key_sh

#print(extension(b'\x02').hex())


def send_client_hello(sock, key_exchange_pubkey: bytes) -> None:
    """
    Performs the TLS v1.3 client hello.

    `key_exchange_pubkey` is the X25519 public key used for key exchange.

    Specified in RFC8446 section 4.1.2.
    """
    packet = []
    # TODO: construct the packet data

    # extensions
    ext = extension(key_exchange_pubkey)
    # print(type(ext))
    ext = pack_varlen(ext)

    # compression methods
    com = b'\x01\x00'

    # cipher suites
    cip = b'\x13\x02'
    cip = pack_varlen(cip)

    # session ID
    id = b''
    id = pack_varlen(id, 1)

    # client random
    random = os.urandom(32)

    # client version
    vers = b'\x03\x03'

    total = vers + random + id + cip + com + ext
    packet.append(total)

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
