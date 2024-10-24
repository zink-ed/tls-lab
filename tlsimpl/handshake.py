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

def extract_ext(extensions, data):
     
    pub_key = '0'

    while (len(data) > 0):
        ext_type = data[0:4]
        ext_len = data[4:8]
        extensions[ext_type] = data[0:8+ext_len]
        data = data[8+ext_len:]

    '''
    ext_type = data[0:incr(2)*2]
    match ext_type:
        case('002b'):
            sup_len = int(data[tracker*2: incr(2)*2], 16)
            incr(sup_len)
        case('0033'):
            incr(4)
            pub_len = int(data[tracker*2: incr(2)*2], 16) 
            pub_key = data[tracker*2: incr(pub_len)*2]

    '''

    return extensions

def parse_pub(key_dict, data):
    key_dict["key len"] = data[4:8]
    key_dict["x25519"] = data[8:12]
    key_dict["pub len"] = data[12:16]
    key_dict["pub key"] = data[16:]
    return key_dict


def parse_server(data):

    server_hel ={}

    count = int.from_bytes(5, "big")
    server_hel["record"] = data[0:count]
    data = data[count:]
    count = int.from_bytes(2, "big")
    server_hel["server ver"] = data[0:count]
    data = data[count:]
    count = int.from_bytes(32, "big")
    server_hel["server rand"] = data[0:count]
    data = data[count:]
    server_hel["id"] = unpack_varlen(data, 1)[0]
    data = unpack_varlen(data)[1]
    server_hel["cipher suite"] = unpack_varlen(data)[0]
    data = unpack_varlen(data)[1]
    server_hel["compression"] = unpack_varlen(data, 1)[0]
    data = unpack_varlen(data)[1]

    ext = {}
    extract_ext(ext, data)

    key_dict = {}
    key_dict = parse_pub(key_dict, ext['0033'])

    return server_hel, ext, key_dict


def recv_server_hello(sock: client.TLSSocket) -> bytes:
    """
    Parses the TLS v1.3 server hello.

    Returns the pubkey of the server.

    Specified in RFC8446 section 4.1.3.
    """
    (ty, data) = sock.recv_handshake_record()
    assert ty == HandshakeType.SERVER_HELLO
    # TODO: parse server hello and find server pubkey

    server_data, extension_data, key_share_data = parse_server(data)

    peer_pubkey = key_share_data['pub key']
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
