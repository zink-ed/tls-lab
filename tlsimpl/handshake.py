"""
The TLS v1.3 handshake implementation.
"""

from __future__ import annotations

import secrets

from tlsimpl import client, cryptoimpl, util
from tlsimpl.consts import *
from tlsimpl.util import *
import os
from tlsimpl.cryptoimpl import *

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

    while (len(data) > 0):
        ext = unpack_extension(data)
        ext_type = ext[0]
        extensions[ext_type] = ext[1]
        data = ext[2]
        print(1)

    return extensions

def parse_pub(key_dict, data):
    key_dict["x25519"] = data[0:2]
    key_dict["pub len"] = data[2:4]
    key_dict["pub key"] = data[4:]
    print(key_dict)
    return key_dict


def parse_server(data):

    server_hel ={}

    count = 2
    server_hel["server ver"] = data[0:count]
    data = data[count:]
    count = 32
    server_hel["server rand"] = data[0:count]
    data = data[count:]
    server_hel["id"] = unpack_varlen(data, 1)[0]
    data = unpack_varlen(data, 1)[1]
    count = 2
    server_hel["cipher suite"] = data[0:count]
    data = data[count:]
    count = 1
    server_hel["compression"] = data[0:count]
    data = data[count:]
    count = 2
    server_hel["ext_len"] = data[0:count]
    data = data[count:]

    ext = {}
    extract_ext(ext, data)

    key_dict = {}
    key_dict = parse_pub(key_dict, ext[0x0033])

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


def recv_server_info(sock: client.TLSSocket) -> None:
    """
    Receives the server's encrypted extensions, certificate, and certificate verification.

    Also verifies the certificate's validity.
    """
    sock.recv_handshake_record()
    sock.recv_handshake_record()
    sock.recv_handshake_record()
    sock.recv_handshake_record()



def finish_handshake(sock: client.TLSSocket, handshake_secret: bytes) -> None:
    """
    Receives the server finish, sends the client finish, and derives the application keys.

    Takes in the shared secret from key exchange.
    """
    # TODO: implement
    sock.recv_handshake_record()
    sock.send_handshake_record(HandshakeType.FINISHED,compute_finish(handshake_secret,sock.transcript_hash.digest()))
    derive_application_params(handshake_secret, sock.transcript_hash.digest())
    
    


def perform_handshake(sock: client.TLSSocket) -> None:
    key_exchange_keypair = cryptoimpl.generate_x25519_keypair()
    send_client_hello(sock, key_exchange_keypair[1])
    peer_pubkey = recv_server_hello(sock)
    shared_secret = cryptoimpl.derive_shared_x25519_key(
        key_exchange_keypair[0], peer_pubkey
    )
    transcript_hash = sock.transcript_hash.digest()
    (handshake_secret, sock.client_params, sock.server_params) = (
        cryptoimpl.derive_handshake_params(shared_secret, transcript_hash)
    )
    recv_server_info(sock)
    finish_handshake(sock, handshake_secret)

    # key_derivation()

    # receive an encrypted handshake record to verify decryption works
    print("got record:", sock.recv_handshake_record())

    sock.send_record(RecordType.APPLICATION_DATA, b"hellohellooooooooooooooooooooooooo:)ooooooooooooo\n")
    

# We don't need this lol there's a skeleton in cryptoimpl.py
# def key_derivation(transcript_hash, shared_secret):

#     our_key = generate_x25519_keypair()

#     early_secret = sha384_hkdf_extract(00, 00)
#     empty_hash = hashes.SHA384("")
#     hello_hash = transcript_hash

#     derived_secret = labeled_sha384_hkdf(early_secret, "derived", empty_hash, 48)
#     handshake_secret = sha384_hkdf_extract(derived_secret, shared_secret)
#     client_secret = labeled_sha384_hkdf(handshake_secret, "c hs traffic", hello_hash, 48)
#     server_secret = labeled_sha384_hkdf(handshake_secret, "s hs traffic", hello_hash, 48)
#     client_handshake_key = labeled_sha384_hkdf(client_secret, "key", "", 32)
#     server_handskae_key = labeled_sha384_hkdf(server_secret, "key", "",32)
#     client_handshake_iv = labeled_sha384_hkdf(client_secret, "iv", "", 12)
#     server_handshake_iv = labeled_sha384_hkdf(server_secret, "iv", "", 12)


# We also don't need this LOL it's written into client.py
# def parsing_ciphertext(response):
#     without_type = response[2:]
#     length = without_type[0:2].int_from_bytes()
#     without_type = without_type[2:]
#     ciphertext = without_type[0:length]
#     without_type = without_type[length:]
#     tag = without_type[:16]

# def decryption(ciphertext):
#     ciphertext_with_length = pack_varlen(ciphertext,3)
#     final_ciphertext = b'\x08' + ciphertext_with_length


