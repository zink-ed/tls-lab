"""
The actual TLS v1.3 client implementation.
"""

from __future__ import annotations

import socket
from typing import Any

from tlsimpl import handshake, util
from tlsimpl.consts import *


class TLSSocket:
    """
    A wrapper class around an inner socket.
    """

    inner: socket.socket

    def __init__(self, inner: socket.socket) -> None:
        """
        Constructs a new TLSSocket instance from an inner socket.

        Performs the TLS handshake.
        """
        self.inner = inner
        handshake.perform_handshake(self)

    @staticmethod
    def create_connection(*args: Any, **kwargs: Any) -> TLSSocket:
        """
        Utility function to create a TLS connection.
        """
        return TLSSocket(socket.create_connection(*args, **kwargs))

    def send_handshake_record(self, typ: HandshakeType, data: bytes) -> None:
        """
        Utility function to send a record containing a single handshake message.

        Records are specified in RFC8446 section 5.
        Handshake messages are specified in RFC8446 section 4.
        """
        packet = [
            # record
            util.pack(RecordType.HANDSHAKE),  # record type
            b"\x03\x03",  # record version
            util.pack(
                len(data) + 4, 2
            ),  # record data length (add 4 for handshake header)
            # handshake
            util.pack(typ),  # handshake type
            util.pack(len(data), 3),  # handshake data length
            data,  # handshake data
        ]
        self.inner.sendall(b"".join(packet))

    def recv_raw(self, length: int):
        """
        Utility function to receive a certain amount of bytes from the socket.

        Will only return fewer bytes if the client disconnects.
        """
        chunks = []
        while length > 0:
            temp = self.inner.recv(length)
            if not temp:
                break
            length -= len(temp)
            chunks.append(temp)
        return b"".join(chunks)

    # The rest of these are just housekeeping functions
    def close(self) -> None:
        self.inner.close()

    def __enter__(self) -> None:
        self.inner.__enter__()

    def __exit__(self, *args: tuple[Any, ...]) -> None:
        self.inner.__exit__(*args)
