"""
Utility functions for various aspects of TLS.
"""


def pack(num: int, width: int = 1) -> bytes:
    """
    Packs the integer `num` to `width` bytes.

    Specified in RFC8446 section 3.3.
    """
    return num.to_bytes(width, "big")


def pack_varlen(data: bytes, len_width: int = 2) -> bytes:
    """
    Packs variable length data.
    `len_width` is the number of bytes to use for the length.

    Specified in RFC8446 section 3.4.
    """
    return len(data).to_bytes(len_width, "big") + data


def pack_extension(ty: int, data: bytes) -> bytes:
    """
    Packs TLS extension data.

    Specified in RFC8446 section 4.2.
    """
    return pack(ty, 2) + pack_varlen(data)
