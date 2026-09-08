"""
LuaR Binary Format

Offset  Size  Field
------  ----  -----
0       4     Magic: b"LuaR"
4       2     Format version (uint16 LE) — currently 1
6       2     Runtime version (uint16 LE) — currently 1
8       4     Flags (uint32 LE) — reserved, must be 0
12      32    Salt (random, for KDF)
44      12    Nonce (random, for AES-GCM)
56      4     Payload length (uint32 LE)
60      N     Encrypted payload
60+N    16    Authentication tag (GCM)

Total minimum size: 60 + 0 + 16 = 76 bytes
"""

import struct
from pathlib import Path

MAGIC           = b"LuaR"
FORMAT_VERSION  = 1
RUNTIME_VERSION = 1
FLAGS           = 0

SALT_LEN    = 32
NONCE_LEN   = 12
TAG_LEN     = 16

HEADER_FMT  = "<4sHHI"          # magic, fmt_ver, rt_ver, flags
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 12 bytes


class FormatError(Exception):
    pass


def pack_luar(path: Path, salt: bytes, nonce: bytes,
              payload: bytes, tag: bytes) -> None:
    """Write a .luar file."""
    header = struct.pack(HEADER_FMT, MAGIC, FORMAT_VERSION, RUNTIME_VERSION, FLAGS)
    payload_len = struct.pack("<I", len(payload))

    with open(path, "wb") as f:
        f.write(header)         # 12 bytes
        f.write(salt)           # 32 bytes
        f.write(nonce)          # 12 bytes
        f.write(payload_len)    #  4 bytes
        f.write(payload)        #  N bytes
        f.write(tag)            # 16 bytes


def unpack_luar(path: Path):
    """
    Read and validate a .luar file.

    Returns (salt, nonce, payload, tag).
    Raises FormatError on any structural problem.
    """
    data = path.read_bytes()
    min_size = HEADER_SIZE + SALT_LEN + NONCE_LEN + 4 + 0 + TAG_LEN
    if len(data) < min_size:
        raise FormatError("File too small to be a valid .luar")

    offset = 0
    magic, fmt_ver, rt_ver, flags = struct.unpack_from(HEADER_FMT, data, offset)
    offset += HEADER_SIZE

    if magic != MAGIC:
        raise FormatError(f"Invalid magic: expected {MAGIC!r}, got {magic!r}")
    if fmt_ver != FORMAT_VERSION:
        raise FormatError(
            f"Unsupported format version {fmt_ver} (this runtime supports {FORMAT_VERSION})"
        )
    if rt_ver != RUNTIME_VERSION:
        raise FormatError(
            f"Unsupported runtime version {rt_ver} (this runtime supports {RUNTIME_VERSION})"
        )
    if flags != 0:
        raise FormatError(f"Unknown flags: 0x{flags:08X}")

    salt  = data[offset:offset+SALT_LEN];   offset += SALT_LEN
    nonce = data[offset:offset+NONCE_LEN];  offset += NONCE_LEN

    payload_len = struct.unpack_from("<I", data, offset)[0]; offset += 4

    expected_total = offset + payload_len + TAG_LEN
    if expected_total != len(data):
        raise FormatError(
            f"Payload length mismatch: header says {payload_len} bytes, "
            f"file has {len(data) - offset - TAG_LEN} bytes"
        )

    payload = data[offset:offset+payload_len]; offset += payload_len
    tag     = data[offset:offset+TAG_LEN]

    return salt, nonce, payload, tag
