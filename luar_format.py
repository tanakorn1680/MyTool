"""
LuaR Format v2 — mimics Lua bytecode header visually
ขึ้นต้นด้วย \x1bLuaR เหมือน Lua bytecode จริง
ฝัง banner ไว้ใน header เหมือน SCBI
Seed random อัตโนมัติ ฝังใน file (mask ด้วย XOR)
"""

import os, struct, hashlib
from pathlib import Path

# Visual magic เหมือน Lua bytecode header
MAGIC        = b"\x1bLuaR"          # ESC + LuaR — เหมือน \x1bLua52 etc.
LUA_HEADER   = b"\x00\x01\x04\x04\x04\x08\x00\x19\x93\r\n\x1a\n"  # Lua 5.2 header bytes

BANNER       = b" \xe2\xbb\xac Encrypted by Tanakorn \x00"  # Unicode ปน binary

FORMAT_VER   = 2
RUNTIME_VER  = 1

SEED_LEN  = 32
SALT_LEN  = 32
NONCE_LEN = 12
TAG_LEN   = 16

# Mask ทำให้ seed ดูเป็น binary noise
_MASK = hashlib.sha256(b"luar-tanakorn-v2-seed-mask").digest()

def _mask(b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(b, _MASK))


class FormatError(Exception):
    pass


def pack_luar(path: Path, seed: bytes, salt: bytes, nonce: bytes,
              payload: bytes, tag: bytes) -> None:
    """
    Layout:
      5   \x1bLuaR
      13  Lua-like header bytes (binary noise)
      4   fmt_ver + rt_ver (uint16 LE x2)
      4   flags uint32 LE
      len(BANNER)  banner text (มี binary chars ปน)
      32  masked seed
      32  salt
      12  nonce
      4   payload_len
      N   encrypted payload
      16  GCM tag
    """
    hdr = struct.pack("<HHI", FORMAT_VER, RUNTIME_VER, 0)
    masked_seed = _mask(seed)

    with open(path, "wb") as f:
        f.write(MAGIC)
        f.write(LUA_HEADER)
        f.write(hdr)
        f.write(BANNER)
        f.write(masked_seed)
        f.write(salt)
        f.write(nonce)
        f.write(struct.pack("<I", len(payload)))
        f.write(payload)
        f.write(tag)


# precompute header offset
_FIXED_HDR = len(MAGIC) + len(LUA_HEADER) + 8 + len(BANNER)

def unpack_luar(path: Path):
    """Returns (seed, salt, nonce, payload, tag)"""
    data = path.read_bytes()
    min_sz = _FIXED_HDR + SEED_LEN + SALT_LEN + NONCE_LEN + 4 + TAG_LEN
    if len(data) < min_sz:
        raise FormatError("File too small")

    off = 0
    if data[off:off+5] != MAGIC:
        raise FormatError(f"Invalid magic: {data[off:off+5]!r}")
    off += 5
    off += 13  # skip Lua header bytes

    fmt_ver, rt_ver, flags = struct.unpack_from("<HHI", data, off); off += 8
    if fmt_ver != FORMAT_VER:
        raise FormatError(f"Unsupported format version {fmt_ver}")
    if flags != 0:
        raise FormatError(f"Unknown flags")

    off += len(BANNER)  # skip banner

    seed  = _mask(data[off:off+SEED_LEN]);  off += SEED_LEN
    salt  = data[off:off+SALT_LEN];         off += SALT_LEN
    nonce = data[off:off+NONCE_LEN];        off += NONCE_LEN

    plen = struct.unpack_from("<I", data, off)[0]; off += 4
    if off + plen + TAG_LEN != len(data):
        raise FormatError("Payload length mismatch")

    payload = data[off:off+plen]; off += plen
    tag     = data[off:off+TAG_LEN]
    return seed, salt, nonce, payload, tag
