"""
LuaR Binary Format v2 — with embedded seed and obfuscation layers

Visible structure (plaintext prefix):
  [0..N)    Banner: null-terminated UTF-8 string
              e.g. b"Encrypted by LuaR Protector\x00"
  [N..N+8)  Magic + scramble hint: b"\x4c\x75\x61\x52" XOR 4 junk bytes
              (raw: magic_xored[4] + junk[4])

After banner+magic (all remaining bytes = opaque blob):
  Layout of the opaque blob (before it reaches the caller, the
  runtime must peel 4 layers):

  Layer 0 — outer junk envelope
    junk_a[JUNK_A]            deterministic noise, skip via JUNK_A constant
    seed_block[SEED_BLOCK]    encrypted seed (see below)
    junk_b[JUNK_B]            more noise
    inner_blob[*]             the real AES-GCM envelope

  seed_block layout (64 bytes total):
    decoy_salt[16]            looks like a salt, is random noise
    enc_seed[32]              actual random seed XOR'd with derive_seed_xor_key()
    seed_mac[16]              HMAC-SHA256(enc_seed, xor_key)[:16] — integrity check

  inner_blob layout:
    decoy_nonce[12]           random, unused — confuses static analysis
    salt[SALT_LEN=32]         real Scrypt salt
    nonce[NONCE_LEN=12]       real AES-GCM nonce
    payload_len[4]            uint32 LE
    ciphertext[payload_len]
    tag[TAG_LEN=16]

Constants embedded in code (reverse-engineer bait):
  JUNK_A, JUNK_B — derived from banner length and magic, not magic by themselves
"""

import os
import struct
import hmac
import hashlib
from pathlib import Path

# ── Visible prefix ─────────────────────────────────────────────────────────
BANNER        = b"Encrypted by LuaR Protector"
MAGIC_RAW     = b"\x4c\x75\x61\x52"      # "LuaR" — XOR'd before writing

# ── Seed block ──────────────────────────────────────────────────────────────
DECOY_SALT_LEN  = 16
REAL_SEED_LEN   = 32
SEED_MAC_LEN    = 16
SEED_BLOCK_LEN  = DECOY_SALT_LEN + REAL_SEED_LEN + SEED_MAC_LEN  # 64

# ── Inner crypto ────────────────────────────────────────────────────────────
DECOY_NONCE_LEN = 12
SALT_LEN        = 32
NONCE_LEN       = 12
TAG_LEN         = 16

# ── Junk sizing (deterministic from banner) ──────────────────────────────────
def _junk_sizes():
    b = sum(BANNER) & 0xFF          # 0xB3 = 179  → not immediately obvious
    JUNK_A = (b ^ 0x5A) % 64 + 16   # range [16,79]
    JUNK_B = (b ^ 0xA5) % 64 + 24   # range [24,87]
    return JUNK_A, JUNK_B

JUNK_A, JUNK_B = _junk_sizes()


# ── XOR key for seed encryption (self-referential fingerprint) ───────────────
def _derive_seed_xor_key(junk_a_bytes: bytes, magic_xored: bytes) -> bytes:
    """
    Key = HMAC-SHA256(junk_a_bytes, magic_xored)
    Both inputs are stored in the file itself → any tampering breaks decryption.
    32 bytes output, same length as seed.
    """
    return hmac.new(magic_xored, junk_a_bytes, hashlib.sha256).digest()


# ── Junk generators (deterministic-looking, seeded from os.urandom at pack time)
def _make_junk(length: int, seed_bytes: bytes) -> bytes:
    """Pseudo-random junk that looks like crypto material."""
    h = hashlib.sha256(seed_bytes).digest()
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(h + counter.to_bytes(4, "little")).digest()
        counter += 1
    return out[:length]


class FormatError(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
#  PACK
# ─────────────────────────────────────────────────────────────────────────────

def pack_luar(path: Path, salt: bytes, nonce: bytes,
              payload: bytes, tag: bytes, seed_hex: str) -> None:
    """
    Embed seed_hex obfuscated into the file alongside the encrypted payload.
    seed_hex comes from protect_payload() in luar_crypto.py.
    """
    # 1. Decode seed from hex
    real_seed_bytes = bytes.fromhex(seed_hex)

    # 2. Banner (null-terminated plaintext)
    banner_bytes = BANNER + b"\x00"

    # 3. Magic XOR'd with 4 random junk bytes stored right after
    junk_magic = os.urandom(4)
    magic_xored = bytes(a ^ b for a, b in zip(MAGIC_RAW, junk_magic))
    magic_block = magic_xored + junk_magic   # 8 bytes

    # 4. Junk A (deterministic from random entropy)
    junk_a_seed = os.urandom(8)
    junk_a = _make_junk(JUNK_A, junk_a_seed)

    # 5. Seed block
    xor_key      = _derive_seed_xor_key(junk_a, magic_xored)
    enc_seed     = bytes(a ^ b for a, b in zip(real_seed_bytes, xor_key))
    decoy_salt_b = os.urandom(DECOY_SALT_LEN)
    seed_mac     = hmac.new(xor_key, enc_seed, hashlib.sha256).digest()[:SEED_MAC_LEN]
    seed_block   = decoy_salt_b + enc_seed + seed_mac

    # 6. Junk B
    junk_b_seed = os.urandom(8)
    junk_b = _make_junk(JUNK_B, junk_b_seed)

    # 7. Inner blob: decoy_nonce + real crypto fields
    decoy_nonce  = os.urandom(DECOY_NONCE_LEN)
    payload_len  = struct.pack("<I", len(payload))
    inner_blob   = decoy_nonce + salt + nonce + payload_len + payload + tag

    # 8. Assemble opaque blob with junk seeds prepended (needed for unpack)
    # Layout of opaque blob:
    #   junk_a_seed[8] | junk_a[JUNK_A] | seed_block[64] | junk_b_seed[8] | junk_b[JUNK_B] | inner_blob
    opaque = junk_a_seed + junk_a + seed_block + junk_b_seed + junk_b + inner_blob

    with open(path, "wb") as f:
        f.write(banner_bytes)
        f.write(magic_block)
        f.write(opaque)


# ─────────────────────────────────────────────────────────────────────────────
#  UNPACK
# ─────────────────────────────────────────────────────────────────────────────

def unpack_luar(path: Path):
    """
    Parse a .luar file.
    Returns (salt, nonce, payload, tag, seed_hex).
    Raises FormatError on structural or integrity problems.
    """
    data = path.read_bytes()
    off  = 0

    # 1. Banner (null-terminated)
    null = data.find(b"\x00", off)
    if null < 0:
        raise FormatError("Missing banner terminator")
    banner = data[off:null]
    off = null + 1

    # 2. Magic block (8 bytes)
    if off + 8 > len(data):
        raise FormatError("File too small: missing magic block")
    magic_xored = data[off:off+4]
    junk_magic  = data[off+4:off+8]
    off += 8
    recovered_magic = bytes(a ^ b for a, b in zip(magic_xored, junk_magic))
    if recovered_magic != MAGIC_RAW:
        raise FormatError("Invalid magic — file corrupted or wrong format")

    # 3. Junk A
    if off + 8 > len(data):
        raise FormatError("File too small: missing junk_a_seed")
    junk_a_seed = data[off:off+8]; off += 8
    junk_a      = _make_junk(JUNK_A, junk_a_seed)
    off += JUNK_A

    # 4. Seed block
    if off + SEED_BLOCK_LEN > len(data):
        raise FormatError("File too small: missing seed block")
    decoy_salt_b = data[off:off+DECOY_SALT_LEN]; off += DECOY_SALT_LEN
    enc_seed     = data[off:off+REAL_SEED_LEN];  off += REAL_SEED_LEN
    seed_mac     = data[off:off+SEED_MAC_LEN];   off += SEED_MAC_LEN

    xor_key = _derive_seed_xor_key(junk_a, magic_xored)

    # Verify MAC before XOR
    expected_mac = hmac.new(xor_key, enc_seed, hashlib.sha256).digest()[:SEED_MAC_LEN]
    if not hmac.compare_digest(seed_mac, expected_mac):
        raise FormatError("Seed block integrity check failed — file tampered")

    real_seed_bytes = bytes(a ^ b for a, b in zip(enc_seed, xor_key))

    # 5. Junk B
    if off + 8 > len(data):
        raise FormatError("File too small: missing junk_b_seed")
    junk_b_seed = data[off:off+8]; off += 8
    off += JUNK_B  # skip junk_b

    # 6. Inner blob
    if off + DECOY_NONCE_LEN > len(data):
        raise FormatError("File too small: missing decoy nonce")
    off += DECOY_NONCE_LEN   # skip decoy nonce

    if off + SALT_LEN + NONCE_LEN + 4 > len(data):
        raise FormatError("File too small: missing crypto fields")
    salt  = data[off:off+SALT_LEN];  off += SALT_LEN
    nonce = data[off:off+NONCE_LEN]; off += NONCE_LEN

    payload_len = struct.unpack_from("<I", data, off)[0]; off += 4
    expected_end = off + payload_len + TAG_LEN
    if expected_end != len(data):
        raise FormatError(
            f"Payload length mismatch: expected {payload_len} bytes, "
            f"file has {len(data) - off - TAG_LEN}"
        )

    payload = data[off:off+payload_len]; off += payload_len
    tag     = data[off:off+TAG_LEN]

    return salt, nonce, payload, tag, real_seed_bytes.hex()
