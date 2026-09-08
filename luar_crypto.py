"""
LuaR Crypto Module v2

Seed comes from luar_format (embedded in file), not from the user.
KDF  : Scrypt (N=2^14, r=8, p=1) — serverless-safe
AEAD : AES-256-GCM
"""

import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

SCRYPT_N  = 2 ** 14
SCRYPT_R  = 8
SCRYPT_P  = 1
KEY_LEN   = 32
SALT_LEN  = 32
NONCE_LEN = 12
TAG_LEN   = 16

# Fixed AAD — domain separation; changing this invalidates all existing files
AAD = b"LuaR-v2"


class AuthenticationError(Exception):
    pass


def _derive_key(seed_hex: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(bytes.fromhex(seed_hex))


def protect_payload(plaintext: bytes):
    """
    Encrypt plaintext. Seed is generated internally.
    Returns (ciphertext, salt, nonce, tag, seed_hex).
    seed_hex must be passed to pack_luar to embed in the file.
    """
    seed_hex = os.urandom(32).hex()
    salt     = os.urandom(SALT_LEN)
    nonce    = os.urandom(NONCE_LEN)
    key      = _derive_key(seed_hex, salt)

    aesgcm      = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, AAD)

    ciphertext = ct_with_tag[:-TAG_LEN]
    tag        = ct_with_tag[-TAG_LEN:]

    return ciphertext, salt, nonce, tag, seed_hex


def unprotect_payload(ciphertext: bytes, salt: bytes, nonce: bytes,
                      tag: bytes, seed_hex: str) -> bytes:
    """
    Decrypt using seed_hex recovered from the file by unpack_luar.
    Raises AuthenticationError on any failure.
    """
    key = _derive_key(seed_hex, salt)
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    try:
        return aesgcm.decrypt(nonce, ct_with_tag, AAD)
    except InvalidTag:
        raise AuthenticationError(
            "Authentication failed — file corrupted or tampered."
        )
