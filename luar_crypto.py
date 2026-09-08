"""
LuaR Crypto — AES-256-GCM + Scrypt
seed = 32 random bytes (generated at protect time, stored in .luar)
"""

import os, hashlib
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
AAD       = b"LuaR-tanakorn-v2"


class AuthenticationError(Exception):
    pass


def _derive_key(seed: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(seed)


def protect_payload(plaintext: bytes):
    """Generate random seed, encrypt. Returns (seed, ct, salt, nonce, tag)."""
    seed  = os.urandom(32)
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = _derive_key(seed, salt)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, AAD)
    return seed, ct_tag[:-TAG_LEN], salt, nonce, ct_tag[-TAG_LEN:]


def unprotect_payload(ciphertext: bytes, salt: bytes, nonce: bytes,
                      tag: bytes, seed: bytes) -> bytes:
    key = _derive_key(seed, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, AAD)
    except InvalidTag:
        raise AuthenticationError("Authentication failed — corrupted file.")
