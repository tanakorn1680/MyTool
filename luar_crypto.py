"""
LuaR Crypto Module

- KDF : Scrypt (N=2^17, r=8, p=1)
- AEAD: AES-256-GCM
- Salt : 32 random bytes
- Nonce: 12 random bytes
- Tag  : 16 bytes (GCM standard)
"""

import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# KDF parameters
SCRYPT_N = 2 ** 14   # lowered for serverless (was 2**17)
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN  = 32        # AES-256
SALT_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

# Fixed AAD tied to the format — provides domain separation
AAD = b"LuaR-v1"


class AuthenticationError(Exception):
    pass


def _derive_key(seed: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(seed.encode("utf-8"))


def protect_payload(plaintext: bytes, seed: str):
    """
    Encrypt plaintext with AES-256-GCM using a seed-derived key.

    Returns (ciphertext_without_tag, salt, nonce, tag).
    The tag is extracted separately so we can store it in the header.
    """
    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = _derive_key(seed, salt)

    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag (tag is last TAG_LEN bytes)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, AAD)

    ciphertext = ct_with_tag[:-TAG_LEN]
    tag        = ct_with_tag[-TAG_LEN:]

    return ciphertext, salt, nonce, tag


def unprotect_payload(ciphertext: bytes, salt: bytes, nonce: bytes,
                      tag: bytes, seed: str) -> bytes:
    """
    Decrypt and authenticate.  Raises AuthenticationError on any failure.
    """
    key = _derive_key(seed, salt)
    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + tag
    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, AAD)
    except InvalidTag:
        raise AuthenticationError(
            "Authentication failed — wrong seed or corrupted file."
        )
    return plaintext
