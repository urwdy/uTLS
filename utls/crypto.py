"""Cryptographic primitives used by the TLS state machine.

Only thin wrappers around :mod:`cryptography` plus HKDF / PRF helpers live
here; the TLS record and handshake logic lives in the other modules.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

try:  # cryptography 48+ moved 3DES to the "decrepit" namespace
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover - older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from . import mlkem
from .errors import RecordError
from .constants import (
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
    GROUP_X25519,
    GROUP_X25519_MLKEM768,
    VERSION_TLS10,
    VERSION_TLS12,
    VERSION_TLS13,
)

HASHES = {
    "md5": hashlib.md5,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha1": hashlib.sha1,
}

CRYPTO_HASHES = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha1": hashes.SHA1,
}


def hash_len(name: str) -> int:
    return HASHES[name]().digest_size


def new_hash(name: str):
    return HASHES[name]()


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) and TLS 1.3 HKDF-Expand-Label
# ---------------------------------------------------------------------------


def hkdf_extract(hash_name: str, salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * hash_len(hash_name)
    return hmac.new(salt, ikm, HASHES[hash_name]).digest()


def hkdf_expand(hash_name: str, prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), HASHES[hash_name]).digest()
        out += t
        counter += 1
    return out[:length]


def hkdf_expand_label(hash_name: str, secret: bytes, label: str, context: bytes, length: int) -> bytes:
    label_bytes = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(label_bytes)]) + label_bytes
    info += bytes([len(context)]) + context
    return hkdf_expand(hash_name, secret, info, length)


def derive_secret(hash_name: str, secret: bytes, label: str, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(hash_name, secret, label, transcript_hash, hash_len(hash_name))


# ---------------------------------------------------------------------------
# TLS 1.2 PRF (RFC 5246)
# ---------------------------------------------------------------------------


def tls12_prf(hash_name: str, secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    label_seed = label + seed
    out = b""
    a = label_seed
    while len(out) < length:
        a = hmac.new(secret, a, HASHES[hash_name]).digest()
        out += hmac.new(secret, a + label_seed, HASHES[hash_name]).digest()
    return out[:length]


def _p_hash(hash_name: str, secret: bytes, seed: bytes, length: int) -> bytes:
    out = b""
    a = seed
    while len(out) < length:
        a = hmac.new(secret, a, HASHES[hash_name]).digest()
        out += hmac.new(secret, a + seed, HASHES[hash_name]).digest()
    return out[:length]


def tls10_prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.0/1.1 PRF: P_MD5 XOR P_SHA1 with overlapping secret halves."""
    half = (len(secret) + 1) // 2
    s1 = secret[:half]
    s2 = secret[-half:]
    label_seed = label + seed
    md5 = _p_hash("md5", s1, label_seed, length)
    sha1 = _p_hash("sha1", s2, label_seed, length)
    return bytes(a ^ b for a, b in zip(md5, sha1))


def tls_prf(
    version: int, hash_name: str, secret: bytes, label: bytes, seed: bytes, length: int
) -> bytes:
    """PRF dispatcher for TLS 1.0-1.3 (TLS 1.2 and 1.3 share P_hash)."""
    if version >= VERSION_TLS12:
        return tls12_prf(hash_name, secret, label, seed, length)
    return tls10_prf(secret, label, seed, length)


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------


@dataclass
class RecordCipher:
    """Symmetric state of one direction of a TLS connection."""

    suite: object  # constants.CipherSuite
    key: bytes
    iv: bytes
    seq: int = 0
    version: int = VERSION_TLS13
    mac_key: bytes = b""

    def __post_init__(self) -> None:
        if self.suite.aead == "aes-gcm":
            self._aead = AESGCM(self.key)
        elif self.suite.aead == "chacha20-poly1305":
            self._aead = ChaCha20Poly1305(self.key)
        elif self.suite.aead == "aes-cbc":
            if len(self.key) == 24:
                self._block_cipher = TripleDES(self.key)
            else:
                self._block_cipher = algorithms.AES(self.key)
            self._aead = None
        else:  # pragma: no cover - guarded by cipher suite table
            raise ValueError(f"unsupported AEAD {self.suite.aead}")

    # -- TLS 1.3 -----------------------------------------------------------
    def seal_tls13(self, plaintext: bytes, content_type: int) -> bytes:
        nonce = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))
        inner = plaintext + bytes([content_type])
        aad = b"\x17\x03\x03" + struct.pack("!H", len(inner) + 16)
        out = self._aead.encrypt(nonce, inner, aad)
        self.seq += 1
        return out

    def open_tls13(self, ciphertext: bytes, header: bytes) -> tuple[bytes, int]:
        nonce = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))
        try:
            inner = self._aead.decrypt(nonce, ciphertext, header)
        except InvalidTag as exc:
            raise RecordError("TLS record authentication failed (bad record MAC)") from exc
        self.seq += 1
        if not inner:
            raise ValueError("empty TLS 1.3 inner plaintext")
        # Strip zero padding, the last non-zero byte is the content type.
        i = len(inner) - 1
        while i >= 0 and inner[i] == 0:
            i -= 1
        if i < 0:
            raise ValueError("invalid TLS 1.3 inner plaintext")
        return inner[:i], inner[i]

    # -- TLS 1.2 AEAD / CBC ------------------------------------------------
    def _tls12_mac(self, content_type: int, version: int, data: bytes) -> bytes:
        header = (
            self.seq.to_bytes(8, "big")
            + bytes([content_type])
            + struct.pack("!H", version)
            + struct.pack("!H", len(data))
        )
        return hmac.new(self.mac_key, header + data, HASHES[self.suite.mac_hash]).digest()

    def seal_tls12(self, plaintext: bytes, content_type: int, version: int) -> bytes:
        if self.suite.aead == "aes-cbc":
            block = self.suite.block_size
            mac = self._tls12_mac(content_type, version, plaintext)
            fragment = plaintext + mac
            pad_len = (block - ((len(fragment) + 1) % block)) % block
            fragment += bytes([pad_len]) * (pad_len + 1)
            if version <= VERSION_TLS10:
                # TLS 1.0 uses the previous ciphertext block as the IV.
                explicit_iv = self.iv
            else:
                explicit_iv = os.urandom(block)
            encryptor = Cipher(self._block_cipher, modes.CBC(explicit_iv)).encryptor()
            ciphertext = encryptor.update(fragment) + encryptor.finalize()
            if version <= VERSION_TLS10:
                self.iv = ciphertext[-block:]
                self.seq += 1
                return ciphertext
            self.seq += 1
            return explicit_iv + ciphertext
        if self.suite.aead == "chacha20-poly1305":
            nonce = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))
            explicit = b""
        else:
            explicit = self.seq.to_bytes(8, "big")
            nonce = self.iv + explicit
        aad = (
            self.seq.to_bytes(8, "big")
            + bytes([content_type])
            + struct.pack("!H", version)
            + struct.pack("!H", len(plaintext))
        )
        out = explicit + self._aead.encrypt(nonce, plaintext, aad)
        self.seq += 1
        return out

    def open_tls12(self, payload: bytes, content_type: int, version: int) -> bytes:
        if self.suite.aead == "aes-cbc":
            block = self.suite.block_size
            if version <= VERSION_TLS10:
                if len(payload) < block*2 or len(payload) % block:
                    raise RecordError("invalid TLS CBC record length")
                explicit_iv, ciphertext = self.iv, payload
            else:
                if len(payload) < 2 * block or (len(payload) - block) % block:
                    raise RecordError("invalid TLS CBC record length")
                explicit_iv, ciphertext = payload[:block], payload[block:]
            decryptor = Cipher(self._block_cipher, modes.CBC(explicit_iv)).decryptor()
            fragment = decryptor.update(ciphertext) + decryptor.finalize()
            if version <= VERSION_TLS10:
                self.iv = ciphertext[-block:]
            pad_len = fragment[-1]
            if pad_len + 1 > len(fragment):
                raise RecordError("invalid TLS CBC padding")
            if any(byte != pad_len for byte in fragment[-pad_len - 1 :]):
                raise RecordError("invalid TLS CBC padding")
            content = fragment[: -pad_len - 1]
            mac_len = self.suite.mac_key_len
            if len(content) < mac_len:
                raise RecordError("short TLS CBC record")
            received_mac = content[-mac_len:]
            data = content[:-mac_len]
            expected_mac = self._tls12_mac(content_type, version, data)
            if not hmac.compare_digest(received_mac, expected_mac):
                raise RecordError("TLS record authentication failed (bad record MAC)")
            self.seq += 1
            return data
        if self.suite.aead == "chacha20-poly1305":
            explicit = b""
            nonce = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))
        else:
            if len(payload) < 8:
                raise ValueError("short TLS 1.2 AEAD record")
            explicit = payload[:8]
            nonce = self.iv + explicit
            payload = payload[8:]
        plaintext_len = len(payload) - 16
        if plaintext_len < 0:
            raise ValueError("short TLS 1.2 AEAD record")
        aad = (
            self.seq.to_bytes(8, "big")
            + bytes([content_type])
            + struct.pack("!H", version)
            + struct.pack("!H", plaintext_len)
        )
        try:
            out = self._aead.decrypt(nonce, payload, aad)
        except InvalidTag as exc:
            raise RecordError("TLS record authentication failed (bad record MAC)") from exc
        self.seq += 1
        return out

# ---------------------------------------------------------------------------
# Key exchange
# ---------------------------------------------------------------------------


@dataclass
class KeySharePrivate:
    group: int
    private_key: object
    public_key: bytes

    def decapsulate(self, peer_public: bytes, version: int) -> bytes:
        if self.group == GROUP_X25519:
            return self.private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
        if self.group in (GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1):
            peer = ec.EllipticCurvePublicKey.from_encoded_point(self.private_key.curve, peer_public)
            return self.private_key.exchange(ec.ECDH(), peer)
        if self.group == GROUP_X25519_MLKEM768:
            # hybrid share: ML-KEM-768 ciphertext (1088) || X25519 public key (32)
            if version == VERSION_TLS13:
                if len(peer_public) < 32:
                    raise ValueError("short hybrid key share")
                mlkem_ct, x25519_pub = peer_public[:-32], peer_public[-32:]
                ss_mlkem = mlkem.decapsulate(self.private_key["mlkem"], mlkem_ct)
                ss_x = self.private_key["x25519"].exchange(
                    x25519.X25519PublicKey.from_public_bytes(x25519_pub)
                )
                return ss_mlkem + ss_x
            raise ValueError("hybrid group requires TLS 1.3")
        raise ValueError(f"unsupported group {self.group:#06x}")


def generate_key_share(group: int, curve_hint: int | None = None) -> KeySharePrivate:
    if group == GROUP_X25519:
        sk = x25519.X25519PrivateKey.generate()
        return KeySharePrivate(group, sk, sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ))
    if group in (GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1):
        curve = {
            GROUP_SECP256R1: ec.SECP256R1(),
            GROUP_SECP384R1: ec.SECP384R1(),
            GROUP_SECP521R1: ec.SECP521R1(),
        }[group]
        sk = ec.generate_private_key(curve)
        pub = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return KeySharePrivate(group, sk, pub)
    if group == GROUP_X25519_MLKEM768:
        ek, dk = mlkem.keygen()
        sk = x25519.X25519PrivateKey.generate()
        x_pub = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return KeySharePrivate(group, {"mlkem": dk, "x25519": sk}, ek + x_pub)
    raise ValueError(f"unsupported key share group {group:#06x}")
