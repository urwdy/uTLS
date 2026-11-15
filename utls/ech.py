"""TLS Encrypted ClientHello (RFC 9849) client support.

The module implements ECH configuration parsing, the HPKE base-mode seal
operation used for ``ClientHelloInner``, and construction of the inner/outer
ClientHello pair.  HPKE (RFC 9180) is implemented locally instead of using
``cryptography.hazmat.primitives.hpke`` because ECH has to know the
encapsulated key before it can authenticate the outer ClientHello as AEAD
associated data, and the high-level HPKE API generates that key internally.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .constants import (
    CIPHER_SUITES,
    EXT_COOKIE,
    EXT_EARLY_DATA,
    EXT_ENCRYPTED_CLIENT_HELLO,
    EXT_PADDING,
    EXT_PRE_SHARED_KEY,
    EXT_SUPPORTED_VERSIONS,
    GROUP_X25519,
    VERSION_TLS13,
    is_grease,
)
from .crypto import hkdf_expand, hkdf_expand_label, hkdf_extract, hash_len
from .errors import UTLSError
from .extensions import (
    CookieExtension,
    ECHInnerExtension,
    ECHOuterExtension,
    EarlyDataExtension,
    KeyShareEntry,
    KeyShareExtension,
    PSKKeyExchangeModesExtension,
    PreSharedKeyExtension,
    SupportedGroupsExtension,
    SupportedVersionsExtension,
    uint8,
    uint16,
    vec8,
    vec16,
)
from .hello import BuiltClientHello, ClientHelloSpec, build_client_hello

#: ``encrypted_client_hello`` extension / ECH version.
ECH_VERSION = 0xFE0D
ECH_CLIENT_HELLO_OUTER = 0
ECH_CLIENT_HELLO_INNER = 1

# HPKE identifiers from RFC 9180.
HPKE_KEM_P256 = 0x0010
HPKE_KEM_P384 = 0x0011
HPKE_KEM_P521 = 0x0012
HPKE_KEM_X25519 = 0x0020

HPKE_KDF_HKDF_SHA256 = 0x0001
HPKE_KDF_HKDF_SHA384 = 0x0002
HPKE_KDF_HKDF_SHA512 = 0x0003

HPKE_AEAD_AES_128_GCM = 0x0001
HPKE_AEAD_AES_256_GCM = 0x0002
HPKE_AEAD_CHACHA20_POLY1305 = 0x0003

_KDF_HASHES = {
    HPKE_KDF_HKDF_SHA256: "sha256",
    HPKE_KDF_HKDF_SHA384: "sha384",
    HPKE_KDF_HKDF_SHA512: "sha512",
}

# aead id -> (key length, tag length)
_AEAD_PARAMS = {
    HPKE_AEAD_AES_128_GCM: (16, 16),
    HPKE_AEAD_AES_256_GCM: (32, 16),
    HPKE_AEAD_CHACHA20_POLY1305: (32, 16),
}

# kem id -> (dh group, KEM hash, Nsecret)
_KEM_PARAMS = {
    HPKE_KEM_P256: ("p256", "sha256", 32),
    HPKE_KEM_P384: ("p384", "sha384", 48),
    HPKE_KEM_P521: ("p521", "sha512", 66),
    HPKE_KEM_X25519: ("x25519", "sha256", 32),
}

_EC_CURVES = {
    "p256": ec.SECP256R1,
    "p384": ec.SECP384R1,
    "p521": ec.SECP521R1,
}


class ECHConfigError(UTLSError, ValueError):
    """Raised when an ECHConfig or ECHConfigList is malformed."""


# ---------------------------------------------------------------------------
# ECHConfig parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ECHConfig:
    """One ``ECHConfig`` structure.

    ``raw`` preserves the exact wire encoding, which is important because it
    is part of the HPKE ``info`` value.
    """

    version: int
    config_id: int
    kem_id: int
    public_key: bytes
    cipher_suites: tuple[tuple[int, int], ...]
    maximum_name_length: int
    public_name: str
    extensions: tuple[tuple[int, bytes], ...] = ()
    raw: bytes = field(default=b"", repr=False, compare=False)

    def serialize(self) -> bytes:
        if self.raw:
            return self.raw
        contents = (
            uint8(self.config_id)
            + uint16(self.kem_id)
            + vec16(self.public_key)
            + vec16(b"".join(uint16(k) + uint16(a) for k, a in self.cipher_suites))
            + uint8(self.maximum_name_length)
            + vec8(self.public_name.encode("ascii"))
            + vec16(b"".join(uint16(t) + vec16(d) for t, d in self.extensions))
        )
        return uint16(self.version) + vec16(contents)

    def select_cipher_suite(self) -> tuple[int, int] | None:
        for kdf_id, aead_id in self.cipher_suites:
            if kdf_id in _KDF_HASHES and aead_id in _AEAD_PARAMS:
                return kdf_id, aead_id
        return None

    def supported(self) -> bool:
        if self.version != ECH_VERSION or self.kem_id not in _KEM_PARAMS:
            return False
        if self.select_cipher_suite() is None:
            return False
        if not _valid_public_name(self.public_name):
            return False
        # No mandatory ECHConfig extensions are defined; reject any unknown
        # mandatory extension (high bit set) as required by RFC 9849 4.2.
        return not any(ext_type & 0x8000 for ext_type, _ in self.extensions)


def _valid_public_name(name: str) -> bool:
    """RFC 9849 4: public_name must be a dot-separated sequence of LDH labels."""
    if not name or name.startswith(".") or name.endswith("."):
        return False
    labels = name.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False
    last = labels[-1]
    return not (last.isdigit() or last.lower().startswith("0x"))


@dataclass(frozen=True)
class ECHConfigList:
    """A parsed ``ECHConfigList``."""

    configs: tuple[ECHConfig, ...]

    def serialize(self) -> bytes:
        return vec16(b"".join(config.serialize() for config in self.configs))

    def select(self) -> ECHConfig | None:
        for config in self.configs:
            if config.supported():
                return config
        return None


def _parse_ech_config_contents(version: int, contents: bytes, raw: bytes) -> ECHConfig:
    pos = 0
    try:
        config_id = contents[pos]
        pos += 1
        kem_id = int.from_bytes(contents[pos : pos + 2], "big")
        pos += 2
        key_len = int.from_bytes(contents[pos : pos + 2], "big")
        pos += 2
        public_key = contents[pos : pos + key_len]
        if len(public_key) != key_len:
            raise ECHConfigError("truncated ECH public key")
        pos += key_len
        suite_len = int.from_bytes(contents[pos : pos + 2], "big")
        pos += 2
        if suite_len == 0 or suite_len % 4:
            raise ECHConfigError("invalid ECH cipher suite list")
        suites = []
        for i in range(0, suite_len, 4):
            kdf_id = int.from_bytes(contents[pos + i : pos + i + 2], "big")
            aead_id = int.from_bytes(contents[pos + i + 2 : pos + i + 4], "big")
            suites.append((kdf_id, aead_id))
        pos += suite_len
        maximum_name_length = contents[pos]
        pos += 1
        name_len = contents[pos]
        pos += 1
        public_name = contents[pos : pos + name_len]
        if len(public_name) != name_len:
            raise ECHConfigError("truncated ECH public name")
        pos += name_len
        ext_len = int.from_bytes(contents[pos : pos + 2], "big")
        pos += 2
        if pos + ext_len > len(contents):
            raise ECHConfigError("truncated ECH config extensions")
        extensions = []
        end = pos + ext_len
        while pos < end:
            ext_type = int.from_bytes(contents[pos : pos + 2], "big")
            data_len = int.from_bytes(contents[pos + 2 : pos + 4], "big")
            pos += 4
            data = contents[pos : pos + data_len]
            if len(data) != data_len:
                raise ECHConfigError("truncated ECH config extension")
            pos += data_len
            extensions.append((ext_type, data))
        if pos != end:
            raise ECHConfigError("trailing bytes in ECH config extensions")
        if end != len(contents):
            raise ECHConfigError("trailing bytes in ECHConfigContents")
    except IndexError as exc:
        raise ECHConfigError("truncated ECHConfigContents") from exc

    try:
        public_name_text = public_name.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ECHConfigError("ECH public_name is not ASCII") from exc
    return ECHConfig(
        version=version,
        config_id=config_id,
        kem_id=kem_id,
        public_key=public_key,
        cipher_suites=tuple(suites),
        maximum_name_length=maximum_name_length,
        public_name=public_name_text,
        extensions=tuple(extensions),
        raw=raw,
    )


def parse_ech_config_list(data: bytes | bytearray | memoryview | str) -> ECHConfigList:
    """Parse a wire-format or base64-encoded ``ECHConfigList``.

    Base64 input may be either the raw ``ech=`` SVCB parameter value or the
    complete ``ech=...`` token; surrounding whitespace is ignored.
    """
    if isinstance(data, str):
        text = data.strip()
        if text.startswith("ech="):
            text = text[4:]
        try:
            raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
        except Exception as exc:  # binascii.Error, ValueError
            raise ECHConfigError("invalid base64 ECHConfigList") from exc
    else:
        raw = bytes(data)

    if len(raw) < 2:
        raise ECHConfigError("short ECHConfigList")
    total = int.from_bytes(raw[:2], "big")
    end = 2 + total
    if end > len(raw):
        raise ECHConfigError("truncated ECHConfigList")
    if end != len(raw):
        raise ECHConfigError("trailing bytes after ECHConfigList")

    configs: list[ECHConfig] = []
    pos = 2
    while pos < end:
        if pos + 4 > end:
            raise ECHConfigError("truncated ECHConfig header")
        version = int.from_bytes(raw[pos : pos + 2], "big")
        length = int.from_bytes(raw[pos + 2 : pos + 4], "big")
        pos += 4
        if pos + length > end:
            raise ECHConfigError("truncated ECHConfig")
        contents = raw[pos : pos + length]
        if version == ECH_VERSION:
            configs.append(
                _parse_ech_config_contents(version, contents, raw[pos - 4 : pos + length])
            )
        pos += length
    return ECHConfigList(tuple(configs))


def coerce_ech_config_list(value) -> ECHConfigList:
    """Accept an ``ECHConfigList``, ``ECHConfig``, bytes, base64 or a list."""
    if isinstance(value, ECHConfigList):
        return value
    if isinstance(value, ECHConfig):
        return ECHConfigList((value,))
    if isinstance(value, (bytes, bytearray, memoryview, str)):
        return parse_ech_config_list(value)
    if isinstance(value, (list, tuple)):
        configs = []
        for item in value:
            if not isinstance(item, ECHConfig):
                raise TypeError("ECH config list items must be ECHConfig instances")
            configs.append(item)
        return ECHConfigList(tuple(configs))
    raise TypeError(f"unsupported ECH config list type: {type(value).__name__}")


def fetch_ech_config_list(hostname: str, *, timeout: float = 10.0) -> ECHConfigList:
    """Fetch ``hostname``'s ECHConfigList from a DNS HTTPS record via DoH.

    Cloudflare's JSON DoH endpoint is used by default.  Only the first record
    with an ``ech=`` SVCB parameter is considered.
    """
    query = urllib.parse.urlencode({"name": hostname, "type": "HTTPS"})
    request = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?{query}",
        headers={"Accept": "application/dns-json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.load(response)
    for answer in payload.get("Answer", []):
        data = answer.get("data", "")
        for token in data.split():
            if token.startswith("ech="):
                return parse_ech_config_list(token)
    raise ECHConfigError(f"no ECH configuration in the HTTPS record for {hostname}")


# ---------------------------------------------------------------------------
# HPKE base mode (RFC 9180)
# ---------------------------------------------------------------------------


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _labeled_extract(hash_name: str, suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(hash_name, salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(
    hash_name: str, suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    return hkdf_expand(
        hash_name,
        prk,
        _i2osp(length, 2) + b"HPKE-v1" + suite_id + label + info,
        length,
    )


def _hpke_suite_id(kem_id: int, kdf_id: int, aead_id: int) -> bytes:
    return b"HPKE" + _i2osp(kem_id, 2) + _i2osp(kdf_id, 2) + _i2osp(aead_id, 2)


def _kem_encapsulate(kem_id: int, public_key: bytes) -> tuple[bytes, bytes]:
    """Return ``(enc, shared_secret)`` for a raw HPKE public key."""
    group, hash_name, nsecret = _KEM_PARAMS[kem_id]
    kem_suite_id = b"KEM" + _i2osp(kem_id, 2)

    if group == "x25519":
        try:
            peer = x25519.X25519PublicKey.from_public_bytes(public_key)
        except ValueError as exc:
            raise ECHConfigError("invalid X25519 ECH public key") from exc
        ephemeral = x25519.X25519PrivateKey.generate()
        enc = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        dh = ephemeral.exchange(peer)
    else:
        curve = _EC_CURVES[group]()
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key)
        except ValueError as exc:
            raise ECHConfigError(f"invalid {group} ECH public key") from exc
        ephemeral = ec.generate_private_key(curve)
        enc = ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        dh = ephemeral.exchange(ec.ECDH(), peer)

    kem_context = enc + public_key
    eae_prk = _labeled_extract(hash_name, kem_suite_id, b"", b"eae_prk", dh)
    shared_secret = _labeled_expand(
        hash_name, kem_suite_id, eae_prk, b"shared_secret", kem_context, nsecret
    )
    return enc, shared_secret


@dataclass
class ECHContext:
    """HPKE sender context for one ECH ClientHello (or an HRR retry)."""

    config: ECHConfig
    kdf_id: int
    aead_id: int
    enc: bytes
    key: bytes
    base_nonce: bytes
    seq: int = 0

    @classmethod
    def setup(cls, config: ECHConfig) -> "ECHContext":
        suite = config.select_cipher_suite()
        if suite is None:
            raise ECHConfigError("ECHConfig has no supported HPKE cipher suite")
        kdf_id, aead_id = suite
        hash_name = _KDF_HASHES[kdf_id]
        enc, shared_secret = _kem_encapsulate(config.kem_id, config.public_key)

        suite_id = _hpke_suite_id(config.kem_id, kdf_id, aead_id)
        info = b"tls ech\x00" + config.serialize()
        psk_id_hash = _labeled_extract(hash_name, suite_id, b"", b"psk_id_hash", b"")
        info_hash = _labeled_extract(hash_name, suite_id, b"", b"info_hash", info)
        key_schedule_context = b"\x00" + psk_id_hash + info_hash
        secret = _labeled_extract(hash_name, suite_id, shared_secret, b"secret", b"")
        key_len, _ = _AEAD_PARAMS[aead_id]
        key = _labeled_expand(hash_name, suite_id, secret, b"key", key_schedule_context, key_len)
        base_nonce = _labeled_expand(
            hash_name, suite_id, secret, b"base_nonce", key_schedule_context, 12
        )
        return cls(
            config=config,
            kdf_id=kdf_id,
            aead_id=aead_id,
            enc=enc,
            key=key,
            base_nonce=base_nonce,
        )

    @property
    def tag_length(self) -> int:
        return _AEAD_PARAMS[self.aead_id][1]

    def _nonce(self) -> bytes:
        return bytes(a ^ b for a, b in zip(self.base_nonce, _i2osp(self.seq, 12)))

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        nonce = self._nonce()
        if self.aead_id == HPKE_AEAD_CHACHA20_POLY1305:
            ciphertext = ChaCha20Poly1305(self.key).encrypt(nonce, plaintext, aad)
        else:
            ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, aad)
        self.seq += 1
        return ciphertext

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        """Decrypt a payload with this context (used by tests and HRR code)."""
        nonce = self._nonce()
        if self.aead_id == HPKE_AEAD_CHACHA20_POLY1305:
            plaintext = ChaCha20Poly1305(self.key).decrypt(nonce, ciphertext, aad)
        else:
            plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, aad)
        self.seq += 1
        return plaintext


# ---------------------------------------------------------------------------
# ClientHelloInner / ClientHelloOuter construction
# ---------------------------------------------------------------------------


@dataclass
class ECHClientHello:
    """The two ClientHello views produced for one ECH offer."""

    config: ECHConfig
    context: ECHContext
    inner_spec: ClientHelloSpec
    outer_spec: ClientHelloSpec
    inner_built: BuiltClientHello
    outer_built: BuiltClientHello
    encoded_inner: bytes
    outer_aad: bytes
    inner_random: bytes
    outer_random: bytes
    session_id: bytes
    server_name: str = ""
    session_ticket: bytes = b""
    certificate_compression_algs: list[int] | None = None
    grease_seed: list[int] = field(default_factory=list)

    @property
    def inner_raw(self) -> bytes:
        return self.inner_built.raw

    @property
    def outer_raw(self) -> bytes:
        return self.outer_built.raw

    def accepts(self, server_hello, transcript_prefix: bytes = b"") -> bool:
        """Check the ServerHello accept-confirmation value."""
        suite = CIPHER_SUITES.get(server_hello.cipher_suite)
        if suite is None or not suite.is_tls13 or not server_hello.raw:
            return False
        expected = ech_accept_confirmation(
            transcript_prefix + self.inner_raw,
            server_hello.raw,
            suite.hash,
            self.inner_random,
        )
        return hmac.compare_digest(expected, server_hello.random[-8:])


def _ensure_psk_modes(spec: ClientHelloSpec) -> None:
    if any(isinstance(ext, PSKKeyExchangeModesExtension) for ext in spec.extensions):
        return
    spec.extensions.append(PSKKeyExchangeModesExtension([1]))


def _prepare_spec(spec: ClientHelloSpec) -> None:
    """Force a spec to be usable for a TLS 1.3-only ECH ClientHello."""
    spec.extensions = [
        ext
        for ext in spec.extensions
        if getattr(ext, "type_id", None) != EXT_ENCRYPTED_CLIENT_HELLO
    ]
    spec.tls_vers_min = VERSION_TLS13
    spec.tls_vers_max = VERSION_TLS13

    saw_versions = False
    for ext in spec.extensions:
        if getattr(ext, "type_id", None) == EXT_SUPPORTED_VERSIONS:
            ext.versions = [v for v in ext.versions if is_grease(v)] + [VERSION_TLS13]
            saw_versions = True
            break
    if not saw_versions:
        spec.extensions.append(SupportedVersionsExtension([VERSION_TLS13]))

    if not any(cs in (0x1301, 0x1302, 0x1303) for cs in spec.cipher_suites):
        spec.cipher_suites = [0x1301, 0x1302, 0x1303] + list(spec.cipher_suites)

    if not any(isinstance(ext, KeyShareExtension) for ext in spec.extensions):
        saw_groups = False
        for ext in spec.extensions:
            if isinstance(ext, SupportedGroupsExtension):
                saw_groups = True
                if GROUP_X25519 not in ext.curves:
                    ext.curves.append(GROUP_X25519)
                break
        if not saw_groups:
            spec.extensions.append(SupportedGroupsExtension([GROUP_X25519]))
        # Keep the padding extension last, except for ECH which is appended by
        # the caller.
        insert_at = len(spec.extensions)
        for i, ext in enumerate(spec.extensions):
            if getattr(ext, "type_id", None) == EXT_PADDING:
                insert_at = i
                break
        spec.extensions.insert(insert_at, KeyShareExtension([KeyShareEntry(GROUP_X25519)]))


def encode_client_hello_inner(
    inner_body: bytes, config: ECHConfig, server_name: str
) -> bytes:
    """Build ``EncodedClientHelloInner`` (empty session ID + padding)."""
    if len(inner_body) < 35:
        raise ValueError("short ClientHello body")
    session_id_len = inner_body[34]
    base = inner_body[:34] + b"\x00" + inner_body[35 + session_id_len :]

    name_len = len(server_name.encode("idna")) if server_name else 0
    if name_len:
        name_padding = max(0, config.maximum_name_length - name_len)
    else:
        name_padding = config.maximum_name_length + 9

    length = len(base) + name_padding
    block_padding = 31 - ((length - 1) % 32)
    return base + b"\x00" * (name_padding + block_padding)


def locate_ech_payload(body: bytes) -> tuple[int, int]:
    """Return ``(offset, length)`` of the outer ECH payload in a CH body."""
    pos = 0
    if len(body) < 35:
        raise ValueError("short ClientHello body")
    pos += 2 + 32
    session_id_len = body[pos]
    pos += 1 + session_id_len
    suites_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2 + suites_len
    compression_len = body[pos]
    pos += 1 + compression_len
    extensions_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    end = pos + extensions_len
    if end > len(body):
        raise ValueError("truncated ClientHello extensions")

    while pos + 4 <= end:
        ext_type = int.from_bytes(body[pos : pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
        if ext_type == EXT_ENCRYPTED_CLIENT_HELLO:
            p = pos + 4
            if body[p] != ECH_CLIENT_HELLO_OUTER:
                raise ValueError("not an outer ECH extension")
            p += 1 + 2 + 2 + 1
            enc_len = int.from_bytes(body[p : p + 2], "big")
            p += 2 + enc_len
            payload_len = int.from_bytes(body[p : p + 2], "big")
            return p + 2, payload_len
        pos += 4 + ext_len
    raise ValueError("no encrypted_client_hello extension")


def build_ech_client_hello(
    spec: ClientHelloSpec,
    config: ECHConfig,
    *,
    server_name: str,
    session_ticket: bytes = b"",
    certificate_compression_algs: list[int] | None = None,
    grease_seed: list[int] | None = None,
) -> ECHClientHello:
    """Build a ClientHelloInner/ClientHelloOuter pair for ``config``."""
    if grease_seed is None:
        grease_seed = [int.from_bytes(os.urandom(2), "little") for _ in range(8)]

    inner_spec = spec.clone()
    outer_spec = spec.clone()
    _prepare_spec(inner_spec)
    _prepare_spec(outer_spec)

    inner_psks = [
        ext for ext in inner_spec.extensions if isinstance(ext, PreSharedKeyExtension)
    ]
    inner_early = [
        ext for ext in inner_spec.extensions if isinstance(ext, EarlyDataExtension)
    ]
    if inner_psks:
        _ensure_psk_modes(inner_spec)
    if inner_psks or inner_early:
        inner_spec.extensions = [
            ext
            for ext in inner_spec.extensions
            if not isinstance(ext, (PreSharedKeyExtension, EarlyDataExtension))
        ]
    # early_data precedes ECH, and pre_shared_key stays last (RFC 8446 4.2.11).
    inner_spec.extensions.extend(inner_early)
    inner_spec.extensions.append(ECHInnerExtension())
    inner_spec.extensions.extend(inner_psks)
    # ClientHelloOuter never carries the real PSK.  BoringSSL (and thus
    # Cloudflare) also omits the optional GREASE PSK because its parser
    # requires pre_shared_key to be the last extension, while ECH must be
    # last for the outer AAD construction.
    outer_spec.extensions = [
        ext
        for ext in outer_spec.extensions
        if not isinstance(ext, PreSharedKeyExtension)
    ]

    session_id = os.urandom(32)
    inner_random = os.urandom(32)
    outer_random = os.urandom(32)

    inner_built = build_client_hello(
        inner_spec,
        server_name=server_name,
        session_ticket=session_ticket,
        session_id=session_id,
        random_bytes=inner_random,
        grease_seed=list(grease_seed),
        certificate_compression_algs=certificate_compression_algs,
    )
    # Binder bytes are filled into raw after body was computed; ECH encrypts
    # the finished ClientHello, so use raw[4:] from here on.
    inner_built = BuiltClientHello(
        raw=inner_built.raw,
        body=inner_built.raw[4:],
        session_id=inner_built.session_id,
        key_shares=inner_built.key_shares,
        context=inner_built.context,
    )
    encoded_inner = encode_client_hello_inner(inner_built.body, config, server_name)

    context = ECHContext.setup(config)
    placeholder = b"\x00" * (len(encoded_inner) + context.tag_length)
    outer_spec.extensions.append(
        ECHOuterExtension(
            config.config_id,
            context.kdf_id,
            context.aead_id,
            context.enc,
            placeholder,
        )
    )
    outer_built = build_client_hello(
        outer_spec,
        server_name=config.public_name,
        session_ticket=session_ticket,
        session_id=session_id,
        random_bytes=outer_random,
        grease_seed=list(grease_seed),
        certificate_compression_algs=certificate_compression_algs,
    )
    outer_built = BuiltClientHello(
        raw=outer_built.raw,
        body=outer_built.raw[4:],
        session_id=outer_built.session_id,
        key_shares=outer_built.key_shares,
        context=outer_built.context,
    )

    payload_offset, payload_len = locate_ech_payload(outer_built.body)
    aad = outer_built.body
    sealed = context.seal(aad, encoded_inner)
    if len(sealed) != payload_len:
        raise ValueError("ECH payload length changed during sealing")
    outer_body = bytearray(outer_built.body)
    outer_body[payload_offset : payload_offset + payload_len] = sealed
    outer_raw = outer_built.raw[:4] + bytes(outer_body)
    outer_built = BuiltClientHello(
        raw=outer_raw,
        body=bytes(outer_body),
        session_id=outer_built.session_id,
        key_shares=outer_built.key_shares,
        context=outer_built.context,
    )

    return ECHClientHello(
        config=config,
        context=context,
        inner_spec=inner_spec,
        outer_spec=outer_spec,
        inner_built=inner_built,
        outer_built=outer_built,
        encoded_inner=encoded_inner,
        outer_aad=aad,
        inner_random=inner_random,
        outer_random=outer_random,
        session_id=session_id,
        server_name=server_name,
        session_ticket=session_ticket,
        certificate_compression_algs=certificate_compression_algs,
        grease_seed=list(grease_seed),
    )


def ech_accept_confirmation(
    inner_raw: bytes,
    server_hello_raw: bytes,
    hash_name: str,
    inner_random: bytes | None = None,
) -> bytes:
    """Compute the RFC 9849 7.2 accept-confirmation value."""
    if inner_random is None:
        inner_random = inner_raw[6:38]
    if len(server_hello_raw) < 38:
        raise ValueError("short ServerHello")
    modified = bytearray(server_hello_raw)
    # Handshake header (4) + legacy_version (2) + ServerHello.random (32).
    modified[30:38] = b"\x00" * 8
    transcript = hashlib.new(hash_name, inner_raw + bytes(modified)).digest()
    zeros = b"\x00" * hash_len(hash_name)
    prk = hkdf_extract(hash_name, zeros, inner_random)
    return hkdf_expand_label(hash_name, prk, "ech accept confirmation", transcript, 8)


def zero_ech_extension_payload(raw: bytes) -> bytes:
    """Return a handshake message with the ECH extension payload zeroed."""
    if len(raw) < 4:
        raise ValueError("short handshake message")
    body = bytearray(raw[4:])
    pos = 2 + 32
    if len(body) < pos + 1:
        raise ValueError("short ServerHello")
    session_id_len = body[pos]
    pos += 1 + session_id_len + 2 + 1  # cipher_suite + compression_method
    if len(body) < pos + 2:
        raise ValueError("short ServerHello extensions")
    extensions_len = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    end = pos + extensions_len
    if end > len(body):
        raise ValueError("truncated ServerHello extensions")
    while pos + 4 <= end:
        ext_type = int.from_bytes(body[pos : pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
        data_start = pos + 4
        if data_start + ext_len > end:
            raise ValueError("truncated extension")
        if ext_type == EXT_ENCRYPTED_CLIENT_HELLO:
            body[data_start : data_start + ext_len] = b"\x00" * ext_len
            return raw[:4] + bytes(body)
        pos = data_start + ext_len
    raise ValueError("no encrypted_client_hello extension")


def hrr_accept_confirmation(
    inner_raw: bytes,
    hrr_raw: bytes,
    hash_name: str,
    inner_random: bytes | None = None,
) -> bytes:
    """Compute the RFC 9849 7.2.1 HelloRetryRequest confirmation value."""
    if inner_random is None:
        inner_random = inner_raw[6:38]
    modified = zero_ech_extension_payload(hrr_raw)
    # RFC 8446 4.4.1: after HRR the first ClientHello is replaced by
    # message_hash(ClientHelloInner1) in the transcript.
    inner_digest = hashlib.new(hash_name, inner_raw).digest()
    prefix = (
        bytes([254]) + len(inner_digest).to_bytes(3, "big") + inner_digest
    )
    transcript = hashlib.new(hash_name, prefix + modified).digest()
    zeros = b"\x00" * hash_len(hash_name)
    prk = hkdf_extract(hash_name, zeros, inner_random)
    return hkdf_expand_label(
        hash_name, prk, "hrr ech accept confirmation", transcript, 8
    )


def _strip_extension_types(spec: ClientHelloSpec, types: set[int]) -> None:
    spec.extensions = [
        ext for ext in spec.extensions if getattr(ext, "type_id", None) not in types
    ]


def _set_key_share(spec: ClientHelloSpec, group: int) -> None:
    for ext in spec.extensions:
        if isinstance(ext, KeyShareExtension):
            ext.key_shares = [KeyShareEntry(group)]
            return
    insert_at = len(spec.extensions)
    for i, ext in enumerate(spec.extensions):
        if getattr(ext, "type_id", None) in (EXT_PADDING, EXT_ENCRYPTED_CLIENT_HELLO):
            insert_at = i
            break
    spec.extensions.insert(insert_at, KeyShareExtension([KeyShareEntry(group)]))


def _insert_before_ech(spec: ClientHelloSpec, ext) -> None:
    for i, existing in enumerate(spec.extensions):
        if getattr(existing, "type_id", None) == EXT_ENCRYPTED_CLIENT_HELLO:
            spec.extensions.insert(i, ext)
            return
    spec.extensions.append(ext)


def build_ech_hrr_client_hello(ech: ECHClientHello, hrr) -> ECHClientHello:
    """Build the second ClientHelloInner/Outer after an accepted HRR."""
    selected_group = hrr.key_share_group
    if not selected_group:
        raise ValueError("HelloRetryRequest did not select a key share group")

    stripped = {
        EXT_PRE_SHARED_KEY,
        EXT_EARLY_DATA,
        EXT_COOKIE,
        EXT_ENCRYPTED_CLIENT_HELLO,
    }
    inner_spec = ech.inner_spec.clone()
    outer_spec = ech.outer_spec.clone()
    for spec in (inner_spec, outer_spec):
        _strip_extension_types(spec, stripped)
        _set_key_share(spec, selected_group)
        if hrr.cookie:
            _insert_before_ech(spec, CookieExtension(hrr.cookie))
    inner_spec.extensions.append(ECHInnerExtension())

    inner_built = build_client_hello(
        inner_spec,
        server_name=ech.server_name,
        session_ticket=ech.session_ticket,
        session_id=ech.session_id,
        random_bytes=ech.inner_random,
        grease_seed=list(ech.grease_seed),
        certificate_compression_algs=ech.certificate_compression_algs,
    )
    inner_built = BuiltClientHello(
        raw=inner_built.raw,
        body=inner_built.raw[4:],
        session_id=inner_built.session_id,
        key_shares=inner_built.key_shares,
        context=inner_built.context,
    )
    encoded_inner = encode_client_hello_inner(
        inner_built.body, ech.config, ech.server_name
    )

    placeholder = b"\x00" * (len(encoded_inner) + ech.context.tag_length)
    outer_spec.extensions.append(
        ECHOuterExtension(
            ech.config.config_id,
            ech.context.kdf_id,
            ech.context.aead_id,
            b"",
            placeholder,
        )
    )
    outer_built = build_client_hello(
        outer_spec,
        server_name=ech.config.public_name,
        session_ticket=ech.session_ticket,
        session_id=ech.session_id,
        random_bytes=ech.outer_random,
        grease_seed=list(ech.grease_seed),
        certificate_compression_algs=ech.certificate_compression_algs,
    )
    outer_built = BuiltClientHello(
        raw=outer_built.raw,
        body=outer_built.raw[4:],
        session_id=outer_built.session_id,
        key_shares=outer_built.key_shares,
        context=outer_built.context,
    )

    payload_offset, payload_len = locate_ech_payload(outer_built.body)
    aad = outer_built.body
    sealed = ech.context.seal(aad, encoded_inner)
    if len(sealed) != payload_len:
        raise ValueError("ECH payload length changed during sealing")
    outer_body = bytearray(outer_built.body)
    outer_body[payload_offset : payload_offset + payload_len] = sealed
    outer_raw = outer_built.raw[:4] + bytes(outer_body)
    outer_built = BuiltClientHello(
        raw=outer_raw,
        body=bytes(outer_body),
        session_id=outer_built.session_id,
        key_shares=outer_built.key_shares,
        context=outer_built.context,
    )

    return ECHClientHello(
        config=ech.config,
        context=ech.context,
        inner_spec=inner_spec,
        outer_spec=outer_spec,
        inner_built=inner_built,
        outer_built=outer_built,
        encoded_inner=encoded_inner,
        outer_aad=aad,
        inner_random=ech.inner_random,
        outer_random=ech.outer_random,
        session_id=ech.session_id,
        server_name=ech.server_name,
        session_ticket=ech.session_ticket,
        certificate_compression_algs=ech.certificate_compression_algs,
        grease_seed=list(ech.grease_seed),
    )
