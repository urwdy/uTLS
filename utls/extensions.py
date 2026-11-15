"""ClientHello extensions used to build fingerprints.

Each extension mirrors the corresponding type in uTLS'
``u_tls_extensions.go``.  Extensions are pure descriptions; values that depend
on a connection (SNI, ALPN, key shares, GREASE) are filled in by
:func:`utls.hello.build_client_hello`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .constants import (
    EXT_APPLICATION_SETTINGS,
    EXT_APPLICATION_SETTINGS_NEW,
    EXT_CHANNEL_ID,
    EXT_CHANNEL_ID_OLD,
    EXT_COMPRESS_CERTIFICATE,
    EXT_DELEGATED_CREDENTIALS,
    EXT_EC_POINT_FORMATS,
    EXT_ENCRYPTED_CLIENT_HELLO,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_KEY_SHARE,
    EXT_PADDING,
    EXT_PRE_SHARED_KEY,
    EXT_PSK_KEY_EXCHANGE_MODES,
    EXT_RECORD_SIZE_LIMIT,
    EXT_RENEGOTIATION_INFO,
    EXT_SCT,
    EXT_SESSION_TICKET,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SNI,
    EXT_STATUS_REQUEST,
    EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS,
    EXT_ALPN,
    GREASE_PLACEHOLDER,
)

u8 = struct.Struct("!B")
u16 = struct.Struct("!H")
u24 = struct.Struct("!I")


def uint8(v: int) -> bytes:
    return u8.pack(v)


def uint16(v: int) -> bytes:
    return u16.pack(v)


def uint24(v: int) -> bytes:
    return u24.pack(v)[1:]


def vec8(data: bytes) -> bytes:
    return uint8(len(data)) + data


def vec16(data: bytes) -> bytes:
    return uint16(len(data)) + data


def vec24(data: bytes) -> bytes:
    return uint24(len(data)) + data


@dataclass
class HelloContext:
    """Per-connection data used while marshalling a ClientHello."""

    server_name: str = ""
    alpn_protocols: list[str] = field(default_factory=list)
    grease: list[int] = field(default_factory=list)
    key_shares: dict[int, object] = field(default_factory=dict)
    session_ticket: bytes = b""
    cert_compression_algs: list[int] = field(default_factory=list)
    renegotiated: bytes = b""

    def grease_value(self, index: int) -> int:
        from .constants import grease_value

        return grease_value(self.grease[index])


class TLSExtension:
    """Base class for ClientHello extension descriptions."""

    type_id: int = 0

    def body(self, ctx: HelloContext) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def marshal(self, ctx: HelloContext) -> bytes:
        body = self.body(ctx)
        if body is None:
            return b""
        return uint16(self.type_id) + vec16(body)

    def length(self, ctx: HelloContext) -> int:
        data = self.marshal(ctx)
        return len(data)


class SNIExtension(TLSExtension):
    type_id = EXT_SNI

    def body(self, ctx: HelloContext) -> bytes:
        name = hostname_in_sni(ctx.server_name)
        if not name:
            return b""
        return vec16(uint8(0) + vec16(name.encode("idna") if not name.isascii() else name.encode()))

    def marshal(self, ctx: HelloContext) -> bytes:
        name = hostname_in_sni(ctx.server_name)
        if not name:
            return b""
        return super().marshal(ctx)


class StatusRequestExtension(TLSExtension):
    type_id = EXT_STATUS_REQUEST

    def body(self, ctx: HelloContext) -> bytes:
        # status_type=ocsp(1), empty responder_id_list, empty request_extensions
        return uint8(1) + uint16(0) + uint16(0)


class SupportedGroupsExtension(TLSExtension):
    type_id = EXT_SUPPORTED_GROUPS

    def __init__(self, curves: list[int] | None = None) -> None:
        self.curves = list(curves or [])

    def body(self, ctx: HelloContext) -> bytes:
        groups = list(self.curves)
        for i, group in enumerate(groups):
            if group == GREASE_PLACEHOLDER:
                groups[i] = ctx.grease_value(1)
        return vec16(b"".join(uint16(g) for g in groups))


class SupportedPointsExtension(TLSExtension):
    type_id = EXT_EC_POINT_FORMATS

    def __init__(self, points: bytes = b"\x00") -> None:
        self.points = points

    def body(self, ctx: HelloContext) -> bytes:
        return vec8(self.points)


class SignatureAlgorithmsExtension(TLSExtension):
    type_id = EXT_SIGNATURE_ALGORITHMS

    def __init__(self, algorithms: list[int] | None = None) -> None:
        self.algorithms = list(algorithms or [])

    def body(self, ctx: HelloContext) -> bytes:
        algs = list(self.algorithms)
        for i, scheme in enumerate(algs):
            if scheme == GREASE_PLACEHOLDER:
                algs[i] = ctx.grease_value(7)
        return vec16(b"".join(uint16(a) for a in algs))


class ALPNExtension(TLSExtension):
    type_id = EXT_ALPN

    def __init__(self, protocols: list[str] | None = None) -> None:
        self.protocols = list(protocols or [])

    def body(self, ctx: HelloContext) -> bytes:
        protocols = ctx.alpn_protocols if ctx.alpn_protocols else self.protocols
        return vec16(b"".join(vec8(p.encode()) for p in protocols))


class SCTExtension(TLSExtension):
    type_id = EXT_SCT

    def body(self, ctx: HelloContext) -> bytes:
        return b""


class ExtendedMasterSecretExtension(TLSExtension):
    type_id = EXT_EXTENDED_MASTER_SECRET

    def body(self, ctx: HelloContext) -> bytes:
        return b""


class SessionTicketExtension(TLSExtension):
    type_id = EXT_SESSION_TICKET

    def body(self, ctx: HelloContext) -> bytes:
        return ctx.session_ticket


class RenegotiationInfoExtension(TLSExtension):
    type_id = EXT_RENEGOTIATION_INFO

    def __init__(self, renegotiation: bytes = b"") -> None:
        self.renegotiation = renegotiation

    def body(self, ctx: HelloContext) -> bytes:
        data = self.renegotiation or ctx.renegotiated
        return vec8(data)


class KeyShareEntry:
    __slots__ = ("group", "data", "reuse")

    def __init__(self, group: int, data: bytes | None = None, reuse: int | None = None) -> None:
        self.group = group
        self.data = data
        self.reuse = reuse

    @classmethod
    def hybrid_reuse(cls, group: int) -> "KeyShareEntry":
        return cls(group, reuse=0xF1)

    @classmethod
    def classical_reuse(cls, group: int) -> "KeyShareEntry":
        return cls(group, reuse=0xF2)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"KeyShareEntry(group={self.group:#06x})"


class KeyShareExtension(TLSExtension):
    type_id = EXT_KEY_SHARE

    def __init__(self, key_shares: list[KeyShareEntry] | None = None) -> None:
        self.key_shares = list(key_shares or [])

    def marshal(self, ctx: HelloContext) -> bytes:
        from .constants import GROUP_X25519, HYBRID_GROUPS, is_grease
        from .crypto import generate_key_share

        entries: list[bytes] = []
        reusable: dict[int, object] = {}
        for entry in self.key_shares:
            group = entry.group
            if group == GREASE_PLACEHOLDER or is_grease(group):
                group = ctx.grease_value(1)
                entries.append(uint16(group) + vec16(entry.data or b"\x00"))
                continue

            if entry.reuse == 0xF2:
                if group not in reusable:
                    raise ValueError(f"no hybrid key share available to reuse for group {group:#06x}")
                ks = reusable[group]
                ctx.key_shares.setdefault(group, ks)
                entries.append(uint16(group) + vec16(ks.public_key))
                continue

            ks = generate_key_share(group)
            ctx.key_shares[group] = ks
            entries.append(uint16(group) + vec16(ks.public_key))
            if entry.reuse == 0xF1 and group in HYBRID_GROUPS:
                reusable[GROUP_X25519] = _classical_from_hybrid(ks)
        body = vec16(b"".join(entries))
        return uint16(self.type_id) + vec16(body)


def _classical_from_hybrid(ks):
    """Build a synthetic KeySharePrivate around the hybrid's X25519 key."""

    from cryptography.hazmat.primitives import serialization

    from .constants import GROUP_X25519

    class _Classical:
        group = GROUP_X25519

        def __init__(self, private_key):
            self.private_key = private_key
            self.public_key = private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )

        def decapsulate(self, peer_public: bytes, version: int) -> bytes:
            from cryptography.hazmat.primitives.asymmetric import x25519

            return self.private_key.exchange(
                x25519.X25519PublicKey.from_public_bytes(peer_public)
            )

    return _Classical(ks.private_key["x25519"])


class PSKKeyExchangeModesExtension(TLSExtension):
    type_id = EXT_PSK_KEY_EXCHANGE_MODES

    def __init__(self, modes: list[int] | None = None) -> None:
        self.modes = list(modes or [1])

    def body(self, ctx: HelloContext) -> bytes:
        return vec8(bytes(self.modes))


class PreSharedKeyExtension(TLSExtension):
    """TLS 1.3 ``pre_shared_key`` (41).

    The binder is filled in by :func:`utls.hello.build_client_hello` after the
    rest of the ClientHello has been marshalled.
    """

    type_id = EXT_PRE_SHARED_KEY

    def __init__(
        self,
        psk: bytes,
        ticket: bytes,
        age_millis: int,
        hash_name: str,
    ) -> None:
        self.psk = psk
        self.ticket = ticket
        self.age_millis = age_millis
        self.hash_name = hash_name
        self.truncated_offset = 0
        self.binder_len = 0

    def body(self, ctx: HelloContext) -> bytes:
        from .crypto import hash_len

        identities = (
            vec16(self.ticket) + (self.age_millis & 0xFFFFFFFF).to_bytes(4, "big")
        )
        self.binder_len = hash_len(self.hash_name)
        # Offset of the binders vector (its 2-byte length prefix) within the
        # extension body.
        self.truncated_offset = 2 + len(identities)
        return vec16(identities) + vec16(
            bytes([self.binder_len]) + b"\x00" * self.binder_len
        )


class SupportedVersionsExtension(TLSExtension):
    type_id = EXT_SUPPORTED_VERSIONS

    def __init__(self, versions: list[int] | None = None) -> None:
        self.versions = list(versions or [])

    def body(self, ctx: HelloContext) -> bytes:
        versions = list(self.versions)
        for i, version in enumerate(versions):
            if version == GREASE_PLACEHOLDER:
                versions[i] = ctx.grease_value(4)
        return vec8(b"".join(uint16(v) for v in versions))


class CookieExtension(TLSExtension):
    type_id = 44

    def __init__(self, cookie: bytes = b"") -> None:
        self.cookie = cookie

    def body(self, ctx: HelloContext) -> bytes:
        return vec16(self.cookie)


class EarlyDataExtension(TLSExtension):
    type_id = 42

    def body(self, ctx: HelloContext) -> bytes:
        return b""


class PaddingExtension(TLSExtension):
    type_id = EXT_PADDING

    def __init__(self, pad_len: int | None = None, padding_len_func=None) -> None:
        self.pad_len = pad_len
        self.padding_len_func = padding_len_func

    def body(self, ctx: HelloContext) -> bytes:
        return b"\x00" * (self.pad_len or 0)


class GREASEExtension(TLSExtension):
    """A GREASE extension; its value is assigned from the GREASE seed."""

    def __init__(self, body: bytes = b"") -> None:
        self.body_bytes = body
        self.index = 0

    def marshal(self, ctx: HelloContext) -> bytes:
        value = ctx.grease_value(2 + self.index)
        return uint16(value) + vec16(self.body_bytes)


class CompressCertificateExtension(TLSExtension):
    type_id = EXT_COMPRESS_CERTIFICATE

    def __init__(self, algorithms: list[int] | None = None) -> None:
        self.algorithms = list(algorithms or [])

    def body(self, ctx: HelloContext) -> bytes:
        ctx.cert_compression_algs = list(self.algorithms)
        return vec8(b"".join(uint16(a) for a in self.algorithms))


class ApplicationSettingsExtension(TLSExtension):
    def __init__(self, protocols: list[str] | None = None, new: bool = False) -> None:
        self.protocols = list(protocols or [])
        self.type_id = EXT_APPLICATION_SETTINGS_NEW if new else EXT_APPLICATION_SETTINGS

    def body(self, ctx: HelloContext) -> bytes:
        entries = b"".join(vec8(p.encode()) for p in self.protocols)
        # Draft ALPS: the body is the ALPS extension length followed by the
        # protocol list (the outer body length is the TLS extension header).
        return vec16(entries)


class FakeChannelIDExtension(TLSExtension):
    def __init__(self, old: bool = False) -> None:
        self.type_id = EXT_CHANNEL_ID_OLD if old else EXT_CHANNEL_ID

    def body(self, ctx: HelloContext) -> bytes:
        return b""


class FakeRecordSizeLimitExtension(TLSExtension):
    type_id = EXT_RECORD_SIZE_LIMIT

    def __init__(self, limit: int = 0x4001) -> None:
        self.limit = limit

    def body(self, ctx: HelloContext) -> bytes:
        return uint16(self.limit)


class FakeDelegatedCredentialsExtension(TLSExtension):
    type_id = EXT_DELEGATED_CREDENTIALS

    def __init__(self, algorithms: list[int] | None = None) -> None:
        self.algorithms = list(algorithms or [])

    def body(self, ctx: HelloContext) -> bytes:
        return vec16(b"".join(uint16(a) for a in self.algorithms))


class GREASEEcHExtension(TLSExtension):
    """GREASE ECH (0xfe0d) as emitted by Chrome/Firefox.

    The payload is random; only its length matters for the fingerprint.
    """

    type_id = EXT_ENCRYPTED_CLIENT_HELLO

    def __init__(
        self,
        cipher_suites: list[tuple[int, int]] | None = None,
        payload_lens: list[int] | None = None,
        encapsulated_key: bytes | None = None,
    ) -> None:
        self.cipher_suites = list(cipher_suites or [(0x0001, 0x0001)])
        self.payload_lens = list(payload_lens or [128])
        self.encapsulated_key = encapsulated_key

    def _payload(self) -> bytes:
        import os
        import random

        kdf, aead = random.choice(self.cipher_suites)
        config_id = random.randrange(256)
        enc = self.encapsulated_key or os.urandom(32)
        body_len = random.choice(self.payload_lens) + 16
        payload = os.urandom(body_len)
        return (
            uint8(0)  # ClientHelloType: outer
            + uint16(kdf)
            + uint16(aead)
            + uint8(config_id)
            + vec16(enc)
            + vec16(payload)
        )

    def marshal(self, ctx: HelloContext) -> bytes:
        body = self._payload()
        return uint16(self.type_id) + vec16(body)


class ECHInnerExtension(TLSExtension):
    """Real ECH (RFC 9849) inner ClientHello extension (empty payload)."""

    type_id = EXT_ENCRYPTED_CLIENT_HELLO

    def body(self, ctx: HelloContext) -> bytes:
        return uint8(1)


class ECHOuterExtension(TLSExtension):
    """Real ECH outer extension, filled by :mod:`utls.ech`."""

    type_id = EXT_ENCRYPTED_CLIENT_HELLO

    def __init__(
        self,
        config_id: int,
        kdf_id: int,
        aead_id: int,
        encapsulated_key: bytes,
        payload: bytes,
    ) -> None:
        self.config_id = config_id
        self.kdf_id = kdf_id
        self.aead_id = aead_id
        self.encapsulated_key = encapsulated_key
        self.payload = payload

    def body(self, ctx: HelloContext) -> bytes:
        return (
            uint8(0)
            + uint16(self.kdf_id)
            + uint16(self.aead_id)
            + uint8(self.config_id)
            + vec16(self.encapsulated_key)
            + vec16(self.payload)
        )


class TrustAnchorsExtension(TLSExtension):
    type_id = 0xCA34

    def __init__(self, trust_anchor_ids: list[bytes] | None = None) -> None:
        self.trust_anchor_ids = list(trust_anchor_ids or [])

    def body(self, ctx: HelloContext) -> bytes:
        return vec16(b"".join(bytes([len(x)]) + x for x in self.trust_anchor_ids))


class GenericExtension(TLSExtension):
    """Raw extension for specs parsed from a captured ClientHello."""

    def __init__(self, type_id: int, data: bytes = b"") -> None:
        self.type_id = type_id
        self.data = data

    def body(self, ctx: HelloContext) -> bytes:
        return self.data


class NPNExtension(TLSExtension):
    """Next Protocol Negotiation (legacy Chrome; not IANA assigned)."""

    type_id = 13172

    def body(self, ctx: HelloContext) -> bytes:
        return b""


# ---------------------------------------------------------------------------
# Helpers used by presets
# ---------------------------------------------------------------------------


def hostname_in_sni(hostname: str) -> str:
    """RFC 6066: IP literals, empty names and trailing dots are not sent."""
    import ipaddress

    hostname = (hostname or "").strip()
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if not hostname:
        return ""
    if hostname.startswith("[") and hostname.endswith("]"):
        return ""
    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        return hostname


def boring_padding_style(unpadded_len: int) -> tuple[int, bool]:
    if 0xFF < unpadded_len < 0x200:
        pad = 0x200 - unpadded_len
        if pad >= 5:
            pad -= 4
        else:
            pad = 1
        return pad, True
    return 0, False


def always_pad_to_len(pad_to_len: int):
    def _func(unpadded_len: int) -> tuple[int, bool]:
        if unpadded_len < pad_to_len:
            pad = pad_to_len - unpadded_len
            if pad >= 5:
                pad -= 4
            else:
                pad = 1
            return pad, True
        return 0, False

    return _func
