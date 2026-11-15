"""Parsing and serialisation of TLS handshake messages."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .constants import (
    EXT_ALPN,
    EXT_APPLICATION_SETTINGS,
    EXT_APPLICATION_SETTINGS_NEW,
    EXT_COOKIE,
    EXT_KEY_SHARE,
    EXT_PRE_SHARED_KEY,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_VERSIONS,
    HANDSHAKE_NAMES,
    SIG_HASH_NAMES,
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


class Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def __len__(self) -> int:
        return len(self.data) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated handshake message")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def vec8(self) -> bytes:
        return self.take(self.u8())

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec24(self) -> bytes:
        return self.take(self.u24())


def parse_handshake_header(data: bytes) -> tuple[int, bytes, int]:
    """Return ``(msg_type, body, total_length)`` for a buffered handshake."""
    if len(data) < 4:
        raise ValueError("need more handshake data")
    msg_type = data[0]
    length = int.from_bytes(data[1:4], "big")
    if len(data) < 4 + length:
        raise ValueError("need more handshake data")
    return msg_type, data[4 : 4 + length], 4 + length


def make_handshake(msg_type: int, body: bytes) -> bytes:
    return uint8(msg_type) + uint24(len(body)) + body


@dataclass
class ParsedExtension:
    type: int
    data: bytes


def parse_extension_list(data: bytes) -> list[ParsedExtension]:
    r = Reader(data)
    out = []
    while len(r):
        ext_type = r.u16()
        out.append(ParsedExtension(ext_type, r.vec16()))
    return out


@dataclass
class ServerHello:
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int
    extensions: list[ParsedExtension]
    raw: bytes
    selected_version: int = 0
    key_share_group: int = 0
    key_share: bytes = b""
    selected_alpn: str | None = None
    cookie: bytes = b""
    pre_shared_key_selected: bool = False

    @property
    def is_hello_retry_request(self) -> bool:
        for ext in self.extensions:
            if ext.type == EXT_COOKIE:
                return True
        return False

    def get_extension(self, ext_type: int) -> bytes | None:
        for ext in self.extensions:
            if ext.type == ext_type:
                return ext.data
        return None


def parse_server_hello(body: bytes, raw: bytes = b"") -> ServerHello:
    from .constants import VERSION_TLS12

    r = Reader(body)
    legacy_version = r.u16()
    random = r.take(32)
    session_id = r.vec8()
    cipher_suite = r.u16()
    compression = r.u8()
    extensions: list[ParsedExtension] = []
    if len(r):
        extensions = parse_extension_list(r.vec16())
    sh = ServerHello(
        legacy_version=legacy_version,
        random=random,
        session_id=session_id,
        cipher_suite=cipher_suite,
        compression_method=compression,
        extensions=extensions,
        raw=raw,
        selected_version=legacy_version,
    )
    for ext in extensions:
        if ext.type == EXT_SUPPORTED_VERSIONS and len(ext.data) == 2:
            sh.selected_version = int.from_bytes(ext.data, "big")
        elif ext.type == EXT_KEY_SHARE:
            if len(ext.data) == 2:
                # HelloRetryRequest: key_share carries only the selected group.
                sh.key_share_group = int.from_bytes(ext.data, "big")
            else:
                er = Reader(ext.data)
                sh.key_share_group = er.u16()
                sh.key_share = er.vec16()
        elif ext.type == EXT_COOKIE:
            sh.cookie = Reader(ext.data).vec16()
        elif ext.type == EXT_PRE_SHARED_KEY:
            sh.pre_shared_key_selected = True
    if sh.selected_version < VERSION_TLS12:
        sh.selected_version = legacy_version
    return sh


@dataclass
class EncryptedExtensions:
    extensions: list[ParsedExtension]
    raw: bytes
    alpn_protocol: str | None = None
    early_data_accepted: bool = False
    ech_retry_configs: bytes = b""
    alps_protocols: list[str] = field(default_factory=list)


def parse_encrypted_extensions(body: bytes, raw: bytes = b"") -> EncryptedExtensions:
    r = Reader(body)
    extensions = parse_extension_list(r.vec16())
    ee = EncryptedExtensions(extensions=extensions, raw=raw)
    for ext in extensions:
        if ext.type == EXT_ALPN:
            er = Reader(ext.data)
            proto_list = Reader(er.vec16())
            if len(proto_list):
                ee.alpn_protocol = proto_list.vec8().decode("latin-1")
        elif ext.type == 42:  # early_data
            ee.early_data_accepted = True
        elif ext.type == 0xFE0D:  # encrypted_client_hello (retry_configs)
            ee.ech_retry_configs = ext.data
        elif ext.type in (EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_NEW):
            try:
                settings = Reader(ext.data).vec16()
                protocols = Reader(settings)
                while len(protocols):
                    ee.alps_protocols.append(
                        protocols.vec8().decode("latin-1")
                    )
            except ValueError:
                # ALPS payload is application data; keep the handshake usable
                # even if a server sends an unknown/opaque form.
                ee.alps_protocols = []
    return ee


@dataclass
class CertificateEntry:
    data: bytes
    extensions: list[ParsedExtension] = field(default_factory=list)


@dataclass
class CertificateMessage:
    certificate_list: list[CertificateEntry]
    raw: bytes
    request_context: bytes = b""


def parse_certificate(body: bytes, tls13: bool, raw: bytes = b"") -> CertificateMessage:
    r = Reader(body)
    ctx = b""
    if tls13:
        ctx = r.vec8()
    entries = []
    cert_list = Reader(r.vec24())
    while len(cert_list):
        entry = CertificateEntry(cert_list.vec24())
        if tls13 and len(cert_list):
            entry.extensions = parse_extension_list(cert_list.vec16())
        entries.append(entry)
    return CertificateMessage(entries, raw=raw, request_context=ctx)


@dataclass
class CompressedCertificate:
    algorithm: int
    uncompressed_length: int
    compressed: bytes
    raw: bytes = b""


def parse_compressed_certificate(body: bytes, raw: bytes = b"") -> CompressedCertificate:
    r = Reader(body)
    algorithm = r.u16()
    uncompressed_length = r.u24()
    compressed = r.vec24()
    return CompressedCertificate(algorithm, uncompressed_length, compressed, raw=raw)


@dataclass
class CertificateVerify:
    signature_scheme: int
    signature: bytes
    raw: bytes = b""


def parse_certificate_verify(body: bytes, raw: bytes = b"") -> CertificateVerify:
    r = Reader(body)
    return CertificateVerify(r.u16(), r.vec16(), raw=raw)


@dataclass
class CertificateRequest:
    request_context: bytes
    signature_algorithms: list[int]
    certificate_authorities: list[bytes]
    raw: bytes = b""


def parse_certificate_request(
    body: bytes, tls13: bool, raw: bytes = b"", tls12: bool = True
) -> CertificateRequest:
    r = Reader(body)
    ctx = r.vec8() if tls13 else b""
    sig_algs: list[int] = []
    cas: list[bytes] = []
    if tls13:
        extensions = parse_extension_list(r.vec16())
        for ext in extensions:
            if ext.type == EXT_SIGNATURE_ALGORITHMS:
                er = Reader(ext.data)
                algs = Reader(er.vec16())
                while len(algs):
                    sig_algs.append(algs.u16())
            elif ext.type == 47:  # certificate_authorities
                ca_reader = Reader(ext.data)
                authorities = Reader(ca_reader.vec16())
                while len(authorities):
                    cas.append(authorities.vec16())
    else:
        cert_types = Reader(r.vec8())
        while len(cert_types):
            cert_types.u8()
        if tls12:
            algs = Reader(r.vec16())
            while len(algs):
                sig_algs.append(algs.u16())
        cas_raw = Reader(r.vec16())
        while len(cas_raw):
            cas.append(cas_raw.vec16())
    return CertificateRequest(ctx, sig_algs, cas, raw=raw)


@dataclass
class ServerKeyExchange:
    curve_type: int
    named_curve: int
    public_key: bytes
    signature_scheme: int
    signature: bytes
    params: bytes
    raw: bytes = b""


def parse_server_key_exchange(body: bytes, raw: bytes = b"", tls12: bool = True) -> ServerKeyExchange:
    r = Reader(body)
    start = r.pos
    curve_type = r.u8()
    named_curve = r.u16()
    public_key = r.vec8()
    params = body[start : r.pos]
    if tls12:
        scheme = r.u16()
    else:
        # TLS 1.0/1.1 signatures do not carry a SignatureScheme.
        scheme = 0
    signature = r.vec16()
    return ServerKeyExchange(curve_type, named_curve, public_key, scheme, signature, params, raw)


@dataclass
class KeyUpdate:
    request_update: int
    raw: bytes = b""


def parse_key_update(body: bytes, raw: bytes = b"") -> KeyUpdate:
    return KeyUpdate(body[0] if body else 0, raw=raw)


@dataclass
class NewSessionTicket:
    lifetime: int
    age_add: int
    nonce: bytes
    ticket: bytes
    max_early_data: int = 0
    raw: bytes = b""


def parse_new_session_ticket(body: bytes, raw: bytes = b"") -> NewSessionTicket:
    """Parse a TLS 1.3 NewSessionTicket message body."""
    r = Reader(body)
    lifetime = r.u32()
    age_add = r.u32()
    nonce = r.vec8()
    ticket = r.vec16()
    max_early_data = 0
    if len(r):
        for ext in parse_extension_list(r.vec16()):
            if ext.type == 42 and len(ext.data) == 4:  # early_data
                max_early_data = int.from_bytes(ext.data, "big")
    return NewSessionTicket(lifetime, age_add, nonce, ticket, max_early_data, raw)


def parse_tls12_new_session_ticket(body: bytes) -> tuple[int, bytes]:
    """Return ``(lifetime_hint, ticket)`` for a TLS 1.2 ticket message."""
    r = Reader(body)
    lifetime = r.u32()
    ticket = r.vec16()
    return lifetime, ticket


# ---------------------------------------------------------------------------
# Client-side message serialisation
# ---------------------------------------------------------------------------


def client_key_exchange(public_key: bytes) -> bytes:
    return make_handshake(16, vec8(public_key))


def client_key_exchange_rsa(encrypted_pre_master: bytes) -> bytes:
    return make_handshake(16, vec16(encrypted_pre_master))


def finished(verify_data: bytes) -> bytes:
    return make_handshake(20, verify_data)


def certificate(cert_chain: list[bytes], tls13: bool, context: bytes = b"") -> bytes:
    if tls13:
        entries = b"".join(vec24(cert) + vec16(b"") for cert in cert_chain)
        body = vec8(context) + vec24(entries)
    else:
        entries = b"".join(vec24(cert) for cert in cert_chain)
        body = vec24(entries)
    return make_handshake(11, body)


def certificate_verify(scheme: int, signature: bytes) -> bytes:
    return make_handshake(15, uint16(scheme) + vec16(signature))


def certificate_verify_legacy(signature: bytes) -> bytes:
    return make_handshake(15, vec16(signature))


def key_update(request: bool) -> bytes:
    return make_handshake(24, uint8(1 if request else 0))


def end_of_early_data() -> bytes:
    return make_handshake(5, b"")


def alert(level: int, description: int) -> bytes:
    return bytes([level, description])


def describe_handshake_type(t: int) -> str:
    return HANDSHAKE_NAMES.get(t, f"Handshake({t})")


def signature_hash_name(scheme: int) -> str | None:
    return SIG_HASH_NAMES.get(scheme)
