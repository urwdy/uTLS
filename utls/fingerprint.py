"""Fingerprint helpers: JA3 and ClientHello inspection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .constants import (
    EXT_EC_POINT_FORMATS,
    EXT_SUPPORTED_GROUPS,
    is_grease,
)


@dataclass
class ClientHelloInfo:
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: list[int]
    compression_methods: list[int]
    extensions: list[tuple[int, bytes]] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    alpn_protocols: list[str] = field(default_factory=list)
    server_name: str = ""

    @property
    def extension_ids(self) -> list[int]:
        return [t for t, _ in self.extensions]

    def extension_map(self) -> dict[int, bytes]:
        return {t: d for t, d in self.extensions}


def parse_client_hello(raw: bytes) -> ClientHelloInfo:
    """Parse a captured ClientHello handshake message."""
    from .messages import Reader

    if raw and raw[0] == 1:
        r = Reader(raw[4:])
    else:
        r = Reader(raw)
    legacy_version = r.u16()
    random_bytes = r.take(32)
    session_id = r.vec8()
    cs = Reader(r.vec16())
    cipher_suites = []
    while len(cs):
        cipher_suites.append(cs.u16())
    compression = list(r.vec8())
    extensions: list[tuple[int, bytes]] = []
    if len(r):
        ext_reader = Reader(r.vec16())
        while len(ext_reader):
            ext_type = ext_reader.u16()
            extensions.append((ext_type, ext_reader.vec16()))

    info = ClientHelloInfo(
        legacy_version=legacy_version,
        random=random_bytes,
        session_id=session_id,
        cipher_suites=cipher_suites,
        compression_methods=compression,
        extensions=extensions,
    )
    ext_map = info.extension_map()
    if EXT_SUPPORTED_GROUPS in ext_map:
        gr = Reader(ext_map[EXT_SUPPORTED_GROUPS])
        groups = Reader(gr.vec16())
        while len(groups):
            info.groups.append(groups.u16())
    if EXT_EC_POINT_FORMATS in ext_map:
        pr = Reader(ext_map[EXT_EC_POINT_FORMATS])
        info.point_formats = list(pr.vec8())
    alpn = ext_map.get(16)
    if alpn:
        ar = Reader(alpn)
        protos = Reader(ar.vec16())
        while len(protos):
            info.alpn_protocols.append(protos.vec8().decode("latin-1"))
    sni = ext_map.get(0)
    if sni:
        sr = Reader(sni)
        names = Reader(sr.vec16())
        while len(names):
            name_type = names.u8()
            name = names.vec16()
            if name_type == 0:
                info.server_name = name.decode("idna")
    return info


def ja3(client_hello: bytes) -> str:
    """JA3 string for a ClientHello (GREASE values removed)."""
    info = parse_client_hello(client_hello)
    ciphers = [str(c) for c in info.cipher_suites if not is_grease(c)]
    extensions = [str(t) for t, _ in info.extensions if not is_grease(t)]
    groups = [str(g) for g in info.groups if not is_grease(g)]
    points = [str(p) for p in info.point_formats]
    return ",".join(
        [
            str(info.legacy_version),
            "-".join(ciphers),
            "-".join(extensions),
            "-".join(groups),
            "-".join(points),
        ]
    )


def ja3_hash(client_hello: bytes) -> str:
    return hashlib.md5(ja3(client_hello).encode(), usedforsecurity=False).hexdigest()


def describe(client_hello: bytes) -> dict:
    """Human readable summary used by the CLI and tests."""
    from .constants import CIPHER_SUITES, EXT_NAMES, GROUP_NAMES

    info = parse_client_hello(client_hello)
    return {
        "legacy_version": info.legacy_version,
        "session_id_len": len(info.session_id),
        "cipher_suites": [
            CIPHER_SUITES[c].name if c in CIPHER_SUITES else f"0x{c:04x}"
            for c in info.cipher_suites
        ],
        "extensions": [
            EXT_NAMES.get(t, f"0x{t:04x}") for t in info.extension_ids
        ],
        "groups": [GROUP_NAMES.get(g, f"0x{g:04x}") for g in info.groups],
        "alpn": info.alpn_protocols,
        "server_name": info.server_name,
        "ja3": ja3(client_hello),
        "ja3_hash": ja3_hash(client_hello),
    }


class Fingerprinter:
    """uTLS-style wrapper for parsing and serializing ClientHello specs."""

    def FingerprintClientHello(self, data: bytes):
        from .hello import build_client_hello_from_parsed

        return build_client_hello_from_parsed(data)

    def RawClientHello(self, data: bytes):
        return self.FingerprintClientHello(data)

    def UnmarshalJSONClientHello(self, data):
        from .hello import ClientHelloSpec

        return ClientHelloSpec.from_json(data)

    def MarshalJSONClientHello(self, spec, **kwargs) -> str:
        return spec.to_json(**kwargs)

    # Pythonic aliases
    fingerprint_client_hello = FingerprintClientHello
    raw_client_hello = RawClientHello
    unmarshal_json_client_hello = UnmarshalJSONClientHello
    marshal_json_client_hello = MarshalJSONClientHello


__all__ = [
    "ClientHelloInfo",
    "Fingerprinter",
    "parse_client_hello",
    "ja3",
    "ja3_hash",
    "describe",
]
