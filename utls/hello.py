"""ClientHello specification and marshalling."""

from __future__ import annotations

import copy
import hashlib
import hmac
import os
import random
from dataclasses import dataclass, field

from .constants import (
    GREASE_PLACEHOLDER,
    VERSION_TLS10,
    VERSION_TLS12,
)
from .extensions import (
    GREASEExtension,
    HelloContext,
    KeyShareExtension,
    PaddingExtension,
    TLSExtension,
    uint16,
    uint24,
    uint8,
    vec8,
    vec16,
    boring_padding_style,
)


@dataclass
class ClientHelloSpec:
    """Description of the ClientHello to emit.

    Mirrors uTLS' ``ClientHelloSpec``: cipher suite order, compression methods
    and the exact extension list (including empty "GREASE" extensions and a
    padding extension) are all part of the fingerprint.
    """

    tls_vers_min: int = VERSION_TLS10
    tls_vers_max: int = VERSION_TLS12
    cipher_suites: list[int] = field(default_factory=list)
    compression_methods: list[int] = field(default_factory=lambda: [0])
    extensions: list[TLSExtension] = field(default_factory=list)
    get_session_id: object | None = None

    def clone(self) -> "ClientHelloSpec":
        return copy.deepcopy(self)

    def to_dict(self) -> dict:
        from .spec_json import spec_to_dict

        return spec_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ClientHelloSpec":
        from .spec_json import spec_from_dict

        return spec_from_dict(data)

    def to_json(self, **kwargs) -> str:
        from .spec_json import spec_to_json

        return spec_to_json(self, **kwargs)

    @classmethod
    def from_json(cls, data) -> "ClientHelloSpec":
        from .spec_json import spec_from_json

        return spec_from_json(data)


def shuffle_chrome_tls_extensions(exts: list[TLSExtension]) -> list[TLSExtension]:
    """Shuffle every extension except GREASE, padding and pre_shared_key.

    Chrome 106+ randomises the extension order on every connection; uTLS
    reproduces this when building the spec.
    """
    from .constants import EXT_PRE_SHARED_KEY

    out = list(exts)
    indices = [
        i
        for i, ext in enumerate(out)
        if not isinstance(ext, (GREASEExtension, PaddingExtension))
        and getattr(ext, "type_id", None) != EXT_PRE_SHARED_KEY
    ]
    values = [out[i] for i in indices]
    random.shuffle(values)
    for i, value in zip(indices, values):
        out[i] = value
    return out


@dataclass
class BuiltClientHello:
    raw: bytes
    body: bytes
    session_id: bytes
    key_shares: dict[int, object]
    context: HelloContext


def _assign_grease(ctx: HelloContext) -> None:
    for i, ext in enumerate(ctx._extensions):  # type: ignore[attr-defined]
        if isinstance(ext, GREASEExtension):
            ext.index = ctx._grease_ext_count  # type: ignore[attr-defined]
            # uTLS/BoringSSL: the second GREASE extension carries a single
            # zero byte, independent of what the preset declared.
            if ext.index == 1:
                ext.body_bytes = b"\x00"
            ctx._grease_ext_count += 1  # type: ignore[attr-defined]


def build_client_hello(
    spec: ClientHelloSpec,
    *,
    server_name: str = "",
    alpn_protocols: list[str] | None = None,
    random_bytes: bytes | None = None,
    session_id: bytes | None = None,
    grease_seed: list[int] | None = None,
    session_ticket: bytes = b"",
    certificate_compression_algs: list[int] | None = None,
) -> BuiltClientHello:
    """Serialise a ClientHello for ``spec``.

    Returns the full handshake message (including the 4-byte handshake header),
    exactly like ``UConn.HandshakeState.Hello.Raw`` in uTLS.
    """
    spec = spec.clone()
    if not spec.cipher_suites:
        spec.cipher_suites = [0x1301, 0x1302, 0x1303]
    if not spec.compression_methods:
        spec.compression_methods = [0]

    if grease_seed is None:
        grease_seed = [int.from_bytes(os.urandom(2), "little") for _ in range(8)]
    if len(grease_seed) != 8:
        raise ValueError("GREASE seed must contain 8 values")

    ctx = HelloContext(
        server_name=server_name,
        alpn_protocols=list(alpn_protocols or []),
        grease=list(grease_seed),
        session_ticket=session_ticket,
        cert_compression_algs=list(certificate_compression_algs or []),
    )
    ctx._extensions = spec.extensions  # type: ignore[attr-defined]
    ctx._grease_ext_count = 0  # type: ignore[attr-defined]
    _assign_grease(ctx)

    # GREASE the cipher suite placeholder exactly once (BoringSSL uses the
    # "cipher" seed slot).
    cipher_suites = []
    cipher_grease = None
    for suite in spec.cipher_suites:
        if suite == GREASE_PLACEHOLDER:
            if cipher_grease is None:
                cipher_grease = ctx.grease_value(0)
            cipher_suites.append(cipher_grease)
        else:
            cipher_suites.append(suite)

    if session_id is None:
        # uTLS always uses a 32-byte random session ID as a TLS 1.3
        # compatibility measure.
        session_id = os.urandom(32)
    if random_bytes is None:
        random_bytes = os.urandom(32)
    if len(random_bytes) != 32:
        raise ValueError("ClientHello random must be 32 bytes")

    version = VERSION_TLS12 if spec.tls_vers_max >= VERSION_TLS12 else spec.tls_vers_max
    header = (
        uint16(version)
        + random_bytes
        + vec8(session_id)
        + vec16(b"".join(uint16(c) for c in cipher_suites))
        + vec8(bytes(spec.compression_methods))
    )

    padding_ext = None
    padding_index = -1
    blobs: list[bytes] = []
    blob_exts: list[TLSExtension] = []
    for ext in spec.extensions:
        if isinstance(ext, PaddingExtension):
            if padding_ext is not None:
                raise ValueError("multiple padding extensions")
            padding_ext = ext
            padding_index = len(blobs)
            blobs.append(b"")  # placeholder, inserted below
            blob_exts.append(ext)
            continue
        blobs.append(ext.marshal(ctx))
        blob_exts.append(ext)

    unpadded_len = 4 + len(header) + 2 + sum(len(b) for b in blobs)
    if padding_ext is not None:
        pad_len, will_pad = 0, False
        if padding_ext.padding_len_func is not None:
            pad_len, will_pad = padding_ext.padding_len_func(unpadded_len)
        elif padding_ext.pad_len is not None:
            pad_len, will_pad = padding_ext.pad_len, True
        else:
            pad_len, will_pad = boring_padding_style(unpadded_len)

        idx = padding_index
        if will_pad:
            blobs[idx] = uint16(padding_ext.type_id) + vec16(b"\x00" * pad_len)
        else:
            # A padding extension that decides not to pad is omitted entirely.
            blobs.pop(idx)
            blob_exts.pop(idx)

    # A session ticket extension with an empty body is fine; uTLS leaves it
    # empty for fresh connections.
    ext_bytes = b"".join(blobs)
    body = header + vec16(ext_bytes)
    raw = bytearray(uint8(1) + uint24(len(body)) + body)

    # Fill TLS 1.3 PSK binders now that the full ClientHello is known (minus
    # the binders themselves, per RFC 8446 4.2.11.2).
    from .crypto import derive_secret, hkdf_expand_label, hkdf_extract
    from .extensions import PreSharedKeyExtension

    offset = 4 + len(header) + 2
    for ext, blob in zip(blob_exts, blobs):
        if isinstance(ext, PreSharedKeyExtension):
            body_start = offset + 4
            truncated_len = body_start + ext.truncated_offset
            binder_start = truncated_len + 3  # binders length + per-entry length
            early_secret = hkdf_extract(ext.hash_name, b"", ext.psk)
            binder_key = derive_secret(
                ext.hash_name,
                early_secret,
                "res binder",
                hashlib.new(ext.hash_name, b"").digest(),
            )
            finished_key = hkdf_expand_label(
                ext.hash_name, binder_key, "finished", b"", ext.binder_len
            )
            digest = hashlib.new(ext.hash_name, bytes(raw[:truncated_len])).digest()
            binder = hmac.new(finished_key, digest, ext.hash_name).digest()
            raw[binder_start : binder_start + ext.binder_len] = binder
        offset += len(blob)

    return BuiltClientHello(
        raw=bytes(raw),
        body=body,
        session_id=session_id,
        key_shares=dict(ctx.key_shares),
        context=ctx,
    )


def build_client_hello_from_parsed(raw: bytes) -> ClientHelloSpec:
    """Parse a captured ClientHello into a ``ClientHelloSpec``.

    Useful for replaying/hardening a fingerprint obtained elsewhere.  Unknown
    extensions are preserved as :class:`~utls.extensions.GenericExtension`.
    """
    from .extensions import (
        ALPNExtension,
        ApplicationSettingsExtension,
        CompressCertificateExtension,
        ExtendedMasterSecretExtension,
        FakeChannelIDExtension,
        FakeDelegatedCredentialsExtension,
        FakeRecordSizeLimitExtension,
        GenericExtension,
        KeyShareEntry,
        PSKKeyExchangeModesExtension,
        RenegotiationInfoExtension,
        SNIExtension,
        SCTExtension,
        SessionTicketExtension,
        SignatureAlgorithmsExtension,
        StatusRequestExtension,
        SupportedGroupsExtension,
        SupportedPointsExtension,
        SupportedVersionsExtension,
    )
    from .constants import (
        EXT_ALPN,
        EXT_APPLICATION_SETTINGS,
        EXT_APPLICATION_SETTINGS_NEW,
        EXT_CHANNEL_ID,
        EXT_CHANNEL_ID_OLD,
        EXT_COMPRESS_CERTIFICATE,
        EXT_DELEGATED_CREDENTIALS,
        EXT_EC_POINT_FORMATS,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_KEY_SHARE,
        EXT_PADDING,
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
    )
    data = raw
    if data and data[0] == 1:
        data = data[4:]
    if len(data) < 34:
        raise ValueError("short ClientHello")
    pos = 0
    legacy_version = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    pos += 32  # random
    sid_len = data[pos]
    pos += 1 + sid_len
    cs_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    ciphers = [int.from_bytes(data[pos + i : pos + i + 2], "big") for i in range(0, cs_len, 2)]
    pos += cs_len
    comp_len = data[pos]
    pos += 1
    comps = list(data[pos : pos + comp_len])
    pos += comp_len
    ext_total = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    end = pos + ext_total

    exts: list[TLSExtension] = []
    min_ver, max_ver = VERSION_TLS10, VERSION_TLS12
    while pos + 4 <= end:
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
        body = data[pos + 4 : pos + 4 + ext_len]
        pos += 4 + ext_len
        if ext_type == EXT_SNI:
            exts.append(SNIExtension())
        elif ext_type == EXT_SUPPORTED_GROUPS:
            n = int.from_bytes(body[:2], "big")
            groups = [int.from_bytes(body[2 + i : 4 + i], "big") for i in range(0, n, 2)]
            exts.append(SupportedGroupsExtension(groups))
        elif ext_type == EXT_EC_POINT_FORMATS:
            exts.append(SupportedPointsExtension(body[1 : 1 + body[0]]))
        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            n = int.from_bytes(body[:2], "big")
            algs = [int.from_bytes(body[2 + i : 4 + i], "big") for i in range(0, n, 2)]
            exts.append(SignatureAlgorithmsExtension(algs))
        elif ext_type == EXT_ALPN:
            n = int.from_bytes(body[:2], "big")
            p = 2
            protos = []
            while p < 2 + n:
                l = body[p]
                protos.append(body[p + 1 : p + 1 + l].decode())
                p += 1 + l
            exts.append(ALPNExtension(protos))
        elif ext_type == EXT_SUPPORTED_VERSIONS:
            n = body[0]
            versions = [int.from_bytes(body[1 + i : 3 + i], "big") for i in range(0, n, 2)]
            exts.append(SupportedVersionsExtension(versions))
            real = [v for v in versions if not (v & 0x0F0F == 0x0A0A)]
            if real:
                min_ver, max_ver = min(real), max(real)
        elif ext_type == EXT_KEY_SHARE:
            n = int.from_bytes(body[:2], "big")
            p = 2
            entries = []
            while p < 2 + n:
                group = int.from_bytes(body[p : p + 2], "big")
                l = int.from_bytes(body[p + 2 : p + 4], "big")
                entries.append(KeyShareEntry(group, body[p + 4 : p + 4 + l]))
                p += 4 + l
            exts.append(KeyShareExtension(entries))
        elif ext_type == EXT_PSK_KEY_EXCHANGE_MODES:
            exts.append(PSKKeyExchangeModesExtension(list(body[1 : 1 + body[0]])))
        elif ext_type == EXT_STATUS_REQUEST:
            exts.append(StatusRequestExtension())
        elif ext_type == EXT_SCT:
            exts.append(SCTExtension())
        elif ext_type == EXT_EXTENDED_MASTER_SECRET:
            exts.append(ExtendedMasterSecretExtension())
        elif ext_type == EXT_SESSION_TICKET:
            exts.append(SessionTicketExtension())
        elif ext_type == EXT_RENEGOTIATION_INFO:
            exts.append(RenegotiationInfoExtension(body[1 : 1 + body[0]] if body else b""))
        elif ext_type == EXT_COMPRESS_CERTIFICATE:
            cm = list(body[1 : 1 + body[0]])
            algs = [int.from_bytes(cm[i : i + 2], "big") for i in range(0, len(cm), 2)]
            exts.append(CompressCertificateExtension(algs))
        elif ext_type in (EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_NEW):
            # body: uint16 alps_len, uint16 list_len, list
            alps_len = int.from_bytes(body[:2], "big")
            inner = body[4 : 2 + alps_len]
            protos = []
            p = 0
            while p < len(inner):
                l = inner[p]
                protos.append(inner[p + 1 : p + 1 + l].decode())
                p += 1 + l
            exts.append(
                ApplicationSettingsExtension(
                    protos, new=(ext_type == EXT_APPLICATION_SETTINGS_NEW)
                )
            )
        elif ext_type == EXT_DELEGATED_CREDENTIALS:
            n = int.from_bytes(body[:2], "big")
            algs = [int.from_bytes(body[2 + i : 4 + i], "big") for i in range(0, n, 2)]
            exts.append(FakeDelegatedCredentialsExtension(algs))
        elif ext_type == EXT_RECORD_SIZE_LIMIT:
            exts.append(FakeRecordSizeLimitExtension(int.from_bytes(body[:2], "big")))
        elif ext_type in (EXT_CHANNEL_ID, EXT_CHANNEL_ID_OLD):
            exts.append(FakeChannelIDExtension(old=(ext_type == EXT_CHANNEL_ID_OLD)))
        elif ext_type == EXT_PADDING:
            exts.append(PaddingExtension(pad_len=len(body)))
        else:
            exts.append(GenericExtension(ext_type, body))

    if legacy_version < VERSION_TLS12 and max_ver < legacy_version:
        max_ver = legacy_version
    return ClientHelloSpec(
        tls_vers_min=min_ver,
        tls_vers_max=max_ver,
        cipher_suites=ciphers,
        compression_methods=comps or [0],
        extensions=exts,
    )


def set_tls_versions(spec: ClientHelloSpec, min_ver: int, max_ver: int) -> None:
    """Keep versions consistent between spec fields and supported_versions."""
    from .constants import EXT_SUPPORTED_VERSIONS, is_grease

    spec.tls_vers_min = min_ver
    spec.tls_vers_max = max_ver
    for ext in list(spec.extensions):
        if getattr(ext, "type_id", None) != EXT_SUPPORTED_VERSIONS:
            continue
        if max_ver < VERSION_TLS12:
            # TLS 1.0/1.1 clients do not send supported_versions at all.
            spec.extensions.remove(ext)
            continue
        versions = [
            v
            for v in ext.versions  # type: ignore[attr-defined]
            if is_grease(v) or min_ver <= v <= max_ver
        ]
        ext.versions = versions  # type: ignore[attr-defined]
