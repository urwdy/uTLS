"""JSON/raw serialization for :class:`utls.hello.ClientHelloSpec`.

The dictionary format intentionally follows uTLS' ClientHelloSpec JSON keys
where practical (``min_vers``, ``max_vers``, ``cipher_suites`` and
``extensions``), while still accepting integer extension/cipher identifiers.
"""

from __future__ import annotations

import json

from .constants import (
    CIPHER_ALIASES,
    CIPHER_SUITES,
    CIPHER_SUITES_BY_NAME,
    EXT_APPLICATION_SETTINGS_NEW,
    EXT_CHANNEL_ID_OLD,
)
from .extensions import (
    ALPNExtension,
    ApplicationSettingsExtension,
    CompressCertificateExtension,
    CookieExtension,
    ECHInnerExtension,
    ECHOuterExtension,
    EarlyDataExtension,
    ExtendedMasterSecretExtension,
    FakeChannelIDExtension,
    FakeDelegatedCredentialsExtension,
    FakeRecordSizeLimitExtension,
    GenericExtension,
    GREASEEcHExtension,
    GREASEExtension,
    KeyShareEntry,
    KeyShareExtension,
    NPNExtension,
    PaddingExtension,
    PreSharedKeyExtension,
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
    TrustAnchorsExtension,
    boring_padding_style,
)

# These imports are deliberately local to avoid a module import cycle:
# hello.py imports this module only from methods.


def _bytes_hex(value) -> str:
    if isinstance(value, str):
        return value
    return bytes(value).hex()


def _hex_bytes(value) -> bytes:
    if not value:
        return b""
    if isinstance(value, str):
        return bytes.fromhex(value)
    return bytes(value)


def _cipher_name(value: int):
    suite = CIPHER_SUITES.get(value)
    return suite.name if suite is not None else value


def _cipher_value(value) -> int:
    if isinstance(value, int):
        return value
    if value in CIPHER_SUITES_BY_NAME:
        return CIPHER_SUITES_BY_NAME[value].id
    if value in CIPHER_ALIASES:
        return CIPHER_ALIASES[value]
    raise ValueError(f"unknown cipher suite {value!r}")


def extension_to_dict(ext) -> dict:
    """Serialize one extension description."""
    if isinstance(ext, PreSharedKeyExtension):
        raise ValueError("pre_shared_key extensions contain secrets and are not serializable")
    if isinstance(ext, SNIExtension):
        return {"type": "sni"}
    if isinstance(ext, StatusRequestExtension):
        return {"type": "status_request"}
    if isinstance(ext, SupportedGroupsExtension):
        return {"type": "supported_groups", "groups": list(ext.curves)}
    if isinstance(ext, SupportedPointsExtension):
        return {"type": "supported_points", "points": ext.points.hex()}
    if isinstance(ext, SignatureAlgorithmsExtension):
        return {"type": "signature_algorithms", "algorithms": list(ext.algorithms)}
    if isinstance(ext, ALPNExtension):
        return {"type": "alpn", "protocols": list(ext.protocols)}
    if isinstance(ext, SCTExtension):
        return {"type": "sct"}
    if isinstance(ext, ExtendedMasterSecretExtension):
        return {"type": "ems"}
    if isinstance(ext, SessionTicketExtension):
        return {"type": "session_ticket"}
    if isinstance(ext, CompressCertificateExtension):
        return {
            "type": "compress_certificate",
            "algorithms": list(ext.algorithms),
        }
    if isinstance(ext, FakeRecordSizeLimitExtension):
        return {"type": "record_size_limit", "limit": ext.limit}
    if isinstance(ext, FakeDelegatedCredentialsExtension):
        return {
            "type": "delegated_credentials",
            "algorithms": list(ext.algorithms),
        }
    if isinstance(ext, SupportedVersionsExtension):
        return {"type": "supported_versions", "versions": list(ext.versions)}
    if isinstance(ext, PSKKeyExchangeModesExtension):
        return {"type": "psk_modes", "modes": list(ext.modes)}
    if isinstance(ext, KeyShareExtension):
        return {
            "type": "key_share",
            "shares": [
                {
                    "group": entry.group,
                    "data": _bytes_hex(entry.data) if entry.data is not None else None,
                    "reuse": entry.reuse,
                }
                for entry in ext.key_shares
            ],
        }
    if isinstance(ext, GREASEExtension):
        return {"type": "grease", "body": _bytes_hex(ext.body_bytes)}
    if isinstance(ext, GREASEEcHExtension):
        return {
            "type": "ech",
            "suites": [list(suite) for suite in ext.cipher_suites],
            "payload_lens": list(ext.payload_lens),
            "encapsulated_key": (
                _bytes_hex(ext.encapsulated_key)
                if ext.encapsulated_key is not None
                else None
            ),
        }
    if isinstance(ext, ECHInnerExtension):
        return {"type": "ech_inner"}
    if isinstance(ext, ECHOuterExtension):
        return {
            "type": "ech_outer",
            "config_id": ext.config_id,
            "kdf_id": ext.kdf_id,
            "aead_id": ext.aead_id,
            "encapsulated_key": _bytes_hex(ext.encapsulated_key),
            "payload": _bytes_hex(ext.payload),
        }
    if isinstance(ext, ApplicationSettingsExtension):
        return {
            "type": (
                "alps_new"
                if ext.type_id == EXT_APPLICATION_SETTINGS_NEW
                else "alps"
            ),
            "protocols": list(ext.protocols),
        }
    if isinstance(ext, FakeChannelIDExtension):
        return {"type": "channel_id", "old": ext.type_id == EXT_CHANNEL_ID_OLD}
    if isinstance(ext, NPNExtension):
        return {"type": "npn"}
    if isinstance(ext, RenegotiationInfoExtension):
        return {"type": "renegotiation", "data": _bytes_hex(ext.renegotiation)}
    if isinstance(ext, TrustAnchorsExtension):
        return {
            "type": "trust_anchors",
            "ids": [_bytes_hex(item) for item in ext.trust_anchor_ids],
        }
    if isinstance(ext, CookieExtension):
        return {"type": "cookie", "cookie": _bytes_hex(ext.cookie)}
    if isinstance(ext, EarlyDataExtension):
        return {"type": "early_data"}
    if isinstance(ext, PaddingExtension):
        return {
            "type": "padding",
            "length": ext.pad_len or 0,
            "dynamic": ext.padding_len_func is not None,
        }
    if isinstance(ext, GenericExtension):
        return {"type": "unknown", "type_id": ext.type_id, "data": _bytes_hex(ext.data)}
    return {"type": "unknown", "type_id": getattr(ext, "type_id", 0), "data": ""}


def extension_from_dict(data: dict):
    """Rebuild an extension from its dictionary form."""
    if not isinstance(data, dict) or "type" not in data:
        raise ValueError("extension entries must be objects with a type")
    kind = data["type"]
    if isinstance(kind, int):
        return GenericExtension(kind, _hex_bytes(data.get("data", "")))
    kind = str(kind).lower()
    if kind == "sni":
        return SNIExtension()
    if kind == "status_request":
        return StatusRequestExtension()
    if kind == "supported_groups":
        return SupportedGroupsExtension(list(data.get("groups", [])))
    if kind == "supported_points":
        return SupportedPointsExtension(_hex_bytes(data.get("points", "00")))
    if kind == "signature_algorithms":
        return SignatureAlgorithmsExtension(list(data.get("algorithms", [])))
    if kind == "alpn":
        return ALPNExtension(list(data.get("protocols", [])))
    if kind == "sct":
        return SCTExtension()
    if kind == "ems":
        return ExtendedMasterSecretExtension()
    if kind == "session_ticket":
        return SessionTicketExtension()
    if kind == "compress_certificate":
        return CompressCertificateExtension(list(data.get("algorithms", [])))
    if kind == "record_size_limit":
        return FakeRecordSizeLimitExtension(int(data.get("limit", 0x4001)))
    if kind == "delegated_credentials":
        return FakeDelegatedCredentialsExtension(list(data.get("algorithms", [])))
    if kind == "supported_versions":
        return SupportedVersionsExtension(list(data.get("versions", [])))
    if kind == "psk_modes":
        return PSKKeyExchangeModesExtension(list(data.get("modes", [1])))
    if kind == "key_share":
        shares = []
        for item in data.get("shares", []):
            value = item.get("data")
            shares.append(
                KeyShareEntry(
                    int(item["group"]),
                    _hex_bytes(value) if value is not None else None,
                    item.get("reuse"),
                )
            )
        return KeyShareExtension(shares)
    if kind == "grease":
        return GREASEExtension(_hex_bytes(data.get("body", "")))
    if kind == "ech":
        return GREASEEcHExtension(
            [tuple(item) for item in data.get("suites", [(1, 1)])],
            list(data.get("payload_lens", [128])),
            _hex_bytes(data["encapsulated_key"])
            if data.get("encapsulated_key")
            else None,
        )
    if kind == "ech_inner":
        return ECHInnerExtension()
    if kind == "ech_outer":
        return ECHOuterExtension(
            int(data["config_id"]),
            int(data["kdf_id"]),
            int(data["aead_id"]),
            _hex_bytes(data.get("encapsulated_key", "")),
            _hex_bytes(data.get("payload", "")),
        )
    if kind in ("alps", "alps_new"):
        return ApplicationSettingsExtension(
            list(data.get("protocols", [])), new=(kind == "alps_new")
        )
    if kind == "channel_id":
        return FakeChannelIDExtension(bool(data.get("old", False)))
    if kind == "npn":
        return NPNExtension()
    if kind == "renegotiation":
        return RenegotiationInfoExtension(_hex_bytes(data.get("data", "")))
    if kind == "trust_anchors":
        return TrustAnchorsExtension(
            [_hex_bytes(item) for item in data.get("ids", [])]
        )
    if kind == "cookie":
        return CookieExtension(_hex_bytes(data.get("cookie", "")))
    if kind == "early_data":
        return EarlyDataExtension()
    if kind == "padding":
        if data.get("dynamic"):
            return PaddingExtension(padding_len_func=boring_padding_style)
        return PaddingExtension(pad_len=int(data.get("length", 0)))
    if kind == "unknown":
        return GenericExtension(
            int(data.get("type_id", 0)), _hex_bytes(data.get("data", ""))
        )
    raise ValueError(f"unknown extension type {kind!r}")


def spec_to_dict(spec) -> dict:
    return {
        "min_vers": spec.tls_vers_min,
        "max_vers": spec.tls_vers_max,
        "cipher_suites": [_cipher_name(value) for value in spec.cipher_suites],
        "compression_methods": list(spec.compression_methods),
        "extensions": [extension_to_dict(ext) for ext in spec.extensions],
    }


def spec_from_dict(data: dict):
    from .hello import ClientHelloSpec

    if not isinstance(data, dict):
        raise ValueError("ClientHelloSpec JSON must be an object")
    extensions = [extension_from_dict(item) for item in data.get("extensions", [])]
    return ClientHelloSpec(
        tls_vers_min=int(
            data.get("min_vers", data.get("tls_vers_min", 0x0301))
        ),
        tls_vers_max=int(
            data.get("max_vers", data.get("tls_vers_max", 0x0303))
        ),
        cipher_suites=[_cipher_value(value) for value in data.get("cipher_suites", [])],
        compression_methods=list(data.get("compression_methods", [0])),
        extensions=extensions,
    )


def spec_to_json(spec, **kwargs) -> str:
    return json.dumps(spec_to_dict(spec), **kwargs)


def spec_from_json(data):
    if isinstance(data, (bytes, bytearray)):
        data = data.decode()
    if isinstance(data, str):
        data = json.loads(data)
    return spec_from_dict(data)
