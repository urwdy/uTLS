"""Generated legacy ClientHello presets (from uTLS specs).

This module is generated from Go uTLS' ClientHelloSpec definitions.
Do not edit by hand.
"""

from __future__ import annotations

from .extensions import (
    ALPNExtension,
    ApplicationSettingsExtension,
    CompressCertificateExtension,
    ExtendedMasterSecretExtension,
    FakeChannelIDExtension,
    FakeDelegatedCredentialsExtension,
    FakeRecordSizeLimitExtension,
    GREASEExtension,
    KeyShareEntry,
    KeyShareExtension,
    NPNExtension,
    PaddingExtension,
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
    boring_padding_style,
)
from .hello import ClientHelloSpec


def _ext(e):
    t = e["type"]
    if t == "sni":
        return SNIExtension()
    if t == "status_request":
        return StatusRequestExtension()
    if t == "supported_groups":
        return SupportedGroupsExtension(e["groups"])
    if t == "supported_points":
        return SupportedPointsExtension(bytes.fromhex(e["points"]))
    if t == "signature_algorithms":
        return SignatureAlgorithmsExtension(e["algorithms"])
    if t == "alpn":
        return ALPNExtension(e["protocols"])
    if t == "sct":
        return SCTExtension()
    if t == "padding":
        if e.get("dynamic"):
            return PaddingExtension(padding_len_func=boring_padding_style)
        return PaddingExtension(pad_len=e["length"])
    if t == "ems":
        return ExtendedMasterSecretExtension()
    if t == "compress_certificate":
        return CompressCertificateExtension(e["algorithms"])
    if t == "record_size_limit":
        return FakeRecordSizeLimitExtension(e["limit"])
    if t == "delegated_credentials":
        return FakeDelegatedCredentialsExtension(e["algorithms"])
    if t == "session_ticket":
        return SessionTicketExtension()
    if t == "supported_versions":
        return SupportedVersionsExtension(e["versions"])
    if t == "psk_modes":
        return PSKKeyExchangeModesExtension(e["modes"])
    if t == "key_share":
        entries = []
        for share in e["shares"]:
            data = b"\x00" if share["len"] == 1 else None
            entries.append(KeyShareEntry(share["group"], data))
        return KeyShareExtension(entries)
    if t == "grease":
        return GREASEExtension()
    if t == "alps":
        return ApplicationSettingsExtension(e["protocols"])
    if t == "alps_new":
        return ApplicationSettingsExtension(e["protocols"], new=True)
    if t == "channel_id":
        return FakeChannelIDExtension(old=e.get("old", False))
    if t == "npn":
        return NPNExtension()
    if t == "renegotiation":
        return RenegotiationInfoExtension()
    raise ValueError(f"unsupported legacy extension {t}")


LEGACY_SPECS = {
    "Chrome-100": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537], 'type': 'signature_algorithms'}, {'type': 'sct'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771]}, {'algorithms': [2], 'type': 'compress_certificate'}, {'protocols': ['h2'], 'type': 'alps'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-102": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537], 'type': 'signature_algorithms'}, {'type': 'sct'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771]}, {'algorithms': [2], 'type': 'compress_certificate'}, {'protocols': ['h2'], 'type': 'alps'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-106": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537], 'type': 'signature_algorithms'}, {'type': 'ems'}, {'type': 'supported_versions', 'versions': [2570, 772, 771]}, {'protocols': ['h2'], 'type': 'alps'}, {'modes': [1], 'type': 'psk_modes'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'type': 'status_request'}, {'type': 'sct'}, {'points': '00', 'type': 'supported_points'}, {'mode': 1, 'type': 'renegotiation'}, {'type': 'session_ticket'}, {'type': 'sni'}, {'algorithms': [2], 'type': 'compress_certificate'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-58": {
        "min_vers": 769,
        "max_vers": 771,
        "cipher_suites": [2570, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'mode': 1, 'type': 'renegotiation'}, {'type': 'sni'}, {'type': 'ems'}, {'type': 'session_ticket'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513], 'type': 'signature_algorithms'}, {'type': 'status_request'}, {'type': 'sct'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'old': False, 'type': 'channel_id'}, {'points': '00', 'type': 'supported_points'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-70": {
        "min_vers": 769,
        "max_vers": 772,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'mode': 1, 'type': 'renegotiation'}, {'type': 'sni'}, {'type': 'ems'}, {'type': 'session_ticket'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513], 'type': 'signature_algorithms'}, {'type': 'status_request'}, {'type': 'sct'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'old': False, 'type': 'channel_id'}, {'points': '00', 'type': 'supported_points'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771, 770, 769]}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'algorithms': [2], 'type': 'compress_certificate'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-72": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 10],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513], 'type': 'signature_algorithms'}, {'type': 'sct'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771, 770, 769]}, {'algorithms': [2], 'type': 'compress_certificate'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-83": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537], 'type': 'signature_algorithms'}, {'type': 'sct'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771, 770, 769]}, {'algorithms': [2], 'type': 'compress_certificate'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-87": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537], 'type': 'signature_algorithms'}, {'type': 'sct'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771, 770, 769]}, {'algorithms': [2], 'type': 'compress_certificate'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Chrome-96": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537], 'type': 'signature_algorithms'}, {'type': 'sct'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771, 770, 769]}, {'algorithms': [2], 'type': 'compress_certificate'}, {'protocols': ['h2'], 'type': 'alps'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Edge-85": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'grease'}, {'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [2570, 29, 23, 24], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537], 'type': 'signature_algorithms'}, {'type': 'sct'}, {'shares': [{'group': 2570, 'len': 1}, {'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [2570, 772, 771, 770, 769]}, {'algorithms': [2], 'type': 'compress_certificate'}, {'type': 'grease'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Firefox-102": {
        "min_vers": 769,
        "max_vers": 772,
        "cipher_suites": [4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [29, 23, 24, 25, 256, 257], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 1283, 1539, 515], 'type': 'delegated_credentials'}, {'shares': [{'group': 29, 'len': 0}, {'group': 23, 'len': 0}], 'type': 'key_share'}, {'type': 'supported_versions', 'versions': [772, 771]}, {'algorithms': [1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513], 'type': 'signature_algorithms'}, {'modes': [1], 'type': 'psk_modes'}, {'limit': 16385, 'type': 'record_size_limit'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Firefox-105": {
        "min_vers": 771,
        "max_vers": 772,
        "cipher_suites": [4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53],
        "compression_methods": [0],
        "extensions": [{'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [29, 23, 24, 25, 256, 257], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 1283, 1539, 515], 'type': 'delegated_credentials'}, {'shares': [{'group': 29, 'len': 0}, {'group': 23, 'len': 0}], 'type': 'key_share'}, {'type': 'supported_versions', 'versions': [772, 771]}, {'algorithms': [1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513], 'type': 'signature_algorithms'}, {'modes': [1], 'type': 'psk_modes'}, {'limit': 16385, 'type': 'record_size_limit'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Firefox-55": {
        "min_vers": 769,
        "max_vers": 771,
        "cipher_suites": [49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 51, 57, 47, 53, 10],
        "compression_methods": [0],
        "extensions": [{'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [29, 23, 24, 25], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513], 'type': 'signature_algorithms'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Firefox-63": {
        "min_vers": 769,
        "max_vers": 772,
        "cipher_suites": [4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 51, 57, 47, 53, 10],
        "compression_methods": [0],
        "extensions": [{'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [29, 23, 24, 25, 256, 257], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'shares': [{'group': 29, 'len': 0}, {'group': 23, 'len': 0}], 'type': 'key_share'}, {'type': 'supported_versions', 'versions': [772, 771, 770, 769]}, {'algorithms': [1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513], 'type': 'signature_algorithms'}, {'modes': [1], 'type': 'psk_modes'}, {'limit': 16385, 'type': 'record_size_limit'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "Firefox-99": {
        "min_vers": 769,
        "max_vers": 772,
        "cipher_suites": [4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53, 10],
        "compression_methods": [0],
        "extensions": [{'type': 'sni'}, {'type': 'ems'}, {'mode': 1, 'type': 'renegotiation'}, {'groups': [29, 23, 24, 25, 256, 257], 'type': 'supported_groups'}, {'points': '00', 'type': 'supported_points'}, {'type': 'session_ticket'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'type': 'status_request'}, {'algorithms': [1027, 1283, 1539, 515], 'type': 'delegated_credentials'}, {'shares': [{'group': 29, 'len': 0}, {'group': 23, 'len': 0}], 'type': 'key_share'}, {'type': 'supported_versions', 'versions': [772, 771, 770, 769]}, {'algorithms': [1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513], 'type': 'signature_algorithms'}, {'modes': [1], 'type': 'psk_modes'}, {'limit': 16385, 'type': 'record_size_limit'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
    "iOS-11.1": {
        "min_vers": 769,
        "max_vers": 771,
        "cipher_suites": [49196, 49195, 49188, 49187, 49162, 49161, 52393, 49200, 49199, 49192, 49191, 49172, 49171, 52392, 157, 156, 61, 60, 53, 47],
        "compression_methods": [0],
        "extensions": [{'mode': 1, 'type': 'renegotiation'}, {'type': 'sni'}, {'type': 'ems'}, {'algorithms': [1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513], 'type': 'signature_algorithms'}, {'type': 'status_request'}, {'type': 'npn'}, {'type': 'sct'}, {'protocols': ['h2', 'h2-16', 'h2-15', 'h2-14', 'spdy/3.1', 'spdy/3', 'http/1.1'], 'type': 'alpn'}, {'points': '00', 'type': 'supported_points'}, {'groups': [29, 23, 24, 25], 'type': 'supported_groups'}],
    },
    "iOS-12.1": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [49196, 49195, 49188, 49187, 49162, 49161, 52393, 49200, 49199, 49192, 49191, 49172, 49171, 52392, 157, 156, 61, 60, 53, 47, 49160, 49170, 10],
        "compression_methods": [0],
        "extensions": [{'mode': 1, 'type': 'renegotiation'}, {'type': 'sni'}, {'type': 'ems'}, {'algorithms': [1027, 2052, 1025, 1283, 515, 2053, 2053, 1281, 2054, 1537, 513], 'type': 'signature_algorithms'}, {'type': 'status_request'}, {'type': 'npn'}, {'type': 'sct'}, {'protocols': ['h2', 'h2-16', 'h2-15', 'h2-14', 'spdy/3.1', 'spdy/3', 'http/1.1'], 'type': 'alpn'}, {'points': '00', 'type': 'supported_points'}, {'groups': [29, 23, 24, 25], 'type': 'supported_groups'}],
    },
    "iOS-13": {
        "min_vers": 0,
        "max_vers": 0,
        "cipher_suites": [4865, 4866, 4867, 49196, 49195, 49188, 49187, 49162, 49161, 52393, 49200, 49199, 49192, 49191, 49172, 49171, 52392, 157, 156, 61, 60, 53, 47, 49160, 49170, 10],
        "compression_methods": [0],
        "extensions": [{'mode': 1, 'type': 'renegotiation'}, {'type': 'sni'}, {'type': 'ems'}, {'algorithms': [1027, 2052, 1025, 1283, 515, 2053, 2053, 1281, 2054, 1537, 513], 'type': 'signature_algorithms'}, {'type': 'status_request'}, {'type': 'sct'}, {'protocols': ['h2', 'http/1.1'], 'type': 'alpn'}, {'points': '00', 'type': 'supported_points'}, {'shares': [{'group': 29, 'len': 0}], 'type': 'key_share'}, {'modes': [1], 'type': 'psk_modes'}, {'type': 'supported_versions', 'versions': [772, 771, 770, 769]}, {'groups': [29, 23, 24, 25], 'type': 'supported_groups'}, {'dynamic': True, 'length': 0, 'type': 'padding'}],
    },
}


def build_legacy_spec(name: str) -> ClientHelloSpec:
    spec = LEGACY_SPECS[name]
    min_vers = spec["min_vers"]
    max_vers = spec["max_vers"]
    if not max_vers:
        for ext in spec["extensions"]:
            if ext.get("type") == "supported_versions":
                versions = [v for v in ext["versions"] if not ((v & 0x0F0F) == 0x0A0A)]
                if versions:
                    min_vers, max_vers = min(versions), max(versions)
                break
    if not min_vers:
        min_vers = 0x0301
    if not max_vers:
        max_vers = 0x0303
    return ClientHelloSpec(
        tls_vers_min=min_vers,
        tls_vers_max=max_vers,
        cipher_suites=list(spec["cipher_suites"]),
        compression_methods=list(spec["compression_methods"]),
        extensions=[_ext(e) for e in spec["extensions"]],
    )
