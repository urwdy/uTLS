"""Built-in ClientHello fingerprints (port of uTLS' ``u_parrots.go``).

Only the presets that can complete a handshake with this implementation are
listed here.  Every spec is a faithful translation of the upstream Go
definition (cipher suite order, extension order, GREASE slots, padding).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .constants import (
    CERT_COMPRESSION_BROTLI,
    CERT_COMPRESSION_ZLIB,
    CERT_COMPRESSION_ZSTD,
    GREASE_PLACEHOLDER,
    GROUP_SECP256R1,
    GROUP_SECP384R1,
    GROUP_SECP521R1,
    GROUP_X25519,
    GROUP_X25519_MLKEM768,
    SIG_ECDSA_SHA1,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SECP521R1_SHA512,
    SIG_MLDSA44,
    SIG_MLDSA65,
    SIG_MLDSA87,
    SIG_RSA_PKCS1_SHA1,
    SIG_RSA_PKCS1_SHA256,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PKCS1_SHA512,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    VERSION_TLS10,
    VERSION_TLS11,
    VERSION_TLS12,
    VERSION_TLS13,
)
from .extensions import (
    ALPNExtension,
    ApplicationSettingsExtension,
    CompressCertificateExtension,
    ExtendedMasterSecretExtension,
    FakeChannelIDExtension,
    FakeDelegatedCredentialsExtension,
    FakeRecordSizeLimitExtension,
    GREASEEcHExtension,
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
    TrustAnchorsExtension,
    boring_padding_style,
)
from .hello import ClientHelloSpec, shuffle_chrome_tls_extensions
from ._legacy_presets import build_legacy_spec

# Cipher suite IDs used by presets but not implemented by the state machine.
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D
TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = 0xCCA9
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 = 0xCCA8
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303

# Legacy / fake values used by 360 and QQ fingerprints.
TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B
TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032
TLS_RSA_WITH_RC4_128_SHA = 0x0005
TLS_RSA_WITH_RC4_128_MD5 = 0x0004
TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007
TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011
SIG_DSA_SHA256 = 0x0402
SIG_DSA_SHA1 = 0x0202


@dataclass(frozen=True)
class ClientHelloID:
    """Identifier of a browser fingerprint, mirroring uTLS ``ClientHelloID``."""

    client: str
    version: str = "0"

    def __str__(self) -> str:
        return f"{self.client}-{self.version}"


# ---------------------------------------------------------------------------
# Chrome
# ---------------------------------------------------------------------------

_CHROME_CIPHERS = [
    GREASE_PLACEHOLDER,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
]

_CHROME_SIGALGS = [
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA512,
]


def _chrome_120_spec() -> ClientHelloSpec:
    exts = shuffle_chrome_tls_extensions(
        [
            GREASEExtension(),
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension([GREASE_PLACEHOLDER, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]),
            SupportedPointsExtension(b"\x00"),
            SessionTicketExtension(),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(_CHROME_SIGALGS),
            SCTExtension(),
            KeyShareExtension([KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"), KeyShareEntry(GROUP_X25519)]),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension([GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12]),
            CompressCertificateExtension([CERT_COMPRESSION_BROTLI]),
            ApplicationSettingsExtension(["h2"]),
            GREASEEcHExtension([(0x0001, 0x0001)], [128, 160, 192, 224]),
            GREASEExtension(),
            PaddingExtension(padding_len_func=boring_padding_style),
        ]
    )
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_CHROME_CIPHERS),
        extensions=exts,
    )


def _chrome_pq_spec(new_alps: bool, padding: bool) -> ClientHelloSpec:
    exts = [
        GREASEExtension(),
        SNIExtension(),
        ExtendedMasterSecretExtension(),
        RenegotiationInfoExtension(),
        SupportedGroupsExtension(
            [GREASE_PLACEHOLDER, GROUP_X25519_MLKEM768, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]
        ),
        SupportedPointsExtension(b"\x00"),
        SessionTicketExtension(),
        ALPNExtension(["h2", "http/1.1"]),
        StatusRequestExtension(),
        SignatureAlgorithmsExtension(_CHROME_SIGALGS),
        SCTExtension(),
        KeyShareExtension(
            [
                KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"),
                KeyShareEntry(GROUP_X25519_MLKEM768),
                KeyShareEntry(GROUP_X25519),
            ]
        ),
        PSKKeyExchangeModesExtension([1]),
        SupportedVersionsExtension([GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12]),
        CompressCertificateExtension([CERT_COMPRESSION_BROTLI]),
        ApplicationSettingsExtension(["h2"], new=new_alps),
        GREASEEcHExtension([(0x0001, 0x0001)], [128, 160, 192, 224]),
        GREASEExtension(),
    ]
    if padding:
        exts.append(PaddingExtension(padding_len_func=boring_padding_style))
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_CHROME_CIPHERS),
        extensions=shuffle_chrome_tls_extensions(exts),
    )


# ---------------------------------------------------------------------------
# Firefox
# ---------------------------------------------------------------------------

_FIREFOX_CIPHERS = [
    TLS_AES_128_GCM_SHA256,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
]

_FIREFOX_SIGALGS = [
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SECP521R1_SHA512,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA256,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PKCS1_SHA512,
    SIG_ECDSA_SHA1,
    SIG_RSA_PKCS1_SHA1,
]


def _firefox_120_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS12,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_FIREFOX_CIPHERS),
        extensions=[
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension([GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1, 256, 257]),
            SupportedPointsExtension(b"\x00"),
            SessionTicketExtension(),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            FakeDelegatedCredentialsExtension(
                [
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_ECDSA_SECP521R1_SHA512,
                    SIG_ECDSA_SHA1,
                ]
            ),
            KeyShareExtension([KeyShareEntry(GROUP_X25519), KeyShareEntry(GROUP_SECP256R1)]),
            SupportedVersionsExtension([VERSION_TLS13, VERSION_TLS12]),
            SignatureAlgorithmsExtension(_FIREFOX_SIGALGS),
            PSKKeyExchangeModesExtension([1]),
            FakeRecordSizeLimitExtension(0x4001),
            GREASEEcHExtension([(0x0001, 0x0001), (0x0001, 0x0003)], [223]),
        ],
    )


def _firefox_148_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS12,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_FIREFOX_CIPHERS),
        extensions=[
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension(
                [
                    GROUP_X25519_MLKEM768,
                    GROUP_X25519,
                    GROUP_SECP256R1,
                    GROUP_SECP384R1,
                    GROUP_SECP521R1,
                    256,
                    257,
                ]
            ),
            SupportedPointsExtension(b"\x00"),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            FakeDelegatedCredentialsExtension(
                [
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_ECDSA_SECP521R1_SHA512,
                    SIG_ECDSA_SHA1,
                ]
            ),
            SCTExtension(),
            KeyShareExtension(
                [
                    KeyShareEntry.hybrid_reuse(GROUP_X25519_MLKEM768),
                    KeyShareEntry.classical_reuse(GROUP_X25519),
                    KeyShareEntry(GROUP_SECP256R1),
                ]
            ),
            SupportedVersionsExtension([VERSION_TLS13, VERSION_TLS12]),
            SignatureAlgorithmsExtension(_FIREFOX_SIGALGS),
            FakeRecordSizeLimitExtension(0x4001),
            CompressCertificateExtension([CERT_COMPRESSION_ZLIB, CERT_COMPRESSION_BROTLI, CERT_COMPRESSION_ZSTD]),
            GREASEEcHExtension([(0x0001, 0x0001), (0x0001, 0x0003)], [223]),
        ],
    )


# ---------------------------------------------------------------------------
# Safari / iOS
# ---------------------------------------------------------------------------

def _safari_ciphers() -> list[int]:
    return [
        GREASE_PLACEHOLDER,
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_RSA_WITH_AES_256_GCM_SHA384,
        TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_256_CBC_SHA,
        TLS_RSA_WITH_AES_128_CBC_SHA,
        FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    ]


_SAFARI_SIGALGS = [
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PKCS1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SHA1,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PKCS1_SHA512,
    SIG_RSA_PKCS1_SHA1,
]


def _safari_16_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=_safari_ciphers(),
        extensions=[
            GREASEExtension(),
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension(
                [GREASE_PLACEHOLDER, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1]
            ),
            SupportedPointsExtension(b"\x00"),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(_SAFARI_SIGALGS),
            SCTExtension(),
            KeyShareExtension([KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"), KeyShareEntry(GROUP_X25519)]),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension(
                [GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12, VERSION_TLS11, VERSION_TLS10]
            ),
            CompressCertificateExtension([CERT_COMPRESSION_ZLIB]),
            GREASEExtension(),
            PaddingExtension(padding_len_func=boring_padding_style),
        ],
    )


def _safari_26_3_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS12,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=[
            GREASE_PLACEHOLDER,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
        extensions=[
            GREASEExtension(),
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension(
                [
                    GREASE_PLACEHOLDER,
                    GROUP_X25519_MLKEM768,
                    GROUP_X25519,
                    GROUP_SECP256R1,
                    GROUP_SECP384R1,
                    GROUP_SECP521R1,
                ]
            ),
            SupportedPointsExtension(b"\x00"),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(
                [
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_RSA_PSS_RSAE_SHA256,
                    SIG_RSA_PKCS1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PKCS1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA512,
                    SIG_RSA_PKCS1_SHA512,
                    SIG_RSA_PKCS1_SHA1,
                ]
            ),
            SCTExtension(),
            KeyShareExtension(
                [
                    KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"),
                    KeyShareEntry(GROUP_X25519_MLKEM768),
                    KeyShareEntry(GROUP_X25519),
                ]
            ),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension([GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12]),
            CompressCertificateExtension([CERT_COMPRESSION_ZLIB]),
            GREASEExtension(),
        ],
    )


def _ios_14_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=[
            GREASE_PLACEHOLDER,
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
            TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
        extensions=[
            GREASEExtension(),
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension(
                [GREASE_PLACEHOLDER, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1]
            ),
            SupportedPointsExtension(b"\x00"),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(_SAFARI_SIGALGS),
            SCTExtension(),
            KeyShareExtension([KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"), KeyShareEntry(GROUP_X25519)]),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension(
                [GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12, VERSION_TLS11, VERSION_TLS10]
            ),
            GREASEExtension(),
            PaddingExtension(padding_len_func=boring_padding_style),
        ],
    )


# ---------------------------------------------------------------------------
# Android / Edge
# ---------------------------------------------------------------------------


def _android_11_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS12,
        cipher_suites=[
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            TLS_RSA_WITH_AES_256_GCM_SHA384,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA,
        ],
        extensions=[
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension([GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]),
            SupportedPointsExtension(b"\x00"),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(
                [
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_RSA_PSS_RSAE_SHA256,
                    SIG_RSA_PKCS1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PKCS1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA512,
                    SIG_RSA_PKCS1_SHA512,
                    SIG_RSA_PKCS1_SHA1,
                ]
            ),
        ],
    )


def _edge_106_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS12,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_CHROME_CIPHERS),
        extensions=[
            GREASEExtension(),
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension(
                [GREASE_PLACEHOLDER, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]
            ),
            SupportedPointsExtension(b"\x00"),
            SessionTicketExtension(),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(_CHROME_SIGALGS),
            SCTExtension(),
            KeyShareExtension([KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"), KeyShareEntry(GROUP_X25519)]),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension([GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12]),
            CompressCertificateExtension([CERT_COMPRESSION_BROTLI]),
            ApplicationSettingsExtension(["h2"]),
            GREASEExtension(),
            PaddingExtension(padding_len_func=boring_padding_style),
        ],
    )


# ---------------------------------------------------------------------------
# Go crypto/tls (a sane default when no fingerprint is needed)
# ---------------------------------------------------------------------------


def _golang_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS12,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=[
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ],
        extensions=[
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            SupportedGroupsExtension([GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]),
            SupportedPointsExtension(b"\x00"),
            SessionTicketExtension(),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(_CHROME_SIGALGS),
            SCTExtension(),
            KeyShareExtension([KeyShareEntry(GROUP_X25519)]),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension([VERSION_TLS13, VERSION_TLS12]),
        ],
    )


# ---------------------------------------------------------------------------
# Chrome 155, 360, QQ
# ---------------------------------------------------------------------------

_CHROME155_TRUST_ANCHORS = [
    bytes.fromhex(x)
    for x in (
        "82df130201",
        "82df130206",
        "82df13020d",
        "82df13020e",
        "82df13020f",
        "82df130212",
        "82df130213",
        "82df130214",
        "839a648c9b2d0107",
        "839a648c9b2d0108",
        "839a648c9b2d0109",
        "839a648c9b2d010a",
        "839a648c9b2d010b",
        "839a648c9b2d010c",
        "839a648c9b2d010d",
        "839a648c9b2d0112",
        "839a648c9b2d0113",
        "d6790901",
        "d6790904",
        "d6790905",
        "d6790906",
        "d6790907",
        "d6790908",
        "d679090a",
        "d679090b",
        "d679090c",
        "d679090d",
        "d679090f",
    )
]


def _chrome_155_spec() -> ClientHelloSpec:
    exts = [
        GREASEExtension(),
        SNIExtension(),
        ExtendedMasterSecretExtension(),
        RenegotiationInfoExtension(),
        SupportedGroupsExtension(
            [GREASE_PLACEHOLDER, GROUP_X25519_MLKEM768, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]
        ),
        SupportedPointsExtension(b"\x00"),
        SessionTicketExtension(),
        ALPNExtension(["h2", "http/1.1"]),
        StatusRequestExtension(),
        SignatureAlgorithmsExtension(
            [
                GREASE_PLACEHOLDER,
                SIG_MLDSA44,
                SIG_MLDSA65,
                SIG_MLDSA87,
                SIG_ECDSA_SECP256R1_SHA256,
                SIG_RSA_PSS_RSAE_SHA256,
                SIG_RSA_PKCS1_SHA256,
                SIG_ECDSA_SECP384R1_SHA384,
                SIG_RSA_PSS_RSAE_SHA384,
                SIG_RSA_PKCS1_SHA384,
                SIG_RSA_PSS_RSAE_SHA512,
                SIG_RSA_PKCS1_SHA512,
            ]
        ),
        SCTExtension(),
        KeyShareExtension(
            [
                KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"),
                KeyShareEntry(GROUP_X25519_MLKEM768),
                KeyShareEntry(GROUP_X25519),
            ]
        ),
        PSKKeyExchangeModesExtension([1]),
        SupportedVersionsExtension([GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12]),
        CompressCertificateExtension([CERT_COMPRESSION_BROTLI]),
        ApplicationSettingsExtension(["h2"], new=True),
        TrustAnchorsExtension(_CHROME155_TRUST_ANCHORS),
        GREASEEcHExtension([(0x0001, 0x0001)], [128, 160, 192, 224]),
        GREASEExtension(),
    ]
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_CHROME_CIPHERS),
        extensions=shuffle_chrome_tls_extensions(exts),
    )


def _qq_11_1_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_CHROME_CIPHERS),
        extensions=[
            GREASEExtension(),
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension([GREASE_PLACEHOLDER, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]),
            SupportedPointsExtension(b"\x00"),
            SessionTicketExtension(),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(
                [
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_RSA_PSS_RSAE_SHA256,
                    SIG_RSA_PKCS1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PKCS1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA512,
                    SIG_RSA_PKCS1_SHA512,
                ]
            ),
            SCTExtension(),
            KeyShareExtension([KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"), KeyShareEntry(GROUP_X25519)]),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension(
                [GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12, VERSION_TLS11, VERSION_TLS10]
            ),
            CompressCertificateExtension([CERT_COMPRESSION_BROTLI]),
            ApplicationSettingsExtension(["h2"]),
            GREASEExtension(),
            PaddingExtension(padding_len_func=boring_padding_style),
        ],
    )


def _360_11_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS13,
        cipher_suites=list(_CHROME_CIPHERS) + [TLS_RSA_WITH_3DES_EDE_CBC_SHA],
        extensions=[
            GREASEExtension(),
            SNIExtension(),
            ExtendedMasterSecretExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension([GREASE_PLACEHOLDER, GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1]),
            SupportedPointsExtension(b"\x00"),
            SessionTicketExtension(),
            ALPNExtension(["h2", "http/1.1"]),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(
                [
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_RSA_PSS_RSAE_SHA256,
                    SIG_RSA_PKCS1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA384,
                    SIG_RSA_PKCS1_SHA384,
                    SIG_RSA_PSS_RSAE_SHA512,
                    SIG_RSA_PKCS1_SHA512,
                    SIG_RSA_PKCS1_SHA1,
                ]
            ),
            SCTExtension(),
            FakeChannelIDExtension(),
            KeyShareExtension([KeyShareEntry(GREASE_PLACEHOLDER, b"\x00"), KeyShareEntry(GROUP_X25519)]),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension(
                [GREASE_PLACEHOLDER, VERSION_TLS13, VERSION_TLS12, VERSION_TLS11, VERSION_TLS10]
            ),
            CompressCertificateExtension([CERT_COMPRESSION_BROTLI]),
            GREASEExtension(),
            PaddingExtension(padding_len_func=boring_padding_style),
        ],
    )


def _360_7_5_spec() -> ClientHelloSpec:
    return ClientHelloSpec(
        tls_vers_min=VERSION_TLS10,
        tls_vers_max=VERSION_TLS12,
        cipher_suites=[
            TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            TLS_RSA_WITH_AES_256_CBC_SHA,
            TLS_RSA_WITH_AES_256_CBC_SHA256,
            TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            TLS_ECDHE_RSA_WITH_RC4_128_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_RC4_128_SHA,
            TLS_RSA_WITH_RC4_128_MD5,
            TLS_RSA_WITH_AES_128_CBC_SHA,
            TLS_RSA_WITH_AES_128_CBC_SHA256,
            TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ],
        extensions=[
            SNIExtension(),
            RenegotiationInfoExtension(),
            SupportedGroupsExtension([GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1]),
            SupportedPointsExtension(b"\x00"),
            SessionTicketExtension(),
            NPNExtension(),
            ALPNExtension(["spdy/2", "spdy/3", "spdy/3.1", "http/1.1"]),
            FakeChannelIDExtension(old=True),
            StatusRequestExtension(),
            SignatureAlgorithmsExtension(
                [
                    SIG_RSA_PKCS1_SHA256,
                    SIG_RSA_PKCS1_SHA384,
                    SIG_RSA_PKCS1_SHA1,
                    SIG_ECDSA_SECP256R1_SHA256,
                    SIG_ECDSA_SECP384R1_SHA384,
                    SIG_ECDSA_SHA1,
                    SIG_DSA_SHA256,
                    SIG_DSA_SHA1,
                ]
            ),
        ],
    )


def _randomized_spec(alpn: bool = True, with_alpn_list: bool = True) -> ClientHelloSpec:
    tls13 = random.random() < 0.85
    ciphers = [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TLS_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_256_GCM_SHA384,
        TLS_RSA_WITH_AES_128_CBC_SHA,
        TLS_RSA_WITH_AES_256_CBC_SHA,
    ]
    tls13_ciphers = ciphers[:3]
    random.shuffle(tls13_ciphers)
    rest = ciphers[3:]
    random.shuffle(rest)
    suites = tls13_ciphers + rest if tls13 else rest
    if tls13:
        suites = suites[: max(4, len(suites) - random.randrange(0, 4))]

    sigalgs = [
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_RSA_PKCS1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PKCS1_SHA384,
        SIG_RSA_PKCS1_SHA1,
        SIG_RSA_PKCS1_SHA512,
    ]
    if random.random() < 0.5:
        sigalgs.append(SIG_ECDSA_SHA1)
    if random.random() < 0.5:
        sigalgs.append(SIG_ECDSA_SECP521R1_SHA512)
    if tls13 or random.random() < 0.5:
        sigalgs += [SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_RSAE_SHA512]
    random.shuffle(sigalgs)

    curves = []
    if tls13 and random.random() < 0.5:
        curves.append(GROUP_X25519_MLKEM768)
    curves.append(GROUP_X25519)
    curves += [GROUP_SECP256R1, GROUP_SECP384R1]
    if random.random() < 0.5:
        curves.append(GROUP_SECP521R1)

    exts = [
        SNIExtension(),
        SessionTicketExtension(),
        SignatureAlgorithmsExtension(sigalgs),
        SupportedPointsExtension(b"\x00"),
        SupportedGroupsExtension(curves),
    ]
    if alpn:
        exts.append(ALPNExtension(["h2", "http/1.1"] if with_alpn_list else []))
    if tls13 or random.random() < 0.5:
        exts.append(PaddingExtension(padding_len_func=boring_padding_style))
    if random.random() < 0.5:
        exts.append(StatusRequestExtension())
    if random.random() < 0.5:
        exts.append(SCTExtension())
    if random.random() < 0.5:
        exts.append(RenegotiationInfoExtension())
    if random.random() < 0.5:
        exts.append(ExtendedMasterSecretExtension())
    if tls13:
        ks = [KeyShareEntry(GROUP_X25519 if GROUP_X25519 in curves else curves[0])]
        if GROUP_SECP256R1 in curves and random.random() < 0.5:
            ks.append(KeyShareEntry(GROUP_SECP256R1))
        if GROUP_X25519_MLKEM768 in curves and random.random() < 0.5:
            ks.insert(0, KeyShareEntry(GROUP_X25519_MLKEM768))
        exts += [
            KeyShareExtension(ks),
            PSKKeyExchangeModesExtension([1]),
            SupportedVersionsExtension([VERSION_TLS13, VERSION_TLS12]),
        ]
        if alpn and random.random() < 0.5:
            exts.append(ApplicationSettingsExtension(["h2"]))
    random.shuffle(exts)
    return ClientHelloSpec(
        tls_vers_min=random.choice([VERSION_TLS10, VERSION_TLS12]) if tls13 else VERSION_TLS10,
        tls_vers_max=VERSION_TLS13 if tls13 else VERSION_TLS12,
        cipher_suites=suites,
        extensions=exts,
    )


# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------

HelloGolang = ClientHelloID("Golang")
HelloCustom = ClientHelloID("Custom")
HelloRandomized = ClientHelloID("Randomized")
HelloRandomizedALPN = ClientHelloID("Randomized-ALPN")
HelloRandomizedNoALPN = ClientHelloID("Randomized-NoALPN")

HelloChrome_120 = ClientHelloID("Chrome", "120")
HelloChrome_131 = ClientHelloID("Chrome", "131")
HelloChrome_133 = ClientHelloID("Chrome", "133")
HelloChrome_155 = ClientHelloID("Chrome", "155")
HelloChrome_Auto = HelloChrome_155

HelloFirefox_120 = ClientHelloID("Firefox", "120")
HelloFirefox_148 = ClientHelloID("Firefox", "148")
HelloFirefox_Auto = HelloFirefox_148

HelloSafari_16_0 = ClientHelloID("Safari", "16.0")
HelloSafari_26_3 = ClientHelloID("Safari", "26.3")
HelloSafari_Auto = HelloSafari_26_3

HelloIOS_14 = ClientHelloID("iOS", "14")
HelloIOS_Auto = HelloIOS_14

HelloAndroid_11_OkHttp = ClientHelloID("Android", "11")
HelloEdge_106 = ClientHelloID("Edge", "106")
HelloEdge_Auto = HelloEdge_106
Hello360_7_5 = ClientHelloID("360Browser", "7.5")
Hello360_11_0 = ClientHelloID("360Browser", "11.0")
Hello360_Auto = Hello360_11_0
HelloQQ_11_1 = ClientHelloID("QQBrowser", "11.1")
HelloQQ_Auto = HelloQQ_11_1

# Legacy presets generated from the upstream Go definitions.
HelloChrome_58 = ClientHelloID("Chrome", "58")
HelloChrome_62 = ClientHelloID("Chrome", "62")
HelloChrome_70 = ClientHelloID("Chrome", "70")
HelloChrome_72 = ClientHelloID("Chrome", "72")
HelloChrome_83 = ClientHelloID("Chrome", "83")
HelloChrome_87 = ClientHelloID("Chrome", "87")
HelloChrome_96 = ClientHelloID("Chrome", "96")
HelloChrome_100 = ClientHelloID("Chrome", "100")
HelloChrome_102 = ClientHelloID("Chrome", "102")
HelloChrome_106_Shuffle = ClientHelloID("Chrome", "106")
HelloFirefox_55 = ClientHelloID("Firefox", "55")
HelloFirefox_56 = ClientHelloID("Firefox", "56")
HelloFirefox_63 = ClientHelloID("Firefox", "63")
HelloFirefox_65 = ClientHelloID("Firefox", "65")
HelloFirefox_99 = ClientHelloID("Firefox", "99")
HelloFirefox_102 = ClientHelloID("Firefox", "102")
HelloFirefox_105 = ClientHelloID("Firefox", "105")
HelloIOS_11_1 = ClientHelloID("iOS", "11.1")
HelloIOS_12_1 = ClientHelloID("iOS", "12.1")
HelloIOS_13 = ClientHelloID("iOS", "13")
HelloEdge_85 = ClientHelloID("Edge", "85")

_LEGACY_IDS = {
    "Chrome-58": HelloChrome_58,
    "Chrome-62": HelloChrome_62,
    "Chrome-70": HelloChrome_70,
    "Chrome-72": HelloChrome_72,
    "Chrome-83": HelloChrome_83,
    "Chrome-87": HelloChrome_87,
    "Chrome-96": HelloChrome_96,
    "Chrome-100": HelloChrome_100,
    "Chrome-102": HelloChrome_102,
    "Chrome-106": HelloChrome_106_Shuffle,
    "Firefox-55": HelloFirefox_55,
    "Firefox-56": HelloFirefox_56,
    "Firefox-63": HelloFirefox_63,
    "Firefox-65": HelloFirefox_65,
    "Firefox-99": HelloFirefox_99,
    "Firefox-102": HelloFirefox_102,
    "Firefox-105": HelloFirefox_105,
    "iOS-11.1": HelloIOS_11_1,
    "iOS-12.1": HelloIOS_12_1,
    "iOS-13": HelloIOS_13,
    "Edge-85": HelloEdge_85,
}

_PRESET_BUILDERS = {
    HelloGolang: _golang_spec,
    HelloChrome_120: _chrome_120_spec,
    HelloChrome_131: lambda: _chrome_pq_spec(new_alps=False, padding=False),
    HelloChrome_133: lambda: _chrome_pq_spec(new_alps=True, padding=False),
    HelloChrome_155: _chrome_155_spec,
    HelloFirefox_120: _firefox_120_spec,
    HelloFirefox_148: _firefox_148_spec,
    HelloSafari_16_0: _safari_16_spec,
    HelloSafari_26_3: _safari_26_3_spec,
    HelloIOS_14: _ios_14_spec,
    HelloAndroid_11_OkHttp: _android_11_spec,
    HelloEdge_106: _edge_106_spec,
    Hello360_7_5: _360_7_5_spec,
    Hello360_11_0: _360_11_spec,
    HelloQQ_11_1: _qq_11_1_spec,
}

for _legacy_name, _legacy_id in _LEGACY_IDS.items():
    _data_name = {
        "Chrome-62": "Chrome-58",
        "Firefox-56": "Firefox-55",
        "Firefox-65": "Firefox-63",
    }.get(_legacy_name, _legacy_name)
    _PRESET_BUILDERS[_legacy_id] = (
        lambda name=_data_name: build_legacy_spec(name)
    )

PRESETS = dict(_PRESET_BUILDERS)
ALIASES = {
    "chrome": HelloChrome_Auto,
    "firefox": HelloFirefox_Auto,
    "safari": HelloSafari_Auto,
    "ios": HelloIOS_Auto,
    "android": HelloAndroid_11_OkHttp,
    "edge": HelloEdge_Auto,
    "360": Hello360_Auto,
    "360browser": Hello360_Auto,
    "qq": HelloQQ_Auto,
    "qqbrowser": HelloQQ_Auto,
    "360_7_5": Hello360_7_5,
    "360_11_0": Hello360_11_0,
    "qq_11_1": HelloQQ_11_1,
    "golang": HelloGolang,
    "go": HelloGolang,
    "randomized": HelloRandomized,
    "random": HelloRandomized,
}

# Accept "Chrome-133", "chrome_133", "chrome133", "HelloChrome_133", ...
_NAME_TO_ID: dict[str, ClientHelloID] = dict(ALIASES)
for _id in list(_PRESET_BUILDERS) + [HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN]:
    _client = _id.client.lower()
    if _id.version not in ("", "0"):
        for _key in (
            str(_id).lower(),
            f"{_client}_{_id.version}",
            f"{_client}{_id.version}",
            f"{_client}-{_id.version}",
            f"{_client}_{_id.version}".replace(".", ""),
            f"{_client}{_id.version}".replace(".", ""),
        ):
            _NAME_TO_ID[_key] = _id
    _NAME_TO_ID.setdefault(str(_id).lower(), _id)
    _NAME_TO_ID.setdefault(_client, _id)


def _normalize_name(value: str) -> str:
    key = value.strip().lower()
    if key.startswith("hello"):
        key = key[5:]
    return key


def resolve_client_hello_id(value: str) -> ClientHelloID:
    """Resolve a preset name such as ``"chrome"`` or ``"chrome-133"``."""
    resolved = _NAME_TO_ID.get(_normalize_name(value))
    if resolved is None:
        raise KeyError(f"unknown ClientHelloID {value!r}")
    return resolved


def utls_id_to_spec(client_hello_id: ClientHelloID | str) -> ClientHelloSpec:
    """Return a fresh spec for ``client_hello_id`` (uTLS ``UTLSIdToSpec``)."""
    if isinstance(client_hello_id, str):
        client_hello_id = resolve_client_hello_id(client_hello_id)
    if client_hello_id in (HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN):
        if client_hello_id == HelloRandomizedNoALPN:
            return _randomized_spec(alpn=False)
        return _randomized_spec(alpn=True)
    try:
        return _PRESET_BUILDERS[client_hello_id]()
    except KeyError:
        raise KeyError(f"unsupported ClientHelloID {client_hello_id}") from None
