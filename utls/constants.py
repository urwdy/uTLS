"""Protocol constants shared by the whole package.

The names intentionally follow Go's ``crypto/tls`` / uTLS spelling so that
specs copied from the upstream project can be translated one-to-one.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Versions / content types / handshake types
# ---------------------------------------------------------------------------

VERSION_TLS10 = 0x0301
VERSION_TLS11 = 0x0302
VERSION_TLS12 = 0x0303
VERSION_TLS13 = 0x0304

VERSION_NAMES = {
    VERSION_TLS10: "TLS 1.0",
    VERSION_TLS11: "TLS 1.1",
    VERSION_TLS12: "TLS 1.2",
    VERSION_TLS13: "TLS 1.3",
}

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23
CONTENT_HEARTBEAT = 24

HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_NEW_SESSION_TICKET = 4
HANDSHAKE_END_OF_EARLY_DATA = 5
HANDSHAKE_ENCRYPTED_EXTENSIONS = 8
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_SERVER_KEY_EXCHANGE = 12
HANDSHAKE_CERTIFICATE_REQUEST = 13
HANDSHAKE_SERVER_HELLO_DONE = 14
HANDSHAKE_CERTIFICATE_VERIFY = 15
HANDSHAKE_CLIENT_KEY_EXCHANGE = 16
HANDSHAKE_FINISHED = 20
HANDSHAKE_CERTIFICATE_STATUS = 22
HANDSHAKE_KEY_UPDATE = 24
HANDSHAKE_MESSAGE_HASH = 254

HANDSHAKE_NAMES = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    3: "HelloVerifyRequest",
    4: "NewSessionTicket",
    5: "EndOfEarlyData",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
    22: "CertificateStatus",
    24: "KeyUpdate",
    254: "MessageHash",
}

# ---------------------------------------------------------------------------
# Groups (supported_groups / key_share)
# ---------------------------------------------------------------------------

GREASE_PLACEHOLDER = 0x0A0A

GROUP_SECP256R1 = 0x0017
GROUP_SECP384R1 = 0x0018
GROUP_SECP521R1 = 0x0019
GROUP_X25519 = 0x001D
GROUP_X25519_KYBER768_DRAFT00 = 0x6399
GROUP_X25519_MLKEM768 = 0x11EC

GROUP_NAMES = {
    GROUP_SECP256R1: "secp256r1",
    GROUP_SECP384R1: "secp384r1",
    GROUP_SECP521R1: "secp521r1",
    GROUP_X25519: "x25519",
    GROUP_X25519_KYBER768_DRAFT00: "X25519Kyber768Draft00",
    GROUP_X25519_MLKEM768: "X25519MLKEM768",
}

# Groups this implementation can actually complete a handshake with.
SUPPORTED_GROUPS = frozenset(
    {
        GROUP_SECP256R1,
        GROUP_SECP384R1,
        GROUP_SECP521R1,
        GROUP_X25519,
        GROUP_X25519_MLKEM768,
    }
)

HYBRID_GROUPS = frozenset({GROUP_X25519_MLKEM768, GROUP_X25519_KYBER768_DRAFT00})

# ---------------------------------------------------------------------------
# Signature schemes
# ---------------------------------------------------------------------------

SIG_RSA_PKCS1_SHA1 = 0x0201
SIG_ECDSA_SHA1 = 0x0203
SIG_RSA_PKCS1_SHA256 = 0x0401
SIG_ECDSA_SECP256R1_SHA256 = 0x0403
SIG_RSA_PKCS1_SHA384 = 0x0501
SIG_ECDSA_SECP384R1_SHA384 = 0x0503
SIG_RSA_PKCS1_SHA512 = 0x0601
SIG_ECDSA_SECP521R1_SHA512 = 0x0603
SIG_RSA_PSS_RSAE_SHA256 = 0x0804
SIG_RSA_PSS_RSAE_SHA384 = 0x0805
SIG_RSA_PSS_RSAE_SHA512 = 0x0806
SIG_ED25519 = 0x0807
SIG_ED448 = 0x0808
SIG_RSA_PSS_PSS_SHA256 = 0x0809
SIG_RSA_PSS_PSS_SHA384 = 0x080A
SIG_RSA_PSS_PSS_SHA512 = 0x080B
SIG_MLDSA44 = 0x0904
SIG_MLDSA65 = 0x0905
SIG_MLDSA87 = 0x0906

SIG_NAMES = {
    SIG_RSA_PKCS1_SHA1: "rsa_pkcs1_sha1",
    SIG_ECDSA_SHA1: "ecdsa_sha1",
    SIG_RSA_PKCS1_SHA256: "rsa_pkcs1_sha256",
    SIG_ECDSA_SECP256R1_SHA256: "ecdsa_secp256r1_sha256",
    SIG_RSA_PKCS1_SHA384: "rsa_pkcs1_sha384",
    SIG_ECDSA_SECP384R1_SHA384: "ecdsa_secp384r1_sha384",
    SIG_RSA_PKCS1_SHA512: "rsa_pkcs1_sha512",
    SIG_ECDSA_SECP521R1_SHA512: "ecdsa_secp521r1_sha512",
    SIG_RSA_PSS_RSAE_SHA256: "rsa_pss_rsae_sha256",
    SIG_RSA_PSS_RSAE_SHA384: "rsa_pss_rsae_sha384",
    SIG_RSA_PSS_RSAE_SHA512: "rsa_pss_rsae_sha512",
    SIG_ED25519: "ed25519",
    SIG_ED448: "ed448",
    SIG_RSA_PSS_PSS_SHA256: "rsa_pss_pss_sha256",
    SIG_RSA_PSS_PSS_SHA384: "rsa_pss_pss_sha384",
    SIG_RSA_PSS_PSS_SHA512: "rsa_pss_pss_sha512",
    SIG_MLDSA44: "mldsa44",
    SIG_MLDSA65: "mldsa65",
    SIG_MLDSA87: "mldsa87",
}

SIG_HASH_NAMES = {
    SIG_RSA_PKCS1_SHA1: "sha1",
    SIG_ECDSA_SHA1: "sha1",
    SIG_RSA_PKCS1_SHA256: "sha256",
    SIG_ECDSA_SECP256R1_SHA256: "sha256",
    SIG_RSA_PKCS1_SHA384: "sha384",
    SIG_ECDSA_SECP384R1_SHA384: "sha384",
    SIG_RSA_PKCS1_SHA512: "sha512",
    SIG_ECDSA_SECP521R1_SHA512: "sha512",
    SIG_RSA_PSS_RSAE_SHA256: "sha256",
    SIG_RSA_PSS_RSAE_SHA384: "sha384",
    SIG_RSA_PSS_RSAE_SHA512: "sha512",
    SIG_RSA_PSS_PSS_SHA256: "sha256",
    SIG_RSA_PSS_PSS_SHA384: "sha384",
    SIG_RSA_PSS_PSS_SHA512: "sha512",
}

# Signature schemes we can verify (advertised presets may contain more).
SUPPORTED_SIGNATURE_SCHEMES = frozenset(SIG_HASH_NAMES) | {SIG_ED25519, SIG_ED448}

# ---------------------------------------------------------------------------
# Extension types
# ---------------------------------------------------------------------------

EXT_SERVER_NAME = 0
EXT_MAX_FRAGMENT_LENGTH = 1
EXT_STATUS_REQUEST = 5
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SCT = 18
EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
EXT_PADDING = 21
EXT_ENCRYPT_THEN_MAC = 22
EXT_EXTENDED_MASTER_SECRET = 23
EXT_SESSION_TICKET = 35
EXT_PRE_SHARED_KEY = 41
EXT_EARLY_DATA = 42
EXT_SUPPORTED_VERSIONS = 43
EXT_COOKIE = 44
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_CERTIFICATE_AUTHORITIES = 47
EXT_SIGNATURE_ALGORITHMS_CERT = 50
EXT_KEY_SHARE = 51
EXT_RECORD_SIZE_LIMIT = 28
EXT_DELEGATED_CREDENTIALS = 34
EXT_COMPRESS_CERTIFICATE = 27
EXT_APPLICATION_SETTINGS = 17513
EXT_APPLICATION_SETTINGS_NEW = 17613
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
EXT_TRUST_ANCHORS = 0xCA34
EXT_RENEGOTIATION_INFO = 0xFF01
EXT_CHANNEL_ID = 30032
EXT_CHANNEL_ID_OLD = 30031

# Short aliases used throughout the package (uTLS spelling).
EXT_SNI = EXT_SERVER_NAME
EXT_ALPN = EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION

EXT_NAMES = {
    EXT_SERVER_NAME: "server_name",
    EXT_MAX_FRAGMENT_LENGTH: "max_fragment_length",
    EXT_STATUS_REQUEST: "status_request",
    EXT_SUPPORTED_GROUPS: "supported_groups",
    EXT_EC_POINT_FORMATS: "ec_point_formats",
    EXT_SIGNATURE_ALGORITHMS: "signature_algorithms",
    EXT_SCT: "signed_certificate_timestamp",
    EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION: "application_layer_protocol_negotiation",
    EXT_PADDING: "padding",
    EXT_ENCRYPT_THEN_MAC: "encrypt_then_mac",
    EXT_EXTENDED_MASTER_SECRET: "extended_master_secret",
    EXT_SESSION_TICKET: "session_ticket",
    EXT_PRE_SHARED_KEY: "pre_shared_key",
    EXT_EARLY_DATA: "early_data",
    EXT_SUPPORTED_VERSIONS: "supported_versions",
    EXT_COOKIE: "cookie",
    EXT_PSK_KEY_EXCHANGE_MODES: "psk_key_exchange_modes",
    EXT_CERTIFICATE_AUTHORITIES: "certificate_authorities",
    EXT_SIGNATURE_ALGORITHMS_CERT: "signature_algorithms_cert",
    EXT_KEY_SHARE: "key_share",
    EXT_RECORD_SIZE_LIMIT: "record_size_limit",
    EXT_DELEGATED_CREDENTIALS: "delegated_credentials",
    EXT_COMPRESS_CERTIFICATE: "compress_certificate",
    EXT_APPLICATION_SETTINGS: "application_settings",
    EXT_APPLICATION_SETTINGS_NEW: "application_settings_new",
    EXT_ENCRYPTED_CLIENT_HELLO: "encrypted_client_hello",
    EXT_TRUST_ANCHORS: "trust_anchors",
    EXT_RENEGOTIATION_INFO: "renegotiation_info",
    EXT_CHANNEL_ID: "channel_id",
    EXT_CHANNEL_ID_OLD: "channel_id_old",
}

# Certificate compression algorithms (RFC 8879)
CERT_COMPRESSION_ZLIB = 1
CERT_COMPRESSION_BROTLI = 2
CERT_COMPRESSION_ZSTD = 3

CERT_COMPRESSION_NAMES = {
    CERT_COMPRESSION_ZLIB: "zlib",
    CERT_COMPRESSION_BROTLI: "brotli",
    CERT_COMPRESSION_ZSTD: "zstd",
}

# ALPS extension type used by newer Chrome.
EXT_ALPS = EXT_APPLICATION_SETTINGS_NEW

# ---------------------------------------------------------------------------
# Cipher suites
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CipherSuite:
    """Static description of a TLS cipher suite we can use."""

    id: int
    name: str
    version: int
    kx: str  # "ecdhe", "rsa", or "" for TLS 1.3
    aead: str  # "aes-gcm", "chacha20-poly1305", "aes-cbc"
    hash: str  # PRF hash
    key_len: int
    iv_len: int  # AEAD fixed IV / CBC block size
    mac_len: int = 0  # explicit nonce length (TLS 1.2 AEAD)
    mac_hash: str = ""  # TLS 1.2 CBC HMAC hash
    mac_key_len: int = 0
    block_size: int = 0

    @property
    def is_tls13(self) -> bool:
        return self.version == VERSION_TLS13

    @property
    def prf_hash(self) -> str:
        return self.hash


_CIPHER_DEFS = [
    # TLS 1.3
    CipherSuite(0x1301, "TLS_AES_128_GCM_SHA256", VERSION_TLS13, "", "aes-gcm", "sha256", 16, 12),
    CipherSuite(0x1302, "TLS_AES_256_GCM_SHA384", VERSION_TLS13, "", "aes-gcm", "sha384", 32, 12),
    CipherSuite(0x1303, "TLS_CHACHA20_POLY1305_SHA256", VERSION_TLS13, "", "chacha20-poly1305", "sha256", 32, 12),
    # TLS 1.2 ECDHE + AEAD
    CipherSuite(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", VERSION_TLS12, "ecdhe", "aes-gcm", "sha256", 16, 4, 8),
    CipherSuite(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", VERSION_TLS12, "ecdhe", "aes-gcm", "sha384", 32, 4, 8),
    CipherSuite(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", VERSION_TLS12, "ecdhe", "aes-gcm", "sha256", 16, 4, 8),
    CipherSuite(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", VERSION_TLS12, "ecdhe", "aes-gcm", "sha384", 32, 4, 8),
    CipherSuite(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", VERSION_TLS12, "ecdhe", "chacha20-poly1305", "sha256", 32, 12, 0),
    CipherSuite(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", VERSION_TLS12, "ecdhe", "chacha20-poly1305", "sha256", 32, 12, 0),
    # TLS 1.2 RSA key exchange + AEAD
    CipherSuite(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", VERSION_TLS12, "rsa", "aes-gcm", "sha256", 16, 4, 8),
    CipherSuite(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", VERSION_TLS12, "rsa", "aes-gcm", "sha384", 32, 4, 8),
    # TLS 1.2 ECDHE + CBC
    CipherSuite(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 16, 16, 0, "sha1", 20, 16),
    CipherSuite(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 32, 16, 0, "sha1", 20, 16),
    CipherSuite(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 16, 16, 0, "sha1", 20, 16),
    CipherSuite(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 32, 16, 0, "sha1", 20, 16),
    CipherSuite(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 16, 16, 0, "sha256", 32, 16),
    CipherSuite(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", VERSION_TLS12, "ecdhe", "aes-cbc", "sha384", 32, 16, 0, "sha384", 48, 16),
    CipherSuite(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 16, 16, 0, "sha256", 32, 16),
    CipherSuite(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", VERSION_TLS12, "ecdhe", "aes-cbc", "sha384", 32, 16, 0, "sha384", 48, 16),
    # TLS 1.2 RSA + CBC
    CipherSuite(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", VERSION_TLS12, "rsa", "aes-cbc", "sha256", 16, 16, 0, "sha1", 20, 16),
    CipherSuite(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", VERSION_TLS12, "rsa", "aes-cbc", "sha256", 32, 16, 0, "sha1", 20, 16),
    CipherSuite(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", VERSION_TLS12, "rsa", "aes-cbc", "sha256", 16, 16, 0, "sha256", 32, 16),
    CipherSuite(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", VERSION_TLS12, "rsa", "aes-cbc", "sha256", 32, 16, 0, "sha256", 32, 16),
    # 3DES (legacy, kept for fingerprint compatibility)
    CipherSuite(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", VERSION_TLS12, "rsa", "aes-cbc", "sha256", 24, 8, 0, "sha1", 20, 8),
    CipherSuite(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 24, 8, 0, "sha1", 20, 8),
    CipherSuite(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", VERSION_TLS12, "ecdhe", "aes-cbc", "sha256", 24, 8, 0, "sha1", 20, 8),
]

CIPHER_SUITES: dict[int, CipherSuite] = {cs.id: cs for cs in _CIPHER_DEFS}
CIPHER_SUITES_BY_NAME: dict[str, CipherSuite] = {cs.name: cs for cs in _CIPHER_DEFS}

# Go/uTLS aliases without the "_SHA256"/"_SHA384" suffix.
CIPHER_ALIASES = {
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": 0xCCA9,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305": 0xCCA8,
}

TLS13_CIPHER_SUITES = [
    CIPHER_SUITES[0x1301],
    CIPHER_SUITES[0x1302],
    CIPHER_SUITES[0x1303],
]

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

ALERT_NAMES = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
    121: "ech_required",
}


# ---------------------------------------------------------------------------
# GREASE helpers (BoringSSL semantics)
# ---------------------------------------------------------------------------

_GREASE_INDEX_CIPHER = 0
_GREASE_INDEX_GROUP = 1
_GREASE_INDEX_EXTENSION1 = 2
_GREASE_INDEX_EXTENSION2 = 3
_GREASE_INDEX_VERSION = 4
_GREASE_INDEX_TICKET_EXTENSION = 5
_GREASE_INDEX_ECH_CONFIG_ID = 6
_GREASE_INDEX_SIGNATURE_ALGORITHM = 7
GREASE_SEED_COUNT = 8


def is_grease(value: int) -> bool:
    """0x?a?a values are reserved for GREASE (RFC 8701)."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def grease_value(seed: int) -> int:
    # BoringSSL: value of the form 0x?a?a, where ? is a random nibble.
    v = (seed & 0xF0) | 0x0A
    return v | (v << 8)


def grease_seed_bytes_to_values(raw: bytes) -> list[int]:
    if len(raw) != 2 * GREASE_SEED_COUNT:
        raise ValueError("bad GREASE seed length")
    return [int.from_bytes(raw[2 * i : 2 * i + 2], "little") for i in range(GREASE_SEED_COUNT)]


# Convenience aliases used by preset code
SSL_GREASE_CIPHER = 0
SSL_GREASE_GROUP = 1
SSL_GREASE_EXTENSION1 = 2
SSL_GREASE_EXTENSION2 = 3
SSL_GREASE_VERSION = 4
SSL_GREASE_TICKET_EXTENSION = 5
SSL_GREASE_ECH_CONFIG_ID = 6
SSL_GREASE_SIGNATURE_ALGORITHM = 7
