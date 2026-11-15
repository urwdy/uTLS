"""TLS client connection with a uTLS-compatible surface."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import Callable
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import messages as msgs
from .constants import (
    ALERT_NAMES,
    CERT_COMPRESSION_BROTLI,
    CERT_COMPRESSION_ZLIB,
    CERT_COMPRESSION_ZSTD,
    CONTENT_ALERT,
    CONTENT_APPLICATION_DATA,
    CONTENT_CHANGE_CIPHER_SPEC,
    CONTENT_HANDSHAKE,
    EXT_ALPN,
    EXT_ENCRYPTED_CLIENT_HELLO,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_PRE_SHARED_KEY,
    GROUP_NAMES,
    HANDSHAKE_CERTIFICATE,
    HANDSHAKE_CERTIFICATE_REQUEST,
    HANDSHAKE_CERTIFICATE_VERIFY,
    HANDSHAKE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_FINISHED,
    HANDSHAKE_KEY_UPDATE,
    HANDSHAKE_NEW_SESSION_TICKET,
    HANDSHAKE_SERVER_HELLO,
    HANDSHAKE_SERVER_HELLO_DONE,
    HANDSHAKE_SERVER_KEY_EXCHANGE,
    VERSION_TLS10,
    VERSION_TLS11,
    VERSION_TLS12,
    VERSION_TLS13,
    VERSION_NAMES,
    is_grease,
)
from .crypto import (
    RecordCipher,
    derive_secret,
    generate_key_share,
    hash_len,
    hkdf_expand_label,
    hkdf_extract,
    tls_prf,
)
from .errors import (
    AlertError,
    ECHRejectedError,
    HandshakeError,
    RecordError,
    UnsupportedFeatureError,
)
from .extensions import (
    ALPNExtension,
    CookieExtension,
    EarlyDataExtension,
    KeyShareEntry,
    KeyShareExtension,
    PreSharedKeyExtension,
    SignatureAlgorithmsExtension,
    SupportedVersionsExtension,
)
from .hello import ClientHelloSpec, build_client_hello, set_tls_versions
from .presets import ClientHelloID, HelloCustom, utls_id_to_spec
from .record import RecordReader, send_record
from .session import ClientSessionCache as _ClientSessionCache, SessionState
from .stream import TLSFile
from .verify import (
    CertificateVerificationError,
    check_crl_revocation,
    crl_distribution_points,
    fetch_url,
    load_crls,
    load_system_roots,
    ocsp_responder_url,
    select_signature_scheme,
    sign,
    sign_legacy,
    verify_certificate_chain,
    verify_signature,
)
from .ocsp import fetch_ocsp_response, verify_ocsp_response

_CLIENT_VERIFY_CONTEXT = b"TLS 1.3, client CertificateVerify"
_SERVER_VERIFY_CONTEXT = b"TLS 1.3, server CertificateVerify"

# Handshake messages are length-prefixed with 24 bits, but unbounded buffering
# is still a memory-exhaustion vector for a malicious peer.
MAX_HANDSHAKE_SIZE = 16 * 1024 * 1024
MAX_CERTIFICATE_SIZE = 16 * 1024 * 1024


@dataclass
class Config:
    """Connection configuration, loosely mirroring ``tls.Config``."""

    server_name: str = ""
    insecure_skip_verify: bool = False
    root_cas: list[bytes] | None = None
    next_protos: list[str] = field(default_factory=list)
    min_version: int = VERSION_TLS10
    max_version: int = VERSION_TLS13
    allow_legacy_ciphers: bool = False
    allow_rsa_key_exchange: bool = False
    client_cert_chain: list[bytes] = field(default_factory=list)
    client_private_key: bytes | None = None
    client_private_key_password: bytes | None = None
    session_ticket: bytes = b""
    verify_hostname: bool = True
    timeout: float | None = 30.0
    session: SessionState | None = None
    session_cache: _ClientSessionCache | None = None
    verify_ocsp_stapling: bool = False
    require_ocsp_stapling: bool = False
    crls: list[bytes] = field(default_factory=list)
    fetch_crls: bool = False
    require_crl: bool = False
    crl_timeout: float = 10.0
    fetch_ocsp: bool = False
    ocsp_timeout: float = 10.0
    ocsp_url: str | None = None
    allow_private_revocation_urls: bool = False
    early_data: bytes | None = None
    ech_config_list: object | None = None
    ech_allow_fallback: bool = False
    keylog_writer: Callable[[str], None] | None = None
    verify_peer_certificate: (
        Callable[[list[x509.Certificate], str], None] | None
    ) = None
    get_client_certificate: (
        Callable[[list[bytes], list[int]], tuple[list[object], object] | None]
        | None
    ) = None
    verify_connection: Callable[["UConn"], None] | None = None
    sct_verifier: (
        Callable[[x509.Certificate, list[bytes]], None] | None
    ) = None
    require_sct: bool = False

    # uTLS/Go spelling aliases ------------------------------------------------
    @property
    def ServerName(self) -> str:  # noqa: N802 - Go compatibility
        return self.server_name

    @ServerName.setter
    def ServerName(self, value: str) -> None:  # noqa: N802
        self.server_name = value

    @property
    def InsecureSkipVerify(self) -> bool:  # noqa: N802
        return self.insecure_skip_verify

    @InsecureSkipVerify.setter
    def InsecureSkipVerify(self, value: bool) -> None:  # noqa: N802
        self.insecure_skip_verify = value

    @property
    def NextProtos(self) -> list[str]:  # noqa: N802
        return self.next_protos

    @NextProtos.setter
    def NextProtos(self, value: list[str]) -> None:  # noqa: N802
        self.next_protos = list(value)

    @property
    def MinVersion(self) -> int:  # noqa: N802
        return self.min_version

    @MinVersion.setter
    def MinVersion(self, value: int) -> None:  # noqa: N802
        self.min_version = value

    @property
    def MaxVersion(self) -> int:  # noqa: N802
        return self.max_version

    @MaxVersion.setter
    def MaxVersion(self, value: int) -> None:  # noqa: N802
        self.max_version = value

    @property
    def RootCAs(self) -> list[bytes] | None:  # noqa: N802
        return self.root_cas

    @RootCAs.setter
    def RootCAs(self, value: list[bytes] | None) -> None:  # noqa: N802
        self.root_cas = value

    @property
    def ClientSessionCache(self):  # noqa: N802
        return self.session_cache

    @ClientSessionCache.setter
    def ClientSessionCache(self, value) -> None:  # noqa: N802
        self.session_cache = value

    @property
    def KeyLogWriter(self):  # noqa: N802
        return self.keylog_writer

    @KeyLogWriter.setter
    def KeyLogWriter(self, value) -> None:  # noqa: N802
        self.keylog_writer = value

    @property
    def VerifyPeerCertificate(self):  # noqa: N802
        return self.verify_peer_certificate

    @VerifyPeerCertificate.setter
    def VerifyPeerCertificate(self, value) -> None:  # noqa: N802
        self.verify_peer_certificate = value

    @property
    def GetClientCertificate(self):  # noqa: N802
        return self.get_client_certificate

    @GetClientCertificate.setter
    def GetClientCertificate(self, value) -> None:  # noqa: N802
        self.get_client_certificate = value

    @property
    def VerifyConnection(self):  # noqa: N802
        return self.verify_connection

    @VerifyConnection.setter
    def VerifyConnection(self, value) -> None:  # noqa: N802
        self.verify_connection = value

    @property
    def EncryptedClientHelloConfigList(self):  # noqa: N802
        return self.ech_config_list

    @EncryptedClientHelloConfigList.setter
    def EncryptedClientHelloConfigList(self, value) -> None:  # noqa: N802
        self.ech_config_list = value

    @classmethod
    def from_go(cls, **kwargs) -> "Config":
        """Construct a Config using Go/uTLS-style field names.

        Dataclass fields use snake_case; this helper maps the common Go
        spellings such as ``ServerName`` and ``RootCAs``.
        """
        aliases = {
            "ServerName": "server_name",
            "InsecureSkipVerify": "insecure_skip_verify",
            "NextProtos": "next_protos",
            "MinVersion": "min_version",
            "MaxVersion": "max_version",
            "RootCAs": "root_cas",
            "ClientSessionCache": "session_cache",
            "KeyLogWriter": "keylog_writer",
            "VerifyPeerCertificate": "verify_peer_certificate",
            "GetClientCertificate": "get_client_certificate",
            "VerifyConnection": "verify_connection",
            "EncryptedClientHelloConfigList": "ech_config_list",
        }
        mapped = {}
        for key, value in kwargs.items():
            mapped[aliases.get(key, key)] = value
        return cls(**mapped)


@dataclass
class ConnectionState:
    version: int = 0
    cipher_suite: str = ""
    cipher_suite_id: int = 0
    server_name: str = ""
    alpn_protocol: str | None = None
    peer_certificates: list[bytes] = field(default_factory=list)
    handshake_complete: bool = False
    did_resume: bool = False
    early_data_accepted: bool = False
    ech_accepted: bool | None = None
    ech_retry_configs: bytes = b""
    ech_public_name: str = ""
    alps_protocols: list[str] = field(default_factory=list)
    sct_count: int = 0
    client_hello: bytes = b""

    @property
    def version_name(self) -> str:
        return VERSION_NAMES.get(self.version, f"0x{self.version:04x}")

    def __str__(self) -> str:
        return (
            f"{self.version_name} {self.cipher_suite} "
            f"alpn={self.alpn_protocol} server={self.server_name}"
        )


class UConn:
    """A TLS client connection with a configurable ClientHello.

    The object exposes a socket-like API (``sendall``/``recv``/``read``) plus the
    uTLS-style helpers ``build_handshake_state``, ``apply_preset`` and
    ``connection_state``.
    """

    def __init__(
        self,
        sock,
        config: Config | None = None,
        client_hello_id: ClientHelloID | str | None = None,
        *,
        spec: ClientHelloSpec | None = None,
    ) -> None:
        self.sock = sock
        self.config = config or Config()
        self.reader = RecordReader(sock)
        self._client_hello_id = client_hello_id or HelloCustom
        self._spec = spec
        self._transcript = bytearray()
        self._hs_buffer = bytearray()
        self._app_buffer = bytearray()
        self._write_cipher: RecordCipher | None = None
        self._read_cipher: RecordCipher | None = None
        self._client_app_secret: bytes | None = None
        self._server_app_secret: bytes | None = None
        self._hash_name: str = "sha256"
        self._suite = None
        self._state = ConnectionState(server_name=self.config.server_name)
        self._client_hello_raw = b""
        self._client_random = b""
        self._server_random = b""
        self._session_id = b""
        self._grease_seed: list[int] | None = None
        self._session_ticket = self.config.session_ticket
        self._resume_session: SessionState | None = None
        self._tls12_resume_state: SessionState | None = None
        self._tls13_resume_state: SessionState | None = None
        self._resumption_master_secret: bytes | None = None
        self._server_session_id = b""
        self._last_session: SessionState | None = None
        self._tls12_resume_mode = False
        self._early_data: bytes | None = None
        self._early_traffic_secret: bytes | None = None
        self._early_write_cipher: RecordCipher | None = None
        self._handshake_done = False
        self._closed = False
        self._peer_certs: list[x509.Certificate] = []
        self._client_auth_requested = False
        self._client_auth_sig_algs: list[int] = []
        self._client_auth_cas: list[bytes] = []
        self._client_auth_context = b""
        self._tls12_master_secret: bytes | None = None
        self._tls12_ems = False
        self._tls12_server_ccs_seen = False
        self._tls12_client_finished: bytes | None = None
        self._peer_cert_der: list[bytes] = []
        self._stapled_ocsp: bytes | None = None
        self._cert_compression_algs: list[int] = []
        self._last_error: Exception | None = None
        self._sock_timeout = self.config.timeout
        self._ech = None
        self._ech_verify_name: str | None = None
        self._ech_hrr_prefix: bytes | None = None
        self._offered_cipher_suites: set[int] = set()
        self._offered_versions: set[int] = set()
        self._offered_sig_algs: set[int] = set()
        self._offered_alpn: list[str] = []
        self._received_close_notify = False

        if self.config.timeout is not None:
            try:
                self.sock.settimeout(self.config.timeout)
            except OSError:
                pass

        if spec is not None:
            self._spec = spec
        elif client_hello_id is not None:
            self.apply_preset(client_hello_id)
        else:
            # Match the common "just give me a working client" case.
            from .presets import HelloGolang

            self.apply_preset(HelloGolang)

        if self.config.session is None and self.config.session_cache is not None:
            self.config.session = self.config.session_cache.get(self.config.server_name)

    # ------------------------------------------------------------------
    # uTLS-style API
    # ------------------------------------------------------------------
    def apply_preset(self, client_hello_id: ClientHelloID | str | ClientHelloSpec) -> None:
        if isinstance(client_hello_id, ClientHelloSpec):
            self._spec = client_hello_id.clone()
            self._client_hello_id = HelloCustom
            return
        if isinstance(client_hello_id, str):
            # Resolve aliases such as "chrome" / "firefox" / "chrome_120".
            from .presets import resolve_client_hello_id

            resolved = resolve_client_hello_id(client_hello_id)
            self._client_hello_id = resolved
            self._spec = utls_id_to_spec(resolved)
            return
        self._client_hello_id = client_hello_id
        self._spec = utls_id_to_spec(client_hello_id)

    @property
    def client_hello_id(self) -> ClientHelloID:
        return self._client_hello_id

    def build_handshake_state(self) -> bytes:
        """Build (but do not send) the ClientHello; returns the handshake bytes."""
        spec = self._spec
        if spec is None:
            spec = utls_id_to_spec(self._client_hello_id)
            self._spec = spec
        spec = spec.clone()
        if self.config.next_protos:
            self._override_alpn(spec, self.config.next_protos)
        min_version = max(spec.tls_vers_min, self.config.min_version)
        max_version = min(spec.tls_vers_max, self.config.max_version)
        if max_version < min_version:
            raise HandshakeError(
                f"no overlap between ClientHello versions ({spec.tls_vers_min:#06x}-"
                f"{spec.tls_vers_max:#06x}) and Config ({self.config.min_version:#06x}-"
                f"{self.config.max_version:#06x})"
            )
        if min_version != spec.tls_vers_min or max_version != spec.tls_vers_max:
            set_tls_versions(spec, min_version, max_version)
        server_name = self.config.server_name

        # Decide whether to attempt resumption with a previously saved session.
        self._tls12_resume_state = None
        self._tls13_resume_state = None
        self._early_data = None
        self._early_traffic_secret = None
        self._early_write_cipher = None
        resume_session_id = None
        session = self.config.session
        if (
            session is not None
            and not session.is_expired()
            and session.version in (VERSION_TLS10, VERSION_TLS11, VERSION_TLS12, VERSION_TLS13)
            and min_version <= session.version <= max_version
            and (not session.server_name or session.server_name == server_name)
            and (not session.alpn or not self.config.next_protos or session.alpn in self.config.next_protos)
        ):
            if session.version < VERSION_TLS13 and session.master_secret:
                self._tls12_resume_state = session
                self._session_ticket = session.ticket
                resume_session_id = session.session_id or None
            elif session.version == VERSION_TLS13 and session.psk:
                from .constants import CIPHER_SUITES

                suite = CIPHER_SUITES.get(session.cipher_suite_id)
                if suite is not None:
                    self._tls13_resume_state = session
                    age = (session.age_millis() + session.ticket_age_add) & 0xFFFFFFFF
                    spec.extensions = [
                        ext
                        for ext in spec.extensions
                        if not isinstance(ext, (PreSharedKeyExtension, EarlyDataExtension))
                    ]
                    if self.config.early_data:
                        if session.max_early_data <= 0:
                            raise HandshakeError("session ticket does not allow early data")
                        if len(self.config.early_data) > session.max_early_data:
                            raise HandshakeError(
                                "early data exceeds the ticket's max_early_data"
                            )
                        self._early_data = bytes(self.config.early_data)
                        spec.extensions.append(EarlyDataExtension())
                    else:
                        self._early_data = None
                    spec.extensions.append(
                        PreSharedKeyExtension(session.psk, session.ticket, age, suite.hash)
                    )
        if self.config.early_data and self._tls13_resume_state is None:
            raise HandshakeError("early data requires a resumable TLS 1.3 session")

        built = self._build_client_hello(
            spec,
            server_name=server_name,
            resume_session_id=resume_session_id,
        )
        self._grease_seed = built.context.grease
        self._spec = spec
        self._client_hello_raw = built.raw
        self._session_id = built.session_id
        self._client_hello_version = built.body[:2]
        self._client_random = built.body[2:34]
        self._key_shares = built.key_shares
        self._cert_compression_algs = built.context.cert_compression_algs
        self._state.client_hello = built.raw

        self._early_traffic_secret = None
        self._early_write_cipher = None
        if self._early_data and self._tls13_resume_state is not None:
            from .constants import CIPHER_SUITES

            session = self._tls13_resume_state
            suite = CIPHER_SUITES[session.cipher_suite_id]
            h = suite.hash
            early_secret = hkdf_extract(h, b"", session.psk)
            early_hello = self._ech.inner_raw if self._ech is not None else built.raw
            transcript_hash = hashlib.new(h, early_hello).digest()
            secret = derive_secret(h, early_secret, "c e traffic", transcript_hash)
            self._early_traffic_secret = secret
            self._log_keylog(
                "CLIENT_EARLY_TRAFFIC_SECRET",
                secret,
                self._ech.inner_random if self._ech is not None else self._client_random,
            )
            self._early_write_cipher = RecordCipher(
                suite,
                hkdf_expand_label(h, secret, "key", b"", suite.key_len),
                hkdf_expand_label(h, secret, "iv", b"", 12),
                version=VERSION_TLS13,
            )
        return built.raw

    def _build_client_hello(
        self,
        spec: ClientHelloSpec,
        *,
        server_name: str,
        resume_session_id: bytes | None,
    ):
        """Build the wire ClientHello, applying ECH when configured."""
        self._ech = None
        self._ech_verify_name = None
        self._ech_hrr_prefix = None
        self._state.ech_accepted = None
        self._state.ech_retry_configs = b""
        self._state.ech_public_name = ""
        self._offered_cipher_suites = set(spec.cipher_suites) or {
            0x1301,
            0x1302,
            0x1303,
        }
        self._offered_versions = set()
        self._offered_sig_algs = set()
        self._offered_alpn = []
        for ext in spec.extensions:
            if isinstance(ext, SupportedVersionsExtension):
                self._offered_versions.update(
                    version for version in ext.versions if not is_grease(version)
                )
            elif isinstance(ext, SignatureAlgorithmsExtension):
                self._offered_sig_algs.update(
                    scheme for scheme in ext.algorithms if not is_grease(scheme)
                )
            elif isinstance(ext, ALPNExtension):
                self._offered_alpn = list(ext.protocols)
        if not self._offered_versions:
            self._offered_versions = set(
                range(spec.tls_vers_min, spec.tls_vers_max + 1)
            )

        if self.config.ech_config_list is None:
            return build_client_hello(
                spec,
                server_name=server_name,
                session_ticket=self._session_ticket,
                session_id=resume_session_id,
                grease_seed=self._grease_seed,
                certificate_compression_algs=self._cert_compression_algs,
            )

        from .ech import build_ech_client_hello, coerce_ech_config_list

        if self.config.min_version > VERSION_TLS13 or self.config.max_version < VERSION_TLS13:
            raise HandshakeError("ECH requires TLS 1.3 to be enabled")
        if self._tls12_resume_state is not None:
            # A TLS 1.2 ticket/session ID cannot be offered inside ECH.
            self._tls12_resume_state = None
            self._session_ticket = b""
            resume_session_id = None

        config_list = coerce_ech_config_list(self.config.ech_config_list)
        ech_config = config_list.select()
        if ech_config is None:
            raise HandshakeError("no compatible ECHConfig for this client")
        self._ech = build_ech_client_hello(
            spec,
            ech_config,
            server_name=server_name,
            session_ticket=self._session_ticket,
            certificate_compression_algs=self._cert_compression_algs,
            grease_seed=self._grease_seed,
        )
        self._state.ech_public_name = ech_config.public_name
        return self._ech.outer_built

    @staticmethod
    def _override_alpn(spec: ClientHelloSpec, protocols: list[str]) -> None:
        from .extensions import ALPNExtension
        from .constants import EXT_ALPN

        for ext in spec.extensions:
            if getattr(ext, "type_id", None) == EXT_ALPN:
                ext.protocols = list(protocols)  # type: ignore[attr-defined]
                return
        spec.extensions.append(ALPNExtension(list(protocols)))

    # uTLS/Go spelling aliases ------------------------------------------------
    def Handshake(self) -> None:  # noqa: N802
        self.handshake()

    def BuildHandshakeState(self) -> bytes:  # noqa: N802
        return self.build_handshake_state()

    def ApplyPreset(self, preset) -> None:  # noqa: N802
        self.apply_preset(preset)

    def ConnectionState(self) -> ConnectionState:  # noqa: N802
        return self.connection_state()

    def Close(self) -> None:  # noqa: N802
        self.close()

    def Read(self, n: int = 65536) -> bytes:  # noqa: N802
        return self.read(n)

    def Write(self, data: bytes) -> int:  # noqa: N802
        return self.write(data)

    @property
    def ServerName(self) -> str:  # noqa: N802
        return self.config.server_name

    def get_client_hello(self) -> bytes:
        return self._client_hello_raw

    def connection_state(self) -> ConnectionState:
        return self._state

    def get_peer_certificates(self) -> list[bytes]:
        return [cert.public_bytes(serialization.Encoding.DER) for cert in self._peer_certs]

    def get_peer_certificate_objects(self) -> list[x509.Certificate]:
        return list(self._peer_certs)

    @property
    def session(self) -> SessionState | None:
        """Latest resumable session issued by the server (if any)."""
        return self._last_session

    def _set_session(self, session: SessionState) -> None:
        self._last_session = session
        if self.config.session_cache is not None:
            self.config.session_cache.put(self.config.server_name, session)

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------
    def _check_negotiation(self, sh: msgs.ServerHello) -> None:
        if self._offered_versions and sh.selected_version not in self._offered_versions:
            raise HandshakeError(
                f"server selected TLS version {sh.selected_version:#06x} that was not offered",
                alert=70,
            )
        if (
            self._offered_cipher_suites
            and sh.cipher_suite not in self._offered_cipher_suites
        ):
            raise HandshakeError(
                f"server selected cipher suite {sh.cipher_suite:#06x} that was not offered",
                alert=47,
            )
        if VERSION_TLS13 in self._offered_versions and sh.selected_version < VERSION_TLS13:
            if sh.random[-8:] in (b"DOWNGRD\x01", b"DOWNGRD\x00"):
                raise HandshakeError(
                    "TLS downgrade sentinel detected in ServerHello.random",
                    alert=47,
                )

    def _check_signature_scheme(self, scheme: int) -> None:
        if self._offered_sig_algs and scheme not in self._offered_sig_algs:
            raise HandshakeError(
                f"server selected signature scheme {scheme:#06x} that was not offered",
                alert=47,
            )

    def _check_alpn(self, protocol: str | None) -> None:
        if protocol is not None and protocol not in self._offered_alpn:
            raise HandshakeError(
                f"server selected ALPN protocol {protocol!r} that was not offered",
                alert=47,
            )

    def handshake(self) -> None:
        if self._handshake_done:
            return
        if self._client_hello_raw:
            # BuildHandshakeState() was called first: reuse the exact bytes
            # (including random and key shares) instead of rebuilding.
            ch = self._client_hello_raw
        else:
            ch = self.build_handshake_state()
        self._add_transcript(self._ech.inner_raw if self._ech is not None else ch)
        send_record(self.sock, CONTENT_HANDSHAKE, VERSION_TLS10, ch)
        if self._early_write_cipher is not None and self._early_data:
            # TLS 1.3 middlebox compatibility: send a dummy CCS before 0-RTT.
            send_record(self.sock, CONTENT_CHANGE_CIPHER_SPEC, VERSION_TLS12, b"\x01")
            # 0-RTT application data is sent immediately after ClientHello.
            for i in range(0, len(self._early_data), 16384):
                sealed = self._early_write_cipher.seal_tls13(
                    self._early_data[i : i + 16384], CONTENT_APPLICATION_DATA
                )
                send_record(self.sock, CONTENT_APPLICATION_DATA, VERSION_TLS12, sealed)

        # We may receive HelloRetryRequest, in which case the whole ServerHello
        # negotiation restarts with a second ClientHello.
        while True:
            msg_type, body, raw = self._read_handshake_plain()
            if msg_type != HANDSHAKE_SERVER_HELLO:
                raise HandshakeError(
                    f"expected ServerHello, got {msgs.describe_handshake_type(msg_type)}",
                    alert=10,
                )
            self._add_transcript(raw)
            sh = msgs.parse_server_hello(body, raw)
            self._check_negotiation(sh)
            if self._ech is not None:
                if self._is_hrr(sh):
                    self._handle_ech_hrr(sh)
                    continue
                if sh.selected_version < VERSION_TLS13:
                    raise HandshakeError(
                        "server rejected ECH by negotiating an earlier TLS version",
                        alert=70,
                    )
                prefix = self._ech_hrr_prefix or b""
                if self._ech.accepts(sh, prefix):
                    # The transcript is the inner handshake, while the wire
                    # bytes remain the outer ClientHello.
                    self._transcript = bytearray(prefix + self._ech.inner_raw + raw)
                    self._key_shares = self._ech.inner_built.key_shares
                    self._client_random = self._ech.inner_random
                    self._ech_verify_name = None
                    self._state.ech_accepted = True
                else:
                    if self._ech_hrr_prefix is not None:
                        raise HandshakeError(
                            "server did not confirm ECH acceptance after HelloRetryRequest",
                            alert=47,
                        )
                    if sh.pre_shared_key_selected:
                        raise HandshakeError(
                            "server resumed the outer ECH handshake", alert=47
                        )
                    self._transcript = bytearray(ch + raw)
                    self._key_shares = self._ech.outer_built.key_shares
                    self._client_random = self._ech.outer_random
                    self._ech_verify_name = self._ech.config.public_name
                    self._state.ech_accepted = False
            if sh.selected_version == VERSION_TLS13:
                if self._is_hrr(sh):
                    self._handle_hrr(sh)
                    continue
                self._server_random = sh.random
                self._state.server_name = self.config.server_name
                self._handshake_tls13(sh)
                if self._state.ech_accepted is False and not self.config.ech_allow_fallback:
                    try:
                        self._send_encrypted(
                            CONTENT_ALERT, msgs.alert(2, 121)  # ech_required
                        )
                    except Exception:
                        pass
                    raise ECHRejectedError(self._state.ech_retry_configs)
                return
            self._server_random = sh.random
            self._handshake_tls12(sh)
            return

    def _is_hrr(self, sh: msgs.ServerHello) -> bool:
        return sh.random == bytes.fromhex(
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
        )

    def _handle_hrr(self, sh: msgs.ServerHello) -> None:
        from .constants import CIPHER_SUITES as SUITES

        suite = SUITES.get(sh.cipher_suite)
        if suite is not None and suite.is_tls13:
            # message_hash() and the second ClientHello use the hash of the
            # cipher suite selected in the HelloRetryRequest.
            self._hash_name = suite.hash
        selected_group = sh.key_share_group
        if selected_group not in GROUP_NAMES:
            raise HandshakeError("HRR selected an unsupported group", alert=47)
        # RFC 8446 4.1.2: CH2 replaces the key share with the selected group
        # and echoes the cookie. The transcript becomes message_hash(CH1)||HRR.
        ch1 = self._client_hello_raw
        digest = hashlib.new(self._hash_name, ch1).digest()
        self._transcript = bytearray(
            bytes([254]) + len(digest).to_bytes(3, "big") + digest + sh.raw
        )

        spec = self._spec.clone()
        for ext in spec.extensions:
            if isinstance(ext, KeyShareExtension):
                ext.key_shares = [KeyShareEntry(selected_group)]
        # Resumption binders must be recomputed for ClientHello2; OpenSSL is
        # strict about this and the ticket is bound to the original group, so
        # fall back to a full handshake after a HelloRetryRequest.
        if self._tls13_resume_state is not None:
            spec.extensions = [
                ext
                for ext in spec.extensions
                if not isinstance(ext, (PreSharedKeyExtension, EarlyDataExtension))
            ]
            self._tls13_resume_state = None
            self._early_write_cipher = None
            self._early_traffic_secret = None
            self._early_data = None
        if sh.cookie:
            # cookie must come after key_share per RFC 8446 4.2.2 ordering
            # advice (and before pre_shared_key); uTLS appends it.
            cookie = CookieExtension(sh.cookie)
            idx = len(spec.extensions)
            for i, ext in enumerate(spec.extensions):
                if getattr(ext, "type_id", None) == EXT_PRE_SHARED_KEY:
                    idx = i
                    break
            spec.extensions.insert(idx, cookie)

        built = build_client_hello(
            spec,
            server_name=self.config.server_name,
            session_ticket=self._session_ticket,
            random_bytes=self._client_random,
            session_id=self._session_id,
            grease_seed=self._grease_seed,
        )
        self._spec = spec
        self._client_hello_raw = built.raw
        self._key_shares = built.key_shares
        self._add_transcript(built.raw)
        send_record(self.sock, CONTENT_HANDSHAKE, VERSION_TLS10, built.raw)
        self._state.client_hello = built.raw

    def _handle_ech_hrr(self, sh: msgs.ServerHello) -> None:
        from .constants import CIPHER_SUITES as SUITES
        from .ech import build_ech_hrr_client_hello, hrr_accept_confirmation

        if self._ech_hrr_prefix is not None:
            raise HandshakeError("multiple HelloRetryRequest messages", alert=47)
        suite = SUITES.get(sh.cipher_suite)
        if suite is None or not suite.is_tls13:
            raise HandshakeError(
                "HelloRetryRequest selected an unsupported TLS 1.3 cipher suite",
                alert=40,
            )
        self._hash_name = suite.hash
        confirmation = sh.get_extension(EXT_ENCRYPTED_CLIENT_HELLO)
        if confirmation is None:
            self._handle_ech_hrr_rejected(sh)
            return
        if len(confirmation) != 8:
            raise HandshakeError("invalid ECH HelloRetryRequest confirmation", alert=50)

        assert self._ech is not None
        expected = hrr_accept_confirmation(
            self._ech.inner_raw, sh.raw, suite.hash, self._ech.inner_random
        )
        if not hmac.compare_digest(expected, confirmation):
            self._handle_ech_hrr_rejected(sh)
            return

        digest = hashlib.new(suite.hash, self._ech.inner_raw).digest()
        prefix = bytes([254]) + len(digest).to_bytes(3, "big") + digest + sh.raw
        second = build_ech_hrr_client_hello(self._ech, sh)
        self._ech = second
        self._ech_hrr_prefix = prefix
        self._transcript = bytearray(prefix + second.inner_raw)
        self._client_hello_raw = second.outer_raw
        self._key_shares = second.inner_built.key_shares
        self._session_id = second.session_id
        self._client_random = second.inner_random
        self._state.client_hello = second.outer_raw
        send_record(self.sock, CONTENT_HANDSHAKE, VERSION_TLS10, second.outer_raw)

    def _handle_ech_hrr_rejected(self, sh: msgs.ServerHello) -> None:
        """Continue the HRR handshake against the public name (outer)."""
        assert self._ech is not None
        public_name = self._ech.config.public_name
        self._state.ech_accepted = False
        self._ech_verify_name = public_name
        outer1 = self._client_hello_raw
        digest = hashlib.new(self._hash_name, outer1).digest()
        prefix = bytes([254]) + len(digest).to_bytes(3, "big") + digest + sh.raw

        spec = self._spec.clone()
        spec.extensions = [
            ext
            for ext in spec.extensions
            if getattr(ext, "type_id", None)
            not in (
                EXT_ENCRYPTED_CLIENT_HELLO,
                EXT_PRE_SHARED_KEY,
                42,  # early_data
                44,  # cookie
            )
        ]
        saw_key_share = False
        for ext in spec.extensions:
            if isinstance(ext, KeyShareExtension):
                ext.key_shares = [KeyShareEntry(sh.key_share_group)]
                saw_key_share = True
        if not saw_key_share:
            spec.extensions.append(
                KeyShareExtension([KeyShareEntry(sh.key_share_group)])
            )
        if sh.cookie:
            spec.extensions.append(CookieExtension(sh.cookie))

        built = build_client_hello(
            spec,
            server_name=public_name,
            session_ticket=self._session_ticket,
            random_bytes=self._client_random,
            session_id=self._session_id,
            grease_seed=self._grease_seed,
            certificate_compression_algs=self._cert_compression_algs,
        )
        self._ech = None
        self._ech_hrr_prefix = None
        self._spec = spec
        self._client_hello_raw = built.raw
        self._key_shares = built.key_shares
        self._session_id = built.session_id
        self._transcript = bytearray(prefix)
        self._add_transcript(built.raw)
        send_record(self.sock, CONTENT_HANDSHAKE, VERSION_TLS10, built.raw)
        self._state.client_hello = built.raw

    def _handshake_tls13(self, sh: msgs.ServerHello) -> None:
        from .constants import CIPHER_SUITES as SUITES

        suite = SUITES.get(sh.cipher_suite)
        if suite is None or not suite.is_tls13:
            raise HandshakeError(
                f"server selected unsupported TLS 1.3 cipher suite {sh.cipher_suite:#06x}", alert=40
            )
        if sh.compression_method != 0:
            raise HandshakeError("server selected unsupported compression", alert=40)
        self._suite = suite
        self._hash_name = suite.hash
        self._state.version = VERSION_TLS13
        self._state.cipher_suite = suite.name
        self._state.cipher_suite_id = suite.id

        group = sh.key_share_group
        resumed = bool(sh.pre_shared_key_selected)
        resume_state = self._tls13_resume_state
        if resumed:
            if resume_state is None or not resume_state.psk:
                raise HandshakeError("server selected an unknown PSK identity", alert=115)
            if resume_state.cipher_suite_id != sh.cipher_suite:
                selected = SUITES.get(resume_state.cipher_suite_id)
                if selected is None or selected.hash != suite.hash:
                    raise HandshakeError("server selected a PSK with an incompatible cipher suite", alert=47)
            if group == 0:
                raise UnsupportedFeatureError("pure PSK key exchange is not supported")
        else:
            # The server ignored our ticket; continue as a full handshake.
            self._tls13_resume_state = None

        ks = self._key_shares.get(group)
        if ks is None:
            raise HandshakeError(
                f"server selected key share for unsupported group {group:#06x}", alert=47
            )
        shared = ks.decapsulate(sh.key_share, VERSION_TLS13)

        h = self._hash_name
        zeros = b"\x00" * hash_len(h)
        psk = resume_state.psk if resumed else None
        early = hkdf_extract(h, b"", psk if psk is not None else zeros)
        derived = derive_secret(h, early, "derived", hashlib.new(h, b"").digest())
        handshake_secret = hkdf_extract(h, derived, shared)
        th = self._transcript_hash()
        client_hs = derive_secret(h, handshake_secret, "c hs traffic", th)
        server_hs = derive_secret(h, handshake_secret, "s hs traffic", th)
        self._client_hs_secret = client_hs
        self._server_hs_secret = server_hs
        self._log_keylog("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_hs)
        self._log_keylog("SERVER_HANDSHAKE_TRAFFIC_SECRET", server_hs)
        self._client_finished_key = hkdf_expand_label(h, client_hs, "finished", b"", hash_len(h))
        server_finished_key = hkdf_expand_label(h, server_hs, "finished", b"", hash_len(h))

        self._write_cipher = RecordCipher(
            suite,
            hkdf_expand_label(h, client_hs, "key", b"", suite.key_len),
            hkdf_expand_label(h, client_hs, "iv", b"", 12),
            version=VERSION_TLS13,
        )
        self._read_cipher = RecordCipher(
            suite,
            hkdf_expand_label(h, server_hs, "key", b"", suite.key_len),
            hkdf_expand_label(h, server_hs, "iv", b"", 12),
            version=VERSION_TLS13,
        )

        saw_certificate = False
        saw_server_finished = False
        cert_chain: list[x509.Certificate] = []
        while not saw_server_finished:
            msg_type, body, raw = self._read_handshake_encrypted()
            if msg_type == HANDSHAKE_ENCRYPTED_EXTENSIONS:
                ee = msgs.parse_encrypted_extensions(body, raw)
                self._check_alpn(ee.alpn_protocol)
                self._state.alpn_protocol = ee.alpn_protocol
                self._state.alps_protocols = list(ee.alps_protocols)
                if ee.ech_retry_configs:
                    self._state.ech_retry_configs = ee.ech_retry_configs
                if resumed and ee.early_data_accepted:
                    self._state.early_data_accepted = True
                self._add_transcript(raw)
            elif msg_type == HANDSHAKE_CERTIFICATE_REQUEST:
                cr = msgs.parse_certificate_request(body, tls13=True, raw=raw)
                self._client_auth_requested = True
                self._client_auth_sig_algs = cr.signature_algorithms
                self._client_auth_cas = cr.certificate_authorities
                self._client_auth_context = cr.request_context
                self._add_transcript(raw)
            elif msg_type == HANDSHAKE_CERTIFICATE:
                cert_chain = self._parse_certificate_message(body, raw, tls13=True)
                saw_certificate = True
            elif msg_type == 25:  # CompressedCertificate
                cert_chain = self._parse_compressed_certificate(body, raw)
                saw_certificate = True
            elif msg_type == HANDSHAKE_CERTIFICATE_VERIFY:
                cv = msgs.parse_certificate_verify(body, raw)
                if not saw_certificate or not cert_chain:
                    raise HandshakeError("CertificateVerify without Certificate", alert=10)
                signed = (
                    b" " * 64
                    + _SERVER_VERIFY_CONTEXT
                    + b"\x00"
                    + self._transcript_hash()
                )
                self._check_signature_scheme(cv.signature_scheme)
                try:
                    verify_signature(
                        cert_chain[0].public_key(),
                        cv.signature_scheme,
                        cv.signature,
                        signed,
                    )
                except CertificateVerificationError as exc:
                    raise HandshakeError(str(exc), alert=51) from exc
                self._add_transcript(raw)
            elif msg_type == HANDSHAKE_FINISHED:
                expected = hmac.new(
                    server_finished_key, self._transcript_hash(), self._hash_name
                ).digest()
                if not hmac.compare_digest(expected, body):
                    raise HandshakeError("server Finished verification failed", alert=51)
                self._add_transcript(raw)
                saw_server_finished = True
            else:
                raise HandshakeError(
                    f"unexpected {msgs.describe_handshake_type(msg_type)} in TLS 1.3 handshake",
                    alert=10,
                )

        self._peer_certs = cert_chain
        self._state.peer_certificates = self.get_peer_certificates()
        if resumed:
            if cert_chain:
                raise HandshakeError("server sent a certificate during PSK resumption", alert=10)
        else:
            if not cert_chain:
                raise HandshakeError("server did not send a certificate", alert=42)
            verified_chain = cert_chain
            if not self.config.insecure_skip_verify:
                roots = self._load_roots()
                try:
                    verified_chain = verify_certificate_chain(
                        cert_chain,
                        self._ech_verify_name or self.config.server_name,
                        roots,
                        check_hostname_enabled=self.config.verify_hostname,
                    )
                except CertificateVerificationError as exc:
                    raise HandshakeError(str(exc), alert=42) from exc
            self._check_revocation(verified_chain)
            self._run_verify_callback(
                verified_chain, self._ech_verify_name or self.config.server_name
            )
            self._check_sct(verified_chain[0])

        # Application traffic secrets are derived from the transcript through
        # the server's Finished message.
        th = self._transcript_hash()
        master = hkdf_extract(
            h, derive_secret(h, handshake_secret, "derived", hashlib.new(h, b"").digest()), b"\x00" * hash_len(h)
        )
        self._client_app_secret = derive_secret(h, master, "c ap traffic", th)
        self._server_app_secret = derive_secret(h, master, "s ap traffic", th)
        self._log_keylog("CLIENT_TRAFFIC_SECRET_0", self._client_app_secret)
        self._log_keylog("SERVER_TRAFFIC_SECRET_0", self._server_app_secret)

        # Client authentication (optional).
        if self._state.early_data_accepted:
            eoed = msgs.end_of_early_data()
            self._add_transcript(eoed)
            # EndOfEarlyData continues the early-data record sequence and is
            # protected with the early traffic keys (as OpenSSL does).
            assert self._early_write_cipher is not None
            sealed = self._early_write_cipher.seal_tls13(eoed, CONTENT_HANDSHAKE)
            send_record(self.sock, CONTENT_APPLICATION_DATA, VERSION_TLS12, sealed)
        if self._client_auth_requested:
            self._send_client_certificate_tls13()
        verify_data = hmac.new(self._client_finished_key, self._transcript_hash(), self._hash_name).digest()
        finished = msgs.finished(verify_data)
        self._add_transcript(finished)
        self._send_encrypted(CONTENT_HANDSHAKE, finished)
        self._tls12_client_finished = verify_data

        self._install_app_keys()
        self._resumption_master_secret = derive_secret(
            h, master, "res master", self._transcript_hash()
        )
        self._state.handshake_complete = True
        self._state.did_resume = resumed
        try:
            self._run_verify_connection()
        except Exception:
            self._state.handshake_complete = False
            raise
        self._handshake_done = True

    def _install_app_keys(self) -> None:
        suite = self._suite
        h = self._hash_name
        assert suite is not None and self._client_app_secret is not None
        self._write_cipher = RecordCipher(
            suite,
            hkdf_expand_label(h, self._client_app_secret, "key", b"", suite.key_len),
            hkdf_expand_label(h, self._client_app_secret, "iv", b"", 12),
            version=VERSION_TLS13,
        )
        self._read_cipher = RecordCipher(
            suite,
            hkdf_expand_label(h, self._server_app_secret, "key", b"", suite.key_len),
            hkdf_expand_label(h, self._server_app_secret, "iv", b"", 12),
            version=VERSION_TLS13,
        )

    def _send_client_certificate_tls13(self) -> None:
        chain, key = self._client_credentials(
            self._client_auth_cas, self._client_auth_sig_algs
        )
        cert_msg = msgs.certificate(chain, tls13=True, context=self._client_auth_context)
        self._add_transcript(cert_msg)
        self._send_encrypted(CONTENT_HANDSHAKE, cert_msg)
        if key is None:
            return

        scheme = select_signature_scheme(self._client_auth_sig_algs, key)
        signed = (
            b" " * 64 + _CLIENT_VERIFY_CONTEXT + b"\x00" + self._transcript_hash()
        )
        sig = sign(key, scheme, signed)
        cv = msgs.certificate_verify(scheme, sig)
        self._add_transcript(cv)
        self._send_encrypted(CONTENT_HANDSHAKE, cv)

    def _handshake_tls12(self, sh: msgs.ServerHello) -> None:
        from .constants import CIPHER_SUITES as SUITES

        if sh.selected_version < VERSION_TLS10:
            raise HandshakeError(
                f"server selected {VERSION_NAMES.get(sh.selected_version, hex(sh.selected_version))}; "
                "only TLS 1.0-1.3 are supported",
                alert=70,
            )
        suite = SUITES.get(sh.cipher_suite)
        if suite is None or suite.is_tls13:
            raise HandshakeError(
                f"server selected unsupported TLS 1.2 cipher suite {sh.cipher_suite:#06x}", alert=40
            )
        if sh.selected_version < VERSION_TLS12 and suite.aead != "aes-cbc":
            raise UnsupportedFeatureError(
                f"{suite.name} is not valid before TLS 1.2"
            )
        if suite.aead == "aes-cbc" and not self.config.allow_legacy_ciphers:
            raise HandshakeError(
                f"server selected legacy CBC cipher suite {suite.name}; "
                "set Config.allow_legacy_ciphers=True to permit it",
                alert=40,
            )
        if suite.kx == "rsa" and not self.config.allow_rsa_key_exchange:
            raise HandshakeError(
                f"server selected static RSA key exchange {suite.name}; "
                "set Config.allow_rsa_key_exchange=True to permit it",
                alert=40,
            )
        if suite.kx not in ("ecdhe", "rsa"):
            raise UnsupportedFeatureError(
                f"cipher suite {suite.name} uses unsupported key exchange {suite.kx!r}"
            )
        if sh.compression_method != 0:
            raise HandshakeError("server selected unsupported compression", alert=40)
        self._suite = suite
        self._hash_name = suite.hash
        self._state.version = sh.selected_version
        self._state.cipher_suite = suite.name
        self._state.cipher_suite_id = suite.id
        self._tls12_ems = EXT_EXTENDED_MASTER_SECRET in [ext.type for ext in sh.extensions]
        for ext in sh.extensions:
            if ext.type == EXT_ALPN:
                ar = msgs.Reader(ext.data)
                proto_list = msgs.Reader(ar.vec16())
                if len(proto_list):
                    self._state.alpn_protocol = proto_list.vec8().decode("latin-1")
        self._check_alpn(self._state.alpn_protocol)

        cert_chain: list[x509.Certificate] = []
        ske: msgs.ServerKeyExchange | None = None
        cr: msgs.CertificateRequest | None = None
        self._server_session_id = sh.session_id
        resume_state = self._tls12_resume_state
        if resume_state is not None and resume_state.cipher_suite_id != suite.id:
            resume_state = None
        self._tls12_resume_mode = False

        while True:
            message = None
            if self._hs_buffer:
                try:
                    message = self._next_buffered_handshake()
                except ValueError:
                    message = None
            if message is None:
                ctype, payload = self._read_decrypted_record()
                if ctype == CONTENT_CHANGE_CIPHER_SPEC:
                    if resume_state is None or resume_state.master_secret is None:
                        raise HandshakeError(
                            "server resumed a session that is not available", alert=10
                        )
                    if bool(resume_state.ems) != bool(self._tls12_ems):
                        raise HandshakeError(
                            "resumed session uses a different Extended Master Secret setting",
                            alert=40,
                        )
                    self._install_tls12_keys(suite, resume_state.master_secret)
                    self._tls12_master_secret = resume_state.master_secret
                    self._tls12_resume_mode = True
                    continue
                if ctype == CONTENT_ALERT:
                    self._handle_alert(payload)
                    continue
                if ctype != CONTENT_HANDSHAKE:
                    raise HandshakeError(
                        f"unexpected record type {ctype} in TLS 1.2 handshake", alert=10
                    )
                self._hs_buffer += payload
                continue

            msg_type, body, raw = message
            if msg_type == HANDSHAKE_NEW_SESSION_TICKET:
                self._add_transcript(raw)
                self._note_tls12_ticket(body)
                continue
            if self._tls12_resume_mode:
                if msg_type != HANDSHAKE_FINISHED:
                    raise HandshakeError(
                        f"unexpected {msgs.describe_handshake_type(msg_type)} during resumption",
                        alert=10,
                    )
                assert resume_state is not None and resume_state.master_secret is not None
                master = resume_state.master_secret
                self._log_keylog("CLIENT_RANDOM", master)
                expected = self._prf(
                    master, b"server finished", self._finished_hash(), 12
                )
                if not hmac.compare_digest(expected, body):
                    raise HandshakeError("server Finished verification failed", alert=51)
                self._add_transcript(raw)
                send_record(self.sock, CONTENT_CHANGE_CIPHER_SPEC, self._state.version, b"\x01")
                verify_data = self._prf(
                    master, b"client finished", self._finished_hash(), 12
                )
                finished = msgs.finished(verify_data)
                self._add_transcript(finished)
                self._send_encrypted(CONTENT_HANDSHAKE, finished)
                self._tls12_client_finished = verify_data
                self._set_session(resume_state)
                self._state.handshake_complete = True
                self._state.did_resume = True
                try:
                    self._run_verify_connection()
                except Exception:
                    self._state.handshake_complete = False
                    raise
                self._handshake_done = True
                return

            if msg_type == HANDSHAKE_CERTIFICATE:
                cert_chain = self._parse_certificate_message(body, raw, tls13=False)
            elif msg_type == 25:
                cert_chain = self._parse_compressed_certificate(body, raw)
            elif msg_type == HANDSHAKE_SERVER_KEY_EXCHANGE:
                ske = msgs.parse_server_key_exchange(
                    body, raw, tls12=sh.selected_version >= VERSION_TLS12
                )
                self._add_transcript(raw)
            elif msg_type == HANDSHAKE_CERTIFICATE_REQUEST:
                cr = msgs.parse_certificate_request(
                    body,
                    tls13=False,
                    raw=raw,
                    tls12=sh.selected_version >= VERSION_TLS12,
                )
                self._client_auth_requested = True
                self._client_auth_sig_algs = cr.signature_algorithms
                self._add_transcript(raw)
            elif msg_type == 22:  # CertificateStatus (OCSP stapling)
                self._set_stapled_ocsp_status(body)
                self._add_transcript(raw)
            elif msg_type == HANDSHAKE_SERVER_HELLO_DONE:
                self._add_transcript(raw)
                break
            else:
                raise HandshakeError(
                    f"unexpected {msgs.describe_handshake_type(msg_type)} in TLS 1.2 handshake",
                    alert=10,
                )

        if not cert_chain:
            raise HandshakeError("server did not send a certificate", alert=42)

        self._peer_certs = cert_chain
        self._state.peer_certificates = self.get_peer_certificates()
        verified_chain = cert_chain
        if not self.config.insecure_skip_verify:
            roots = self._load_roots()
            try:
                verified_chain = verify_certificate_chain(
                    cert_chain,
                    self.config.server_name,
                    roots,
                    check_hostname_enabled=self.config.verify_hostname,
                )
            except CertificateVerificationError as exc:
                raise HandshakeError(str(exc), alert=42) from exc
        self._check_revocation(verified_chain)
        self._run_verify_callback(verified_chain, self.config.server_name)
        self._check_sct(verified_chain[0])

        # The Certificate message is sent before ClientKeyExchange when the
        # server requested client authentication.
        client_key = None
        if cr is not None:
            chain, client_key = self._client_credentials(
                cr.certificate_authorities, cr.signature_algorithms
            )
            cert_msg = msgs.certificate(chain, tls13=False)
            self._add_transcript(cert_msg)
            send_record(self.sock, CONTENT_HANDSHAKE, self._state.version, cert_msg)

        if suite.kx == "ecdhe":
            if ske is None:
                raise HandshakeError("server did not send ServerKeyExchange", alert=40)
            signed = self._client_random + self._server_random + ske.params
            if ske.signature_scheme != 0:
                self._check_signature_scheme(ske.signature_scheme)
            try:
                verify_signature(
                    cert_chain[0].public_key(),
                    ske.signature_scheme,
                    ske.signature,
                    signed,
                )
            except CertificateVerificationError as exc:
                raise HandshakeError(str(exc), alert=42) from exc
            ks = generate_key_share(ske.named_curve)
            pre_master = ks.decapsulate(ske.public_key, self._state.version)
            ckx = msgs.client_key_exchange(ks.public_key)
        elif suite.kx == "rsa":
            if ske is not None:
                raise HandshakeError("unexpected ServerKeyExchange for RSA key exchange", alert=10)
            public_key = cert_chain[0].public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise HandshakeError("RSA key exchange requires an RSA certificate", alert=40)
            # RFC 5246 7.4.7.1: client_version followed by 46 random bytes.
            pre_master = self._client_hello_version + os.urandom(46)
            encrypted = public_key.encrypt(pre_master, padding.PKCS1v15())
            ckx = msgs.client_key_exchange_rsa(encrypted)
        else:  # pragma: no cover - guarded by the cipher suite table
            raise UnsupportedFeatureError(f"unsupported key exchange {suite.kx!r}")

        # RFC 7627 session_hash covers all handshake messages through
        # ClientKeyExchange.
        self._add_transcript(ckx)
        send_record(self.sock, CONTENT_HANDSHAKE, self._state.version, ckx)

        session_hash = self._finished_hash()

        if cr is not None and client_key is not None:
            if self._state.version >= VERSION_TLS12:
                scheme = select_signature_scheme(cr.signature_algorithms, client_key)
                sig = sign(client_key, scheme, bytes(self._transcript))
                cv = msgs.certificate_verify(scheme, sig)
            else:
                sig = sign_legacy(client_key, bytes(self._transcript))
                cv = msgs.certificate_verify_legacy(sig)
            self._add_transcript(cv)
            send_record(self.sock, CONTENT_HANDSHAKE, self._state.version, cv)

        if self._tls12_ems:
            # RFC 7627: the EMS PRF uses its own label and the session hash.
            master = self._prf(
                pre_master, b"extended master secret", session_hash, 48
            )
        else:
            master = self._prf(
                pre_master,
                b"master secret",
                self._client_random + self._server_random,
                48,
            )
        self._tls12_master_secret = master
        self._log_keylog("CLIENT_RANDOM", master)
        self._install_tls12_keys(suite, master)

        # ChangeCipherSpec, then Finished.
        send_record(self.sock, CONTENT_CHANGE_CIPHER_SPEC, self._state.version, b"\x01")
        verify_data = self._prf(master, b"client finished", self._finished_hash(), 12)
        finished = msgs.finished(verify_data)
        self._add_transcript(finished)
        self._send_encrypted(CONTENT_HANDSHAKE, finished)
        self._tls12_client_finished = verify_data

        # Server's CCS and Finished.  A NewSessionTicket may be sent before
        # the server's CCS; it is included in the transcript.
        server_done = False
        while not server_done:
            ctype, payload = self._read_decrypted_record()
            if ctype == CONTENT_CHANGE_CIPHER_SPEC:
                continue
            if ctype == CONTENT_ALERT:
                self._handle_alert(payload)
                continue
            if ctype != CONTENT_HANDSHAKE:
                raise HandshakeError(
                    f"expected server Finished, got record type {ctype}", alert=10
                )
            self._hs_buffer += payload
            while True:
                try:
                    msg_type, body, raw = self._next_buffered_handshake()
                except ValueError:
                    break
                if msg_type == HANDSHAKE_NEW_SESSION_TICKET:
                    self._add_transcript(raw)
                    self._note_tls12_ticket(body)
                    continue
                if msg_type != HANDSHAKE_FINISHED:
                    raise HandshakeError(
                        f"expected Finished, got {msgs.describe_handshake_type(msg_type)}", alert=10
                    )
                expected = self._prf(
                    master, b"server finished", self._finished_hash(), 12
                )
                if not hmac.compare_digest(expected, body):
                    raise HandshakeError("server Finished verification failed", alert=51)
                self._add_transcript(raw)
                server_done = True
                break
        if self._last_session is None and self._server_session_id and master:
            self._set_session(
                SessionState(
                    version=self._state.version,
                    cipher_suite_id=suite.id,
                    server_name=self.config.server_name,
                    alpn=self._state.alpn_protocol,
                    session_id=self._server_session_id,
                    ems=self._tls12_ems,
                    master_secret=master,
                )
            )
        self._state.handshake_complete = True
        try:
            self._run_verify_connection()
        except Exception:
            self._state.handshake_complete = False
            raise
        self._handshake_done = True

    def _run_verify_connection(self) -> None:
        callback = self.config.verify_connection
        if callback is None:
            return
        try:
            callback(self)
        except HandshakeError:
            raise
        except Exception as exc:
            raise HandshakeError(
                f"connection verification failed: {exc}", alert=80
            ) from exc

    def _install_tls12_keys(self, suite, master: bytes) -> None:
        mac_len = suite.mac_key_len
        key_block_len = 2 * (mac_len + suite.key_len + suite.iv_len)
        key_block = self._prf(
            master,
            b"key expansion",
            self._server_random + self._client_random,
            key_block_len,
        )
        offset = 0
        client_mac = key_block[offset : offset + mac_len]
        offset += mac_len
        server_mac = key_block[offset : offset + mac_len]
        offset += mac_len
        client_write_key = key_block[offset : offset + suite.key_len]
        offset += suite.key_len
        server_write_key = key_block[offset : offset + suite.key_len]
        offset += suite.key_len
        client_iv = key_block[offset : offset + suite.iv_len]
        offset += suite.iv_len
        server_iv = key_block[offset : offset + suite.iv_len]
        self._write_cipher = RecordCipher(
            suite, client_write_key, client_iv, version=self._state.version, mac_key=client_mac
        )
        self._read_cipher = RecordCipher(
            suite, server_write_key, server_iv, version=self._state.version, mac_key=server_mac
        )

    def _note_tls12_ticket(self, body: bytes) -> None:
        try:
            lifetime, ticket = msgs.parse_tls12_new_session_ticket(body)
        except ValueError:
            return
        if not ticket or self._tls12_master_secret is None:
            return
        self._set_session(
            SessionState(
                version=self._state.version,
                cipher_suite_id=self._suite.id,
                server_name=self.config.server_name,
                alpn=self._state.alpn_protocol,
                lifetime=lifetime,
                ticket=ticket,
                session_id=self._server_session_id,
                ems=self._tls12_ems,
                master_secret=self._tls12_master_secret,
            )
        )

    def _note_tls13_ticket(self, body: bytes) -> None:
        if self._resumption_master_secret is None or self._suite is None:
            return
        try:
            ticket = msgs.parse_new_session_ticket(body)
        except ValueError:
            return
        if not ticket.ticket or ticket.lifetime == 0:
            return
        h = self._hash_name
        psk = hkdf_expand_label(
            h, self._resumption_master_secret, "resumption", ticket.nonce, hash_len(h)
        )
        self._set_session(
            SessionState(
                version=VERSION_TLS13,
                cipher_suite_id=self._suite.id,
                server_name=self.config.server_name,
                alpn=self._state.alpn_protocol,
                lifetime=ticket.lifetime,
                ticket=ticket.ticket,
                ticket_age_add=ticket.age_add,
                ticket_nonce=ticket.nonce,
                max_early_data=ticket.max_early_data,
                psk=psk,
            )
        )

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------
    def sendall(self, data: bytes) -> None:
        if not self._handshake_done:
            raise HandshakeError("handshake is not complete")
        if not data:
            return
        for i in range(0, len(data), 16384):
            chunk = data[i : i + 16384]
            self._send_encrypted(CONTENT_APPLICATION_DATA, chunk)

    def write(self, data: bytes) -> int:
        self.sendall(data)
        return len(data)

    def send(self, data: bytes) -> int:
        self.sendall(data)
        return len(data)

    def recv(self, bufsize: int = 65536) -> bytes:
        if not self._handshake_done:
            raise HandshakeError("handshake is not complete")
        if self._app_buffer:
            out = bytes(self._app_buffer[:bufsize])
            del self._app_buffer[: len(out)]
            return out
        try:
            self._read_until_app_data()
        except EOFError:
            if self._received_close_notify:
                # close_notify is the TLS clean-EOF signal.
                return b""
            raise RecordError(
                "connection closed without a TLS close_notify"
            ) from None
        if not self._app_buffer:
            return b""
        out = bytes(self._app_buffer[:bufsize])
        del self._app_buffer[: len(out)]
        return out

    def read(self, n: int | None = None) -> bytes:
        if n is None or n <= 0:
            return self.recv()
        return self.recv(n)

    def recv_into(self, buffer, nbytes: int = 0) -> int:
        data = self.recv(nbytes or len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def makefile(
        self,
        mode: str = "r",
        buffering: int | None = None,
        *,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ):
        binary = "b" in mode
        if binary and (encoding is not None or errors is not None or newline is not None):
            raise ValueError("binary mode doesn't take encoding/errors/newline")
        raw = TLSFile(self, mode)
        if binary:
            return raw
        import io

        return io.TextIOWrapper(
            raw,
            encoding=encoding or "utf-8",
            errors=errors,
            newline=newline,
        )

    def fileno(self) -> int:
        return self.sock.fileno()

    def gettimeout(self):
        return self.sock.gettimeout()

    def settimeout(self, value) -> None:
        self._sock_timeout = value
        self.sock.settimeout(value)

    def getsockopt(self, level, optname, buflen=None):
        if buflen is None:
            return self.sock.getsockopt(level, optname)
        return self.sock.getsockopt(level, optname, buflen)

    def setsockopt(self, level, optname, value) -> None:
        self.sock.setsockopt(level, optname, value)

    def shutdown(self, how) -> None:
        self.sock.shutdown(how)

    def _read_until_app_data(self) -> None:
        while not self._app_buffer:
            ctype, payload = self._read_decrypted_record()
            if ctype == CONTENT_CHANGE_CIPHER_SPEC:
                continue
            if ctype == CONTENT_ALERT:
                self._handle_alert(payload)
                continue
            if ctype == CONTENT_HANDSHAKE:
                self._handle_post_handshake(payload)
                continue
            if ctype == CONTENT_APPLICATION_DATA:
                self._app_buffer += payload
                continue
            if ctype == 24:  # heartbeat
                continue
            raise HandshakeError(f"unexpected record type {ctype}", alert=10)

    def _handle_post_handshake(self, payload: bytes) -> None:
        self._hs_buffer += payload
        if len(self._hs_buffer) > MAX_HANDSHAKE_SIZE:
            raise HandshakeError("post-handshake message is too large", alert=22)
        while True:
            try:
                msg_type, body, raw = self._next_buffered_handshake()
            except ValueError:
                return
            if msg_type == HANDSHAKE_NEW_SESSION_TICKET:
                if self._state.version == VERSION_TLS13:
                    self._note_tls13_ticket(body)
                elif self._state.version < VERSION_TLS13:
                    self._note_tls12_ticket(body)
                continue
            if msg_type == HANDSHAKE_KEY_UPDATE and self._state.version == VERSION_TLS13:
                update = msgs.parse_key_update(body, raw)
                h = self._hash_name
                self._server_app_secret = derive_secret(h, self._server_app_secret or b"", "traffic upd", b"")
                self._read_cipher = self._make_app_cipher(self._server_app_secret)
                if update.request_update:
                    self._client_app_secret = derive_secret(
                        h, self._client_app_secret or b"", "traffic upd", b""
                    )
                    self._write_cipher = self._make_app_cipher(self._client_app_secret)
                    ku = msgs.key_update(False)
                    self._send_encrypted(CONTENT_HANDSHAKE, ku)
                continue
            # Unknown post-handshake messages are ignored for forward
            # compatibility (e.g. certificate requests in TLS 1.3).
            continue

    def _make_app_cipher(self, secret: bytes) -> RecordCipher:
        assert self._suite is not None
        return RecordCipher(
            self._suite,
            hkdf_expand_label(self._hash_name, secret, "key", b"", self._suite.key_len),
            hkdf_expand_label(self._hash_name, secret, "iv", b"", 12),
            version=VERSION_TLS13,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if (
                self._handshake_done
                and self._write_cipher is not None
                and not self._received_close_notify
            ):
                self._send_encrypted(CONTENT_ALERT, msgs.alert(1, 0))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    unwrap = close

    def __enter__(self) -> "UConn":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _add_transcript(self, raw: bytes) -> None:
        self._transcript += raw

    def _transcript_hash(self) -> bytes:
        return hashlib.new(self._hash_name, bytes(self._transcript)).digest()

    def _finished_hash(self) -> bytes:
        data = bytes(self._transcript)
        if self._state.version >= VERSION_TLS12:
            return hashlib.new(self._hash_name, data).digest()
        # TLS 1.0/1.1 Finished hashes use MD5 || SHA1.
        return hashlib.md5(data).digest() + hashlib.sha1(data).digest()

    def _prf(self, secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
        return tls_prf(self._state.version, self._hash_name, secret, label, seed, length)

    def _hmac_hash(self):
        return hashlib.new(self._hash_name)

    def _log_keylog(
        self,
        label: str,
        secret: bytes,
        client_random: bytes | None = None,
    ) -> None:
        writer = self.config.keylog_writer
        if writer is None:
            return
        random_bytes = client_random or self._client_random
        try:
            writer(f"{label} {random_bytes.hex()} {secret.hex()}\n")
        except Exception:
            # Key logging must never break an otherwise valid handshake.
            pass

    def _run_verify_callback(
        self, chain: list[x509.Certificate], authenticated_name: str
    ) -> None:
        callback = self.config.verify_peer_certificate
        if callback is None:
            return
        try:
            callback(list(chain), authenticated_name)
        except Exception as exc:
            raise HandshakeError(
                f"custom certificate verification failed: {exc}", alert=42
            ) from exc

    def _check_sct(self, leaf: x509.Certificate) -> None:
        from .ct import certificate_scts

        scts = certificate_scts(leaf)
        self._state.sct_count = len(scts)
        if not scts and self.config.require_sct:
            raise HandshakeError(
                "certificate transparency SCT is required but missing", alert=42
            )
        callback = self.config.sct_verifier
        if callback is None:
            return
        try:
            callback(leaf, scts)
        except Exception as exc:
            raise HandshakeError(
                f"SCT verification failed: {exc}", alert=42
            ) from exc

    def _load_roots(self) -> list[x509.Certificate] | None:
        if self.config.root_cas is None:
            return self._roots
        roots = []
        for item in self.config.root_cas:
            if isinstance(item, str):
                item = item.encode()
            if b"-----BEGIN" in item:
                roots.append(x509.load_pem_x509_certificate(item))
            else:
                roots.append(x509.load_der_x509_certificate(item))
        return roots

    _default_roots: list[x509.Certificate] | None = None

    @property
    def _roots(self):
        if self._default_roots is None:
            UConn._default_roots = load_system_roots()
        return UConn._default_roots

    @staticmethod
    def _normalize_client_chain(items) -> list[bytes]:
        chain: list[bytes] = []
        for item in items:
            if isinstance(item, x509.Certificate):
                chain.append(
                    item.public_bytes(serialization.Encoding.DER)
                )
                continue
            if isinstance(item, str):
                item = item.encode()
            if not isinstance(item, (bytes, bytearray)):
                raise HandshakeError(
                    "client certificate callback returned an invalid chain entry",
                    alert=40,
                )
            data = bytes(item)
            if b"-----BEGIN" in data:
                data = x509.load_pem_x509_certificate(data).public_bytes(
                    serialization.Encoding.DER
                )
            chain.append(data)
        return chain

    def _normalize_client_key(self, item):
        if hasattr(item, "sign") and hasattr(item, "public_key"):
            return item
        if isinstance(item, str):
            item = item.encode()
        if not isinstance(item, (bytes, bytearray)):
            raise HandshakeError(
                "client certificate callback returned an invalid private key",
                alert=40,
            )
        data = bytes(item)
        try:
            return serialization.load_pem_private_key(
                data, password=self.config.client_private_key_password
            )
        except ValueError:
            return serialization.load_der_private_key(
                data, password=self.config.client_private_key_password
            )

    def _client_credentials(
        self,
        acceptable_cas: list[bytes] | None = None,
        signature_algorithms: list[int] | None = None,
    ):
        callback = self.config.get_client_certificate
        if callback is not None:
            try:
                result = callback(
                    list(acceptable_cas or []),
                    list(signature_algorithms or []),
                )
            except HandshakeError:
                raise
            except Exception as exc:
                raise HandshakeError(
                    f"client certificate callback failed: {exc}", alert=40
                ) from exc
            if result is None:
                return [], None
            try:
                chain_items, key_item = result
            except (TypeError, ValueError) as exc:
                raise HandshakeError(
                    "client certificate callback must return (chain, key) or None",
                    alert=40,
                ) from exc
            chain = self._normalize_client_chain(chain_items)
            key = self._normalize_client_key(key_item)
            if bool(chain) != (key is not None):
                raise HandshakeError(
                    "client certificate callback returned a mismatched chain/key",
                    alert=40,
                )
            return chain, key

        if not self.config.client_cert_chain and not self.config.client_private_key:
            return [], None
        if not self.config.client_cert_chain or not self.config.client_private_key:
            raise HandshakeError(
                "both client_cert_chain and client_private_key are required",
                alert=40,
            )
        chain = self._normalize_client_chain(self.config.client_cert_chain)
        key = self._normalize_client_key(self.config.client_private_key)
        return chain, key

    def _parse_certificate_message(self, body: bytes, raw: bytes, tls13: bool) -> list[x509.Certificate]:
        cert_msg = msgs.parse_certificate(body, tls13, raw)
        self._peer_cert_der = [entry.data for entry in cert_msg.certificate_list]
        if tls13 and cert_msg.certificate_list:
            for ext in cert_msg.certificate_list[0].extensions:
                if ext.type == 5:  # status_request
                    self._set_stapled_ocsp_status(ext.data)
        self._add_transcript(raw)
        chain = []
        for entry in cert_msg.certificate_list:
            try:
                chain.append(x509.load_der_x509_certificate(entry.data))
            except ValueError as exc:
                raise HandshakeError("invalid certificate encoding", alert=42) from exc
        return chain

    def _parse_compressed_certificate(self, body: bytes, raw: bytes) -> list[x509.Certificate]:
        cc = msgs.parse_compressed_certificate(body, raw)
        if (
            cc.uncompressed_length > MAX_CERTIFICATE_SIZE
            or len(cc.compressed) > MAX_CERTIFICATE_SIZE
        ):
            raise HandshakeError("compressed certificate is too large", alert=22)
        if cc.algorithm == CERT_COMPRESSION_ZLIB:
            import zlib

            decompressor = zlib.decompressobj()
            uncompressed = decompressor.decompress(
                cc.compressed, cc.uncompressed_length + 1
            )
            if decompressor.unconsumed_tail or len(uncompressed) > cc.uncompressed_length:
                raise HandshakeError("compressed certificate length mismatch", alert=50)
        elif cc.algorithm == CERT_COMPRESSION_BROTLI:
            try:
                import brotli
            except ImportError as exc:
                raise UnsupportedFeatureError(
                    "server sent a brotli-compressed certificate; install the 'brotli' package"
                ) from exc
            uncompressed = brotli.decompress(cc.compressed)
        elif cc.algorithm == CERT_COMPRESSION_ZSTD:
            try:
                import zstandard
            except ImportError as exc:
                raise UnsupportedFeatureError(
                    "server sent a zstd-compressed certificate; install the 'zstandard' package"
                ) from exc
            uncompressed = zstandard.ZstdDecompressor().decompress(
                cc.compressed, max_output_size=cc.uncompressed_length
            )
        else:
            raise UnsupportedFeatureError(f"unknown certificate compression algorithm {cc.algorithm}")
        if len(uncompressed) != cc.uncompressed_length:
            raise HandshakeError("compressed certificate length mismatch", alert=50)
        # The transcript includes the CompressedCertificate message itself.
        self._add_transcript(raw)
        cert_body = uncompressed
        return self._parse_certificate_body_without_transcript(cert_body, tls13=True)

    def _parse_certificate_body_without_transcript(self, body: bytes, tls13: bool) -> list[x509.Certificate]:
        cert_msg = msgs.parse_certificate(body, tls13)
        self._peer_cert_der = [entry.data for entry in cert_msg.certificate_list]
        if tls13 and cert_msg.certificate_list:
            for ext in cert_msg.certificate_list[0].extensions:
                if ext.type == 5:
                    self._set_stapled_ocsp_status(ext.data)
        return [x509.load_der_x509_certificate(entry.data) for entry in cert_msg.certificate_list]

    def _set_stapled_ocsp_status(self, body: bytes) -> None:
        """Store the OCSP response carried by a CertificateStatus extension."""
        if len(body) < 4 or body[0] != 1:
            return
        length = int.from_bytes(body[1:4], "big")
        if length and len(body) >= 4 + length:
            self._stapled_ocsp = body[4 : 4 + length]

    def _check_revocation(self, cert_chain: list[x509.Certificate]) -> None:
        if not cert_chain or self.config.insecure_skip_verify:
            return
        if self.config.require_crl and not (
            self.config.crls or self.config.fetch_crls
        ):
            raise HandshakeError(
                "CRL verification is required but no CRLs are configured",
                alert=42,
            )
        if self.config.crls or self.config.fetch_crls:
            try:
                crls = load_crls(self.config.crls)
                if self.config.fetch_crls:
                    for index, cert in enumerate(cert_chain[:-1]):
                        issuer = cert_chain[index + 1]
                        if any(crl.issuer == issuer.subject for crl in crls):
                            continue
                        last_error = None
                        for url in crl_distribution_points(cert):
                            try:
                                crls.append(
                                    load_crls(
                                        [
                                            fetch_url(
                                                url,
                                                timeout=self.config.crl_timeout,
                                                allow_private=self.config.allow_private_revocation_urls,
                                            )
                                        ]
                                    )[0]
                                )
                                break
                            except CertificateVerificationError as exc:
                                last_error = exc
                        if last_error is not None and not any(
                            crl.issuer == issuer.subject for crl in crls
                        ):
                            raise last_error
                check_crl_revocation(cert_chain, crls)
                if self.config.require_crl:
                    for index, cert in enumerate(cert_chain[:-1]):
                        issuer = cert_chain[index + 1]
                        if not any(crl.issuer == issuer.subject for crl in crls):
                            raise CertificateVerificationError(
                                f"no CRL is available for {cert.subject.rfc4514_string()}"
                            )
            except CertificateVerificationError as exc:
                raise HandshakeError(str(exc), alert=42) from exc
            except ValueError as exc:
                raise HandshakeError("malformed CRL", alert=42) from exc

        wants_ocsp = (
            self.config.verify_ocsp_stapling
            or self.config.require_ocsp_stapling
            or self.config.fetch_ocsp
        )
        if not wants_ocsp:
            return
        issuer = cert_chain[1] if len(cert_chain) > 1 else cert_chain[0]
        response = self._stapled_ocsp
        if response is None and self.config.fetch_ocsp:
            url = self.config.ocsp_url or ocsp_responder_url(cert_chain[0])
            if url:
                try:
                    response = fetch_ocsp_response(
                        url,
                        cert_chain[0],
                        issuer,
                        timeout=self.config.ocsp_timeout,
                        allow_private=self.config.allow_private_revocation_urls,
                    )
                except CertificateVerificationError as exc:
                    raise HandshakeError(str(exc), alert=42) from exc
        if response is None:
            if self.config.require_ocsp_stapling:
                raise HandshakeError("no OCSP response is available", alert=42)
            return
        try:
            verify_ocsp_response(response, cert_chain[0], issuer)
        except CertificateVerificationError as exc:
            raise HandshakeError(str(exc), alert=42) from exc

    def _send_encrypted(self, content_type: int, payload: bytes) -> None:
        if self._write_cipher is None:
            send_record(self.sock, content_type, self._state.version, payload)
            return
        if self._state.version == VERSION_TLS13:
            out = self._write_cipher.seal_tls13(payload, content_type)
            # TLS 1.3 fixes legacy_record_version to 0x0303.
            send_record(self.sock, CONTENT_APPLICATION_DATA, VERSION_TLS12, out)
        else:
            version = self._state.version
            out = self._write_cipher.seal_tls12(payload, content_type, version)
            send_record(self.sock, content_type, version, out)

    def _read_decrypted_record(self) -> tuple[int, bytes]:
        """Read one record and return ``(inner_content_type, plaintext)``."""
        ctype, version, payload = self.reader.read_record()
        if ctype == CONTENT_CHANGE_CIPHER_SPEC:
            if self._state.version < VERSION_TLS13:
                self._tls12_server_ccs_seen = True
            return ctype, b""
        if self._read_cipher is None:
            return ctype, payload
        if self._state.version == VERSION_TLS13:
            if ctype != CONTENT_APPLICATION_DATA:
                raise RecordError(
                    f"unexpected plaintext record type {ctype} after TLS 1.3 keys were installed"
                )
            header = bytes([ctype]) + version.to_bytes(2, "big") + len(payload).to_bytes(2, "big")
            plaintext, inner_type = self._read_cipher.open_tls13(payload, header)
            return inner_type, plaintext
        # TLS 1.2: everything after the peer's ChangeCipherSpec is protected.
        if self._tls12_server_ccs_seen:
            if ctype not in (
                CONTENT_HANDSHAKE,
                CONTENT_ALERT,
                CONTENT_APPLICATION_DATA,
            ):
                raise RecordError(
                    f"unexpected plaintext record type {ctype} after ChangeCipherSpec"
                )
            return ctype, self._read_cipher.open_tls12(payload, ctype, version)
        return ctype, payload

    def _next_buffered_handshake(self) -> tuple[int, bytes, bytes]:
        msg_type, body, consumed = msgs.parse_handshake_header(bytes(self._hs_buffer))
        raw = bytes(self._hs_buffer[:consumed])
        del self._hs_buffer[:consumed]
        return msg_type, body, raw

    def _read_handshake_plain(self) -> tuple[int, bytes, bytes]:
        while True:
            if self._hs_buffer:
                try:
                    return self._next_buffered_handshake()
                except ValueError:
                    pass
            ctype, payload = self._read_decrypted_record()
            if ctype == CONTENT_CHANGE_CIPHER_SPEC:
                continue
            if ctype == CONTENT_ALERT:
                self._handle_alert(payload)
                continue
            if ctype != CONTENT_HANDSHAKE:
                raise HandshakeError(f"expected handshake record, got type {ctype}", alert=10)
            self._hs_buffer += payload
            if len(self._hs_buffer) > MAX_HANDSHAKE_SIZE:
                raise HandshakeError("handshake message is too large", alert=22)

    def _read_handshake_encrypted(self) -> tuple[int, bytes, bytes]:
        while True:
            if self._hs_buffer:
                try:
                    return self._next_buffered_handshake()
                except ValueError:
                    pass
            ctype, payload = self._read_decrypted_record()
            if ctype == CONTENT_CHANGE_CIPHER_SPEC:
                continue
            if ctype == CONTENT_ALERT:
                self._handle_alert(payload)
                continue
            if ctype != CONTENT_HANDSHAKE:
                raise HandshakeError(f"unexpected record type {ctype} during handshake", alert=10)
            self._hs_buffer += payload
            if len(self._hs_buffer) > MAX_HANDSHAKE_SIZE:
                raise HandshakeError("handshake message is too large", alert=22)

    def _handle_alert(self, payload: bytes) -> None:
        if len(payload) < 2:
            raise HandshakeError("malformed alert", alert=50)
        level, description = payload[0], payload[1]
        if description == 0:
            self._received_close_notify = True
            try:
                self._send_encrypted(CONTENT_ALERT, msgs.alert(1, 0))
            except Exception:
                pass
            raise EOFError("peer closed the connection")
        name = ALERT_NAMES.get(description, f"alert({description})")
        raise AlertError(description, name, level)


# ---------------------------------------------------------------------------
# Convenience constructors
# ---------------------------------------------------------------------------


#: uTLS spells the connection type ``UConn`` and its constructor ``UClient``.
UClient = UConn


def wrap_socket(
    sock,
    server_hostname: str | None = None,
    *,
    config: Config | None = None,
    client_hello: ClientHelloID | str | ClientHelloSpec | None = None,
    insecure: bool = False,
    alpn: list[str] | None = None,
    ech_config_list=None,
) -> UConn:
    """Wrap an existing connected socket and perform the handshake."""
    if config is None:
        config = Config()
    if server_hostname:
        config.server_name = server_hostname
    if insecure:
        config.insecure_skip_verify = True
    if alpn:
        config.next_protos = list(alpn)
    if ech_config_list is not None:
        config.ech_config_list = ech_config_list
    conn = UConn(sock, config, client_hello_id=client_hello)
    conn.handshake()
    return conn


def connect(
    host: str,
    port: int = 443,
    *,
    server_name: str | None = None,
    client_hello: ClientHelloID | str | ClientHelloSpec | None = None,
    preset: ClientHelloID | str | ClientHelloSpec | None = None,
    insecure: bool = False,
    alpn: list[str] | None = None,
    timeout: float | None = 30.0,
    config: Config | None = None,
    ech_config_list=None,
) -> UConn:
    """Open a TCP connection and perform a TLS handshake."""
    import socket as _socket

    if config is None:
        config = Config(server_name=server_name or host, timeout=timeout)
    else:
        if server_name:
            config.server_name = server_name
        elif not config.server_name:
            config.server_name = host
        if timeout is not None:
            config.timeout = timeout
    if insecure:
        config.insecure_skip_verify = True
    if alpn:
        config.next_protos = list(alpn)
    if ech_config_list is not None:
        config.ech_config_list = ech_config_list

    sock = _socket.create_connection((host, port), timeout=timeout)
    try:
        conn = UConn(sock, config, client_hello_id=client_hello or preset)
        conn.handshake()
        return conn
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise
