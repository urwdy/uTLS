"""Shared helpers for the test suite (certificates and a local TLS server)."""

from __future__ import annotations

import atexit
import datetime
import http.server
import ipaddress
import os
import shutil
import socket
import ssl
import tempfile
import threading
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_TMP = tempfile.mkdtemp(prefix="utls-tests-")
atexit.register(shutil.rmtree, _TMP, True)


def _write(name: str, data: bytes) -> str:
    path = os.path.join(_TMP, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


def new_key(key_type: str = "rsa"):
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError(key_type)


def make_ca(common_name: str = "uTLS test CA", key_type: str = "rsa"):
    key = new_key(key_type)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "uTLS tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issue_cert(
    ca,
    common_name: str = "localhost",
    key_type: str = "rsa",
    is_ca: bool = False,
    not_before_days: int = -1,
    not_after_days: int = 90,
    dns_names: tuple[str, ...] | None = None,
    crl_url: str | None = None,
    ocsp_url: str | None = None,
):
    ca_cert, ca_key = ca
    key = new_key(key_type)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "uTLS tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_days))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in (dns_names or ("localhost", "example.test"))]
                + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if is_ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=isinstance(key, rsa.RSAPrivateKey),
                data_encipherment=False,
                key_agreement=isinstance(key, ec.EllipticCurvePrivateKey),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    if ocsp_url:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(ocsp_url),
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(ca_key, hashes.SHA256()), key


def cert_der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def cert_chain_pem(*certs) -> bytes:
    return b"".join(cert_pem(c) for c in certs)


class LocalServer:
    """One-shot TLS server used by the interop tests."""

    def __init__(
        self,
        server_cert,
        server_key,
        *,
        extra_chain: tuple = (),
        min_version=ssl.TLSVersion.TLSv1_2,
        max_version=ssl.TLSVersion.TLSv1_3,
        alpn=("h2", "http/1.1"),
        client_ca=None,
        require_client_cert: bool = False,
        response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ecdh_curve: str | None = None,
        ciphers: str | None = None,
        connections: int = 1,
        options: int = 0,
        clean_close: bool = True,
    ) -> None:
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        certfile = _write("server-chain.pem", cert_chain_pem(server_cert, *extra_chain))
        keyfile = _write("server-key.pem", key_pem(server_key))
        self.ctx.load_cert_chain(certfile, keyfile)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self.ctx.minimum_version = min_version
            self.ctx.maximum_version = max_version
        if alpn:
            self.ctx.set_alpn_protocols(list(alpn))
        if ecdh_curve:
            self.ctx.set_ecdh_curve(ecdh_curve)
        if ciphers:
            self.ctx.set_ciphers(ciphers)
        if options:
            self.ctx.options |= options
        if client_ca is not None:
            self.ctx.load_verify_locations(cadata=cert_pem(client_ca).decode("ascii"))
            self.ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
        self.response = response
        self.connections = connections
        self.clean_close = clean_close
        self.infos: list[dict] = []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(connections + 1)
        self.port = self.sock.getsockname()[1]
        self.errors: list[Exception] = []
        self.info: dict = {}
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        for _ in range(self.connections):
            try:
                raw, _ = self.sock.accept()
                tls = self.ctx.wrap_socket(raw, server_side=True)
                info = {
                    "version": tls.version(),
                    "cipher": tls.cipher()[0],
                    "alpn": tls.selected_alpn_protocol(),
                    "peer_cert": tls.getpeercert(),
                }
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                info["request"] = request
                tls.sendall(self.response)
                self.infos.append(info)
                self.info = info
                # Send a TLS close_notify.  The client replies with its own
                # close_notify, so unwrap() can complete; a short timeout keeps
                # tests that do not read the response from hanging.
                if self.clean_close:
                    try:
                        tls.settimeout(2)
                        raw = tls.unwrap()
                        raw.close()
                    except Exception:
                        pass
                try:
                    tls.close()
                except Exception:
                    pass
            except Exception as exc:  # pragma: no cover - surfaced by tests
                self.errors.append(exc)
                continue
        try:
            self.sock.close()
        except Exception:
            pass

    def wait(self, timeout: float = 10.0) -> None:
        self._thread.join(timeout)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass
        self._thread.join(1)

    def __enter__(self) -> "LocalServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class StaticHTTPServer:
    """Tiny local HTTP server used for CRL / OCSP fetches in tests."""

    def __init__(self, responses: dict[str, bytes]) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self):
                path = self.path.split("?", 1)[0]
                body = responses.get(path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _serve
            do_POST = _serve

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(1)

    def __enter__(self) -> "StaticHTTPServer":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
