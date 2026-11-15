"""X.509 chain validation and TLS signature helpers."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import ipaddress
import socket
import ssl
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)
from cryptography.x509 import UnsupportedGeneralNameType, verification as x509_verification
from cryptography.x509.oid import AuthorityInformationAccessOID

from .errors import UTLSError
from .constants import (
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SECP521R1_SHA512,
    SIG_ECDSA_SHA1,
    SIG_ED25519,
    SIG_ED448,
    SIG_RSA_PKCS1_SHA1,
    SIG_RSA_PKCS1_SHA256,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PKCS1_SHA512,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PSS_PSS_SHA256,
    SIG_RSA_PSS_PSS_SHA384,
    SIG_RSA_PSS_PSS_SHA512,
)

RSA_PKCS1_SCHEMES = {
    SIG_RSA_PKCS1_SHA1: "sha1",
    SIG_RSA_PKCS1_SHA256: "sha256",
    SIG_RSA_PKCS1_SHA384: "sha384",
    SIG_RSA_PKCS1_SHA512: "sha512",
}
RSA_PSS_SCHEMES = {
    SIG_RSA_PSS_RSAE_SHA256: "sha256",
    SIG_RSA_PSS_RSAE_SHA384: "sha384",
    SIG_RSA_PSS_RSAE_SHA512: "sha512",
    SIG_RSA_PSS_PSS_SHA256: "sha256",
    SIG_RSA_PSS_PSS_SHA384: "sha384",
    SIG_RSA_PSS_PSS_SHA512: "sha512",
}
ECDSA_SCHEMES = {
    SIG_ECDSA_SHA1: "sha1",
    SIG_ECDSA_SECP256R1_SHA256: "sha256",
    SIG_ECDSA_SECP384R1_SHA384: "sha384",
    SIG_ECDSA_SECP521R1_SHA512: "sha512",
}

CRYPTO_HASHES = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class CertificateVerificationError(UTLSError):
    pass


def load_system_roots() -> list[x509.Certificate]:
    """Best-effort load of the platform trust store."""
    ders: list[bytes] = []
    try:
        for cert, encoding, _trust in ssl.enum_certificates("ROOT"):
            if encoding == "x509_asn":
                ders.append(cert)
    except Exception:
        pass
    if not ders:
        # Linux/macOS: ask OpenSSL for its default CA bundle.
        try:
            ctx = ssl.create_default_context()
            ders = ctx.get_ca_certs(binary_form=True)
        except Exception:  # pragma: no cover - platform dependent
            ders = []
    roots = []
    seen = set()
    import warnings

    with warnings.catch_warnings():
        # Some platform trust stores contain legacy certificates that trip
        # harmless parsing warnings in newer cryptography releases.
        warnings.simplefilter("ignore")
        for der in ders:
            if der in seen:
                continue
            seen.add(der)
            try:
                roots.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue
    return roots


def cert_fingerprint(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())


def verify_legacy_signature(public_key, signature: bytes, data: bytes) -> None:
    """Verify a pre-TLS 1.2 ServerKeyExchange signature.

    RSA uses PKCS#1 v1.5 over MD5||SHA1, ECDSA uses SHA-1.
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA1()))
        except InvalidSignature as exc:
            raise CertificateVerificationError("bad TLS 1.0 ECDSA signature") from exc
        return
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CertificateVerificationError("unsupported legacy signature key type")
    numbers = public_key.public_numbers()
    size = (numbers.n.bit_length() + 7) // 8
    if len(signature) > size:
        raise CertificateVerificationError("bad TLS 1.0 RSA signature length")
    encoded = pow(int.from_bytes(signature, "big"), numbers.e, numbers.n).to_bytes(size, "big")
    if not encoded.startswith(b"\x00\x01"):
        raise CertificateVerificationError("bad TLS 1.0 RSA signature padding")
    separator = encoded.find(b"\x00", 2)
    if separator < 10:
        raise CertificateVerificationError("bad TLS 1.0 RSA signature padding")
    if any(byte != 0xFF for byte in encoded[2:separator]):
        raise CertificateVerificationError("bad TLS 1.0 RSA signature padding")
    digest = encoded[separator + 1 :]
    expected = hashlib.md5(data).digest() + hashlib.sha1(data).digest()
    if not hmac.compare_digest(digest, expected):
        raise CertificateVerificationError("bad TLS 1.0 RSA signature")


def verify_signature(public_key, scheme: int, signature: bytes, data: bytes) -> None:
    """Verify ``signature`` over ``data``; raises ``CertificateVerificationError``."""
    if scheme == 0:
        verify_legacy_signature(public_key, signature, data)
        return
    if scheme in RSA_PKCS1_SCHEMES:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CertificateVerificationError("RSA PKCS#1 signature with non-RSA key")
        h = CRYPTO_HASHES[RSA_PKCS1_SCHEMES[scheme]]()
        try:
            public_key.verify(signature, data, padding.PKCS1v15(), h)
        except InvalidSignature as exc:
            raise CertificateVerificationError("bad RSA PKCS#1 signature") from exc
        return
    if scheme in RSA_PSS_SCHEMES:
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CertificateVerificationError("RSA-PSS signature with non-RSA key")
        h = CRYPTO_HASHES[RSA_PSS_SCHEMES[scheme]]()
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size),
                h,
            )
        except InvalidSignature as exc:
            raise CertificateVerificationError("bad RSA-PSS signature") from exc
        return
    if scheme in ECDSA_SCHEMES:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise CertificateVerificationError("ECDSA signature with non-EC key")
        h = CRYPTO_HASHES[ECDSA_SCHEMES[scheme]]()
        try:
            public_key.verify(signature, data, ec.ECDSA(h))
        except InvalidSignature as exc:
            raise CertificateVerificationError("bad ECDSA signature") from exc
        return
    if scheme == SIG_ED25519:
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise CertificateVerificationError("Ed25519 signature with non-Ed25519 key")
        try:
            public_key.verify(signature, data)
        except InvalidSignature as exc:
            raise CertificateVerificationError("bad Ed25519 signature") from exc
        return
    if scheme == SIG_ED448:
        if not isinstance(public_key, ed448.Ed448PublicKey):
            raise CertificateVerificationError("Ed448 signature with non-Ed448 key")
        try:
            public_key.verify(signature, data)
        except InvalidSignature as exc:
            raise CertificateVerificationError("bad Ed448 signature") from exc
        return
    raise CertificateVerificationError(f"unsupported signature scheme {scheme:#06x}")


def _verification_dns_name(value: str) -> str:
    value = value.rstrip(".").lower()
    if not value.isascii():
        try:
            value = value.encode("idna").decode()
        except UnicodeError:
            pass
    return value


def _verification_subject(cert: x509.Certificate, server_name: str | None):
    """Choose the subject used for cryptographic path validation.

    When ``server_name`` is omitted, derive a name from the certificate itself
    so that ``build_chain`` can validate the path without performing a
    hostname check.
    """
    if server_name:
        host = server_name.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            return x509_verification.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            return x509_verification.DNSName(_verification_dns_name(host))

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        for name in san:
            if isinstance(name, x509.DNSName) and name.value:
                value = name.value
                if value.startswith("*."):
                    value = "x." + value[2:]
                return x509_verification.DNSName(_verification_dns_name(value))
        for name in san:
            if isinstance(name, x509.IPAddress):
                return x509_verification.IPAddress(name.value)

    for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
        if attr.value:
            value = attr.value
            if value.startswith("*."):
                value = "x." + value[2:]
            return x509_verification.DNSName(_verification_dns_name(value))
    raise CertificateVerificationError("certificate has no usable subject name")


def build_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    roots: list[x509.Certificate] | None = None,
    now: datetime.datetime | None = None,
    *,
    subject_name: str | None = None,
) -> list[x509.Certificate]:
    """Build and validate a server certificate path.

    ``cryptography.x509.verification`` performs RFC 5280 path validation:
    BasicConstraints, KeyUsage, path length, name constraints, EKU, critical
    extensions and signature algorithms.  Hostname matching is performed
    separately by :func:`check_hostname` (and is also constrained by the
    verifier's subject).
    """
    if roots is None:
        roots = load_system_roots()
    if not roots:
        raise CertificateVerificationError("no trusted roots are configured")
    try:
        store = x509_verification.Store(list(roots))
        builder = x509_verification.PolicyBuilder().store(store)
        if now is not None:
            builder = builder.time(now)
        verifier = builder.build_server_verifier(
            _verification_subject(leaf, subject_name)
        )
        return list(verifier.verify(leaf, list(intermediates)))
    except (x509_verification.VerificationError, UnsupportedGeneralNameType) as exc:
        raise CertificateVerificationError(str(exc)) from exc
    except ValueError as exc:
        raise CertificateVerificationError(str(exc)) from exc


def check_hostname(cert: x509.Certificate, hostname: str) -> None:
    """Verify SANs (falling back to CN) with RFC 6125 wildcard rules."""
    hostname = hostname.rstrip(".").lower()
    if not hostname.isascii():
        try:
            hostname = hostname.encode("idna").decode()
        except UnicodeError:
            pass
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        try:
            ips = san.get_values_for_type(x509.IPAddress)
        except ValueError:  # pragma: no cover
            ips = []
    except x509.ExtensionNotFound:
        dns_names = []
        ips = []
        for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
            dns_names.append(attr.value)

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if any(str(ip) == str(candidate) for candidate in ips):
            return
        raise CertificateVerificationError(f"certificate is not valid for IP {hostname}")

    for name in dns_names:
        name = name.lower().rstrip(".")
        if name == hostname:
            return
        if name.startswith("*.") and name.count("*") == 1:
            suffix = name[2:]
            # A wildcard must not cover a public suffix such as *.com or
            # *.co.uk.  Use the bundled Public Suffix List for the check.
            from .psl import is_public_suffix

            if is_public_suffix(suffix):
                continue
            if hostname.endswith("." + suffix) and "." not in hostname[: -len(suffix) - 1]:
                return
    raise CertificateVerificationError(f"certificate is not valid for {hostname}")


def verify_certificate_chain(
    cert_chain: list[x509.Certificate],
    server_name: str,
    roots: list[x509.Certificate] | None = None,
    check_hostname_enabled: bool = True,
) -> list[x509.Certificate]:
    if not cert_chain:
        raise CertificateVerificationError("server did not send a certificate")
    chain = build_chain(
        cert_chain[0],
        cert_chain[1:],
        roots,
        subject_name=server_name if check_hostname_enabled else None,
    )
    if check_hostname_enabled:
        check_hostname(cert_chain[0], server_name)
    return chain


def crl_distribution_points(cert: x509.Certificate) -> list[str]:
    """HTTP(S) CRL URLs from the certificate's CRL Distribution Points."""
    urls: list[str] = []
    try:
        points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return urls
    for point in points:
        for name in point.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                if name.value.lower().startswith(("http://", "https://")):
                    urls.append(name.value)
    return urls


def ocsp_responder_url(cert: x509.Certificate) -> str | None:
    """OCSP responder URL from the certificate's Authority Information Access."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for description in aia:
        if description.access_method != AuthorityInformationAccessOID.OCSP:
            continue
        location = description.access_location
        if isinstance(location, x509.UniformResourceIdentifier):
            if location.value.lower().startswith(("http://", "https://")):
                return location.value
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CertificateVerificationError(
            "redirects are not allowed for revocation URLs"
        )


def _open_revocation_url(request: urllib.request.Request, timeout: float):
    opener = urllib.request.build_opener(_NoRedirect)
    return opener.open(request, timeout=timeout)


def _check_fetch_url(url: str, allow_private: bool) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise CertificateVerificationError("unsupported revocation URL scheme")
    if allow_private:
        return
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = socket.getaddrinfo(
            parsed.hostname, port, type=socket.SOCK_STREAM
        )
    except OSError as exc:
        raise CertificateVerificationError(
            "revocation URL host could not be resolved"
        ) from exc
    for info in addresses:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise CertificateVerificationError(
                "revocation URL resolves to a non-public address"
            )


def fetch_url(
    url: str,
    timeout: float = 10.0,
    max_size: int = 8 * 1024 * 1024,
    *,
    allow_private: bool = False,
) -> bytes:
    """Fetch a small HTTP(S) resource used for revocation data."""
    _check_fetch_url(url, allow_private)
    request = urllib.request.Request(url, headers={"User-Agent": "uTLS-python"})
    try:
        with _open_revocation_url(request, timeout) as response:
            data = response.read(max_size + 1)
    except Exception as exc:
        raise CertificateVerificationError(f"failed to fetch {url}") from exc
    if len(data) > max_size:
        raise CertificateVerificationError("revocation response is too large")
    return data


def load_crls(items: list[bytes]) -> list[x509.CertificateRevocationList]:
    crls = []
    for item in items:
        if isinstance(item, str):
            item = item.encode()
        try:
            if b"-----BEGIN" in item:
                crls.append(x509.load_pem_x509_crl(item))
            else:
                crls.append(x509.load_der_x509_crl(item))
        except ValueError as exc:
            raise CertificateVerificationError("malformed CRL") from exc
    return crls


def check_crl_revocation(
    cert_chain: list[x509.Certificate],
    crls: list[x509.CertificateRevocationList],
    now: datetime.datetime | None = None,
) -> None:
    """Check ``cert_chain`` against locally provided CRLs.

    CRLs that do not match an issuer are ignored; a matching CRL with an
    invalid signature or stale validity is an error.
    """
    if not crls:
        return
    now = now or datetime.datetime.now(datetime.timezone.utc)
    # The root is not checked against a CRL (it is a trust anchor).
    for index, cert in enumerate(cert_chain[:-1]):
        issuer = cert_chain[index + 1]
        for crl in crls:
            if crl.issuer != issuer.subject:
                continue
            try:
                if not crl.is_signature_valid(issuer.public_key()):
                    raise CertificateVerificationError("bad CRL signature")
            except Exception as exc:
                raise CertificateVerificationError("bad CRL signature") from exc
            if crl.last_update_utc > now:
                raise CertificateVerificationError("CRL is not yet valid")
            if crl.next_update_utc is not None and crl.next_update_utc < now:
                raise CertificateVerificationError("CRL has expired")
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
                raise CertificateVerificationError(
                    f"certificate {cert.subject.rfc4514_string()} is revoked (CRL)"
                )


# ---------------------------------------------------------------------------
# Signing (client certificate support)
# ---------------------------------------------------------------------------


def select_signature_scheme(server_algs: list[int], private_key) -> int:
    """Pick a scheme supported by both side's key and the server's list."""
    supported: list[int] = []
    if isinstance(private_key, rsa.RSAPrivateKey):
        supported = [
            SIG_RSA_PSS_RSAE_SHA256,
            SIG_RSA_PSS_RSAE_SHA384,
            SIG_RSA_PSS_RSAE_SHA512,
            SIG_RSA_PKCS1_SHA256,
            SIG_RSA_PKCS1_SHA384,
            SIG_RSA_PKCS1_SHA512,
        ]
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve = private_key.curve
        if isinstance(curve, ec.SECP256R1):
            supported = [SIG_ECDSA_SECP256R1_SHA256]
        elif isinstance(curve, ec.SECP384R1):
            supported = [SIG_ECDSA_SECP384R1_SHA384]
        elif isinstance(curve, ec.SECP521R1):
            supported = [SIG_ECDSA_SECP521R1_SHA512]
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        supported = [SIG_ED25519]
    elif isinstance(private_key, ed448.Ed448PrivateKey):
        supported = [SIG_ED448]
    for scheme in supported:
        if scheme in server_algs:
            return scheme
    raise CertificateVerificationError("no mutually supported signature scheme for client certificate")


def sign_legacy(private_key, data: bytes) -> bytes:
    """Sign a pre-TLS 1.2 CertificateVerify value (RSA MD5||SHA1 / ECDSA SHA1)."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        digest = hashlib.md5(data).digest() + hashlib.sha1(data).digest()
        numbers = private_key.private_numbers()
        size = (numbers.public_numbers.n.bit_length() + 7) // 8
        padding_len = size - len(digest) - 3
        if padding_len < 8:
            raise CertificateVerificationError("RSA key too small for legacy signature")
        encoded = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest
        signature = pow(int.from_bytes(encoded, "big"), numbers.d, numbers.public_numbers.n)
        return signature.to_bytes(size, "big")
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA1()))
    raise CertificateVerificationError("unsupported legacy signing key type")


def sign(private_key, scheme: int, data: bytes) -> bytes:
    if scheme in RSA_PKCS1_SCHEMES:
        h = CRYPTO_HASHES[RSA_PKCS1_SCHEMES[scheme]]()
        return private_key.sign(data, padding.PKCS1v15(), h)
    if scheme in RSA_PSS_SCHEMES:
        h = CRYPTO_HASHES[RSA_PSS_SCHEMES[scheme]]()
        return private_key.sign(
            data, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h
        )
    if scheme in ECDSA_SCHEMES:
        h = CRYPTO_HASHES[ECDSA_SCHEMES[scheme]]()
        return private_key.sign(data, ec.ECDSA(h))
    if scheme == SIG_ED25519:
        return private_key.sign(data)
    if scheme == SIG_ED448:
        return private_key.sign(data)
    raise CertificateVerificationError(f"unsupported signature scheme {scheme:#06x}")


def load_private_key(data: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(data, password=password)


def load_certificate(data: bytes) -> x509.Certificate:
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)
