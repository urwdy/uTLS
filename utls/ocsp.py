"""OCSP stapled-response verification.

Only locally available (stapled) responses are verified; this module does not
perform network fetches.  Revocation checking is opt-in through ``Config``.
"""

from __future__ import annotations

import datetime
import hashlib
import urllib.request

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from .verify import CertificateVerificationError, _check_fetch_url, _open_revocation_url


def fetch_ocsp_response(
    url: str,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    timeout: float = 10.0,
    *,
    allow_private: bool = False,
) -> bytes:
    """Build an OCSP request, POST it to ``url``, and return the response DER."""
    _check_fetch_url(url, allow_private)
    request_der = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, issuer, hashes.SHA1())
        .build()
        .public_bytes(serialization.Encoding.DER)
    )
    request = urllib.request.Request(
        url,
        data=request_der,
        headers={
            "Content-Type": "application/ocsp-request",
            "User-Agent": "uTLS-python",
        },
    )
    try:
        with _open_revocation_url(request, timeout) as response:
            data = response.read(1024 * 1024 + 1)
    except Exception as exc:
        raise CertificateVerificationError(f"failed to query OCSP responder {url}") from exc
    if len(data) > 1024 * 1024:
        raise CertificateVerificationError("OCSP response is too large")
    return data


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _verify_signature(public_key, signature: bytes, data: bytes, hash_alg, oid: str) -> None:
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if oid == "1.2.840.113549.1.1.10":
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size),
                    hash_alg,
                )
            else:
                public_key.verify(signature, data, padding.PKCS1v15(), hash_alg)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hash_alg))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        else:
            raise CertificateVerificationError("unsupported OCSP responder key type")
    except InvalidSignature as exc:
        raise CertificateVerificationError("bad OCSP response signature") from exc


def _signer_certificate(response: ocsp.OCSPResponse):
    certs = list(response.certificates)
    if response.responder_name is not None:
        for cert in certs:
            if cert.subject == response.responder_name:
                return cert
    if response.responder_key_hash is not None:
        for cert in certs:
            spki = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if hashlib.sha1(spki).digest() == response.responder_key_hash:
                return cert
    return None


def _verify_delegated_signer(signer: x509.Certificate, issuer: x509.Certificate) -> None:
    now = _now()
    if signer.not_valid_before_utc > now or signer.not_valid_after_utc < now:
        raise CertificateVerificationError("OCSP responder certificate is not valid")
    try:
        signer.verify_directly_issued_by(issuer)
    except Exception as exc:
        raise CertificateVerificationError("OCSP responder certificate is not issued by the CA") from exc
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CertificateVerificationError("OCSP responder certificate has no OCSP signing usage") from exc
    if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
        raise CertificateVerificationError("OCSP responder certificate has no OCSP signing usage")


def verify_ocsp_response(
    response_der: bytes,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    now: datetime.datetime | None = None,
) -> None:
    """Verify a stapled OCSP response for ``leaf``; raises on any failure."""
    try:
        response = ocsp.load_der_ocsp_response(response_der)
    except ValueError as exc:
        raise CertificateVerificationError("malformed OCSP response") from exc

    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise CertificateVerificationError("OCSP response is not successful")
    if response.serial_number != leaf.serial_number:
        raise CertificateVerificationError("OCSP response is for a different certificate")
    if response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        when = response.revocation_time_utc
        raise CertificateVerificationError(f"certificate is revoked (OCSP, {when})")
    if response.certificate_status != ocsp.OCSPCertStatus.GOOD:
        raise CertificateVerificationError("OCSP response does not confirm a good certificate")

    if response.issuer_name_hash is not None:
        subject_der = issuer.subject.public_bytes(serialization.Encoding.DER)
        if hashlib.sha1(subject_der).digest() != response.issuer_name_hash:
            raise CertificateVerificationError("OCSP issuer name hash mismatch")
    if response.issuer_key_hash is not None:
        public_key = issuer.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_bytes = public_key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.PKCS1
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_bytes = public_key.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
        else:
            key_bytes = public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        if hashlib.sha1(key_bytes).digest() != response.issuer_key_hash:
            raise CertificateVerificationError("OCSP issuer key hash mismatch")

    now = now or _now()
    skew = datetime.timedelta(minutes=5)
    this_update = response.this_update_utc
    next_update = response.next_update_utc
    if this_update is None:
        raise CertificateVerificationError("OCSP response has no thisUpdate time")
    if this_update > now + skew:
        raise CertificateVerificationError("OCSP response is not yet valid")
    if next_update is not None:
        if next_update < now - skew:
            raise CertificateVerificationError("OCSP response has expired")
        if next_update < this_update:
            raise CertificateVerificationError("OCSP response has invalid update times")
    elif this_update < now - datetime.timedelta(hours=24):
        # An OCSP response without nextUpdate must not be replayable forever.
        raise CertificateVerificationError("OCSP response is stale and has no nextUpdate")

    signer = _signer_certificate(response)
    if signer is None:
        signer = issuer
    else:
        issuer_der = issuer.public_bytes(serialization.Encoding.DER)
        signer_der = signer.public_bytes(serialization.Encoding.DER)
        if signer_der == issuer_der:
            signer = issuer
        else:
            _verify_delegated_signer(signer, issuer)

    try:
        hash_alg = response.signature_hash_algorithm
    except UnsupportedAlgorithm:
        hash_alg = None
    if hash_alg is None:
        hash_alg = hashes.SHA256()
    _verify_signature(
        signer.public_key(),
        response.signature,
        response.tbs_response_bytes,
        hash_alg,
        response.signature_algorithm_oid.dotted_string,
    )
