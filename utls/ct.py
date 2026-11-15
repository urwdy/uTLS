"""Certificate Transparency extension parsing helpers.

Full SCT log verification requires an application-supplied log list and policy;
this module exposes the raw SCTs so callers can plug in a verifier through
``Config.sct_verifier``.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

SCT_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")

_HASH_IDS = {"sha1": 2, "sha256": 4, "sha384": 5, "sha512": 6}
_SIG_IDS = {"RSA": 1, "DSA": 2, "ECDSA": 3}


def _vec16(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def _sct_to_bytes(sct) -> bytes:
    version = getattr(sct.version, "value", 0)
    log_id = bytes(sct.log_id)
    timestamp = int(sct.timestamp.timestamp() * 1000)
    extensions = bytes(getattr(sct, "extension_bytes", b"") or b"")
    sig_name = getattr(sct.signature_algorithm, "name", "")
    sig_id = next((value for name, value in _SIG_IDS.items() if name in sig_name), 0)
    hash_id = _HASH_IDS.get(sct.signature_hash_algorithm.name, 0)
    signature = bytes(sct.signature)
    return (
        bytes([version])
        + log_id
        + timestamp.to_bytes(8, "big")
        + _vec16(extensions)
        + bytes([hash_id, sig_id])
        + _vec16(signature)
    )


def certificate_scts(cert: x509.Certificate) -> list[bytes]:
    """Return raw SignedCertificateTimestamp values from ``cert``."""
    try:
        extension = cert.extensions.get_extension_for_oid(SCT_OID)
    except (x509.ExtensionNotFound, ValueError):
        return []
    value = extension.value
    if isinstance(
        value,
        (
            x509.SignedCertificateTimestamps,
            x509.PrecertificateSignedCertificateTimestamps,
        ),
    ):
        return [_sct_to_bytes(sct) for sct in value]
    data = getattr(value, "value", b"")
    if len(data) < 2:
        return []
    total = int.from_bytes(data[:2], "big")
    if total > len(data) - 2:
        return []
    pos = 2
    end = 2 + total
    result = []
    while pos + 2 <= end:
        length = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        if pos + length > end:
            return []
        result.append(data[pos : pos + length])
        pos += length
    return result
