"""Certificate chain and hostname verification tests."""

from __future__ import annotations

import datetime
import hashlib
import types
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from utls.constants import SIG_ED448
from utls.ct import certificate_scts
from utls.verify import (
    CertificateVerificationError,
    build_chain,
    check_hostname,
    load_system_roots,
    sign,
    verify_certificate_chain,
    verify_legacy_signature,
    verify_signature,
)

from . import support


class VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = support.make_ca("root")
        cls.intermediate = support.issue_cert(cls.root, "intermediate", is_ca=True)
        cls.leaf, cls.leaf_key = support.issue_cert(cls.intermediate, "localhost")
        cls.expired, _ = support.issue_cert(
            cls.intermediate, "expired.test", not_before_days=-10, not_after_days=-1
        )

    def test_chain_with_intermediate(self):
        chain = verify_certificate_chain(
            [self.leaf, self.intermediate[0]], "localhost", [self.root[0]]
        )
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[-1].subject, self.root[0].subject)

    def test_untrusted_root(self):
        other = support.make_ca("other")
        with self.assertRaises(CertificateVerificationError):
            verify_certificate_chain(
                [self.leaf, self.intermediate[0]], "localhost", [other[0]]
            )

    def test_expired_certificate(self):
        with self.assertRaises(CertificateVerificationError):
            build_chain(self.expired, [self.intermediate[0]], [self.root[0]])

    def test_hostname_mismatch(self):
        with self.assertRaises(CertificateVerificationError):
            verify_certificate_chain(
                [self.leaf, self.intermediate[0]], "wrong.example", [self.root[0]]
            )

    def test_ip_san(self):
        check_hostname(self.leaf, "127.0.0.1")

    def test_non_ca_intermediate_rejected(self):
        bad_intermediate = support.issue_cert(
            self.root, "non-ca-intermediate", is_ca=False
        )
        bad_leaf, _ = support.issue_cert(bad_intermediate, "localhost")
        with self.assertRaises(CertificateVerificationError):
            verify_certificate_chain(
                [bad_leaf, bad_intermediate[0]], "localhost", [self.root[0]]
            )

    def test_client_auth_only_certificate_rejected_as_server(self):
        key = support.new_key()
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            )
            .issuer_name(self.root[0].subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.root[1].public_key()
                ),
                critical=False,
            )
            .sign(self.root[1], hashes.SHA256())
        )
        with self.assertRaises(CertificateVerificationError):
            verify_certificate_chain([cert], "localhost", [self.root[0]])

    def test_wildcard_public_suffix_rejected(self):
        for suffix in ("*.com", "*.co.uk", "*.github.io"):
            with self.subTest(suffix=suffix):
                cert, _ = support.issue_cert(
                    self.intermediate, suffix, dns_names=(suffix,)
                )
                with self.assertRaises(CertificateVerificationError):
                    check_hostname(cert, "example." + suffix[2:])
                with self.assertRaises(CertificateVerificationError):
                    verify_certificate_chain(
                        [cert, self.intermediate[0]],
                        "example." + suffix[2:],
                        [self.root[0]],
                    )

    def test_cross_signed_root(self):
        # A server may send a cross-signed copy of the root in addition to the
        # chain.  The builder must prefer the self-signed trust anchor.
        other = support.make_ca("other CA")
        root_cert, root_key = self.root
        now = datetime.datetime.now(datetime.timezone.utc)
        cross = (
            x509.CertificateBuilder()
            .subject_name(root_cert.subject)
            .issuer_name(other[0].subject)
            .public_key(root_cert.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .sign(other[1], hashes.SHA256())
        )
        chain = build_chain(
            self.leaf, [self.intermediate[0], cross], [root_cert]
        )
        self.assertEqual(chain[-1].subject, root_cert.subject)
        self.assertTrue(chain[-1].issuer == chain[-1].subject)

    def test_wildcard(self):
        cert, _ = support.issue_cert(
            self.intermediate, "*.example.test", dns_names=("*.example.test",)
        )
        check_hostname(cert, "www.example.test")
        with self.assertRaises(CertificateVerificationError):
            check_hostname(cert, "a.b.example.test")

    def test_system_roots_load(self):
        roots = load_system_roots()
        self.assertGreater(len(roots), 0)

    def test_legacy_rsa_signature_rejects_non_ff_padding(self):
        key = support.new_key()
        data = b"legacy signature"
        digest = hashlib.md5(data).digest() + hashlib.sha1(data).digest()
        numbers = key.private_numbers()
        size = (numbers.public_numbers.n.bit_length() + 7) // 8
        padding_len = size - len(digest) - 3
        encoded = (
            b"\x00\x01"
            + b"\x01"
            + b"\xff" * (padding_len - 1)
            + b"\x00"
            + digest
        )
        signature = pow(
            int.from_bytes(encoded, "big"),
            numbers.d,
            numbers.public_numbers.n,
        ).to_bytes(size, "big")
        with self.assertRaises(CertificateVerificationError):
            verify_legacy_signature(key.public_key(), signature, data)

    def test_ed448_signing(self):
        key = ed448.Ed448PrivateKey.generate()
        signature = sign(key, SIG_ED448, b"ed448 data")
        verify_signature(key.public_key(), SIG_ED448, signature, b"ed448 data")
        with self.assertRaises(CertificateVerificationError):
            verify_signature(key.public_key(), SIG_ED448, signature, b"other data")

    def test_sct_list_parsing(self):
        sct_list = b"\x00\x04\x00\x02ab"
        extension = types.SimpleNamespace(value=types.SimpleNamespace(value=sct_list))
        extensions = types.SimpleNamespace(
            get_extension_for_oid=lambda oid: extension
        )
        fake = types.SimpleNamespace(extensions=extensions)
        self.assertEqual(certificate_scts(fake), [b"ab"])
        self.assertEqual(certificate_scts(self.leaf), [])


if __name__ == "__main__":
    unittest.main()
