"""CRL and stapled-OCSP revocation verification."""

from __future__ import annotations

import datetime
import os
import ssl
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding

import utls
from utls.ocsp import verify_ocsp_response
from utls.verify import (
    CertificateVerificationError,
    check_crl_revocation,
    crl_distribution_points,
    fetch_url,
    load_crls,
    ocsp_responder_url,
)

from . import support

DATA = os.path.join(os.path.dirname(__file__), "data", "ocsp")


class OCSPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(DATA, "ca.pem"), "rb") as f:
            cls.ca = x509.load_pem_x509_certificate(f.read())
        with open(os.path.join(DATA, "server.pem"), "rb") as f:
            cls.leaf = x509.load_pem_x509_certificate(f.read())
        with open(os.path.join(DATA, "server.key"), "rb") as f:
            cls.key = serialization.load_pem_private_key(f.read(), password=None)

    def _response(self, name):
        with open(os.path.join(DATA, name), "rb") as f:
            return f.read()

    def test_good_response(self):
        verify_ocsp_response(self._response("good.der"), self.leaf, self.ca)

    def test_revoked_response(self):
        with self.assertRaises(CertificateVerificationError):
            verify_ocsp_response(self._response("revoked.der"), self.leaf, self.ca)

    def test_wrong_certificate(self):
        other_ca = support.make_ca()
        other, _ = support.issue_cert(other_ca)
        with self.assertRaises(CertificateVerificationError):
            verify_ocsp_response(self._response("good.der"), other, other_ca[0])

    def test_malformed(self):
        with self.assertRaises(CertificateVerificationError):
            verify_ocsp_response(b"not an ocsp response", self.leaf, self.ca)

    def test_fetch_ocsp_response(self):
        for name, should_fail in (("good.der", False), ("revoked.der", True)):
            with self.subTest(response=name):
                http = support.StaticHTTPServer({"/ocsp": self._response(name)})
                self.addCleanup(http.close)
                server = support.LocalServer(
                    self.leaf, self.key, min_version=ssl.TLSVersion.TLSv1_3
                )
                self.addCleanup(server.wait, 10)
                config = utls.Config(
                    server_name="localhost",
                    root_cas=[support.cert_der(self.ca)],
                    fetch_ocsp=True,
                    ocsp_url=http.url("/ocsp"),
                    allow_private_revocation_urls=True,
                    timeout=10,
                )
                if should_fail:
                    with self.assertRaises(utls.HandshakeError):
                        utls.connect(
                            "127.0.0.1", server.port, config=config, preset=utls.HelloChrome_120
                        )
                else:
                    conn = utls.connect(
                        "127.0.0.1", server.port, config=config, preset=utls.HelloChrome_120
                    )
                    self.addCleanup(conn.close)
                    conn.close()
                server.wait(10)


class CRLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = support.make_ca()
        cls.leaf, cls.leaf_key = support.issue_cert(cls.ca, "revoked.test")

    def _crl(self, revoked_serial=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca[0].subject)
            .last_update(now - datetime.timedelta(days=1))
            .next_update(now + datetime.timedelta(days=30))
        )
        if revoked_serial is not None:
            entry = (
                x509.RevokedCertificateBuilder()
                .serial_number(revoked_serial)
                .revocation_date(now - datetime.timedelta(hours=1))
                .build()
            )
            builder = builder.add_revoked_certificate(entry)
        return builder.sign(self.ca[1], hashes.SHA256())

    def test_revoked(self):
        crl = self._crl(self.leaf.serial_number)
        with self.assertRaises(CertificateVerificationError):
            check_crl_revocation([self.leaf, self.ca[0]], [crl])

    def test_not_revoked(self):
        crl = self._crl()
        check_crl_revocation([self.leaf, self.ca[0]], [crl])

    def test_invalid_signature(self):
        # Re-sign a CRL with a different CA so the issuer name matches but the
        # signature does not.
        other = support.make_ca("other")
        bad = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca[0].subject)
            .last_update(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
            .sign(other[1], hashes.SHA256())
        )
        with self.assertRaises(CertificateVerificationError):
            check_crl_revocation([self.leaf, self.ca[0]], [bad])

    def test_load_pem_and_der(self):
        crl = self._crl()
        self.assertEqual(len(load_crls([crl.public_bytes(Encoding.DER)])), 1)

    def test_certificate_urls(self):
        ca = support.make_ca()
        leaf, _ = support.issue_cert(
            ca,
            "urls.test",
            crl_url="http://crl.example/crl.der",
            ocsp_url="http://ocsp.example/",
        )
        self.assertEqual(crl_distribution_points(leaf), ["http://crl.example/crl.der"])
        self.assertEqual(ocsp_responder_url(leaf), "http://ocsp.example/")

    def test_private_revocation_url_is_blocked_by_default(self):
        with self.assertRaises(CertificateVerificationError):
            fetch_url("http://127.0.0.1:1/crl", timeout=1)
        with self.assertRaises(CertificateVerificationError):
            fetch_url("http://localhost:1/crl", timeout=1)

    def _build_crl(self, ca, revoked_serial=None):
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca[0].subject)
            .last_update(now - datetime.timedelta(days=1))
            .next_update(now + datetime.timedelta(days=30))
        )
        if revoked_serial is not None:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(revoked_serial)
                .revocation_date(now - datetime.timedelta(hours=1))
                .build()
            )
        return builder.sign(ca[1], hashes.SHA256())

    def test_fetch_crls(self):
        for revoked in (False, True):
            with self.subTest(revoked=revoked):
                ca = support.make_ca()
                responses: dict[str, bytes] = {}
                http = support.StaticHTTPServer(responses)
                self.addCleanup(http.close)
                leaf, key = support.issue_cert(ca, "fetched.test", crl_url=http.url("/crl"))
                crl = self._build_crl(ca, leaf.serial_number if revoked else None)
                responses["/crl"] = crl.public_bytes(Encoding.DER)
                self.assertEqual(crl_distribution_points(leaf), [http.url("/crl")])
                server = support.LocalServer(leaf, key, min_version=ssl.TLSVersion.TLSv1_3)
                self.addCleanup(server.wait, 10)
                config = utls.Config(
                    server_name="localhost",
                    root_cas=[support.cert_der(ca[0])],
                    fetch_crls=True,
                    allow_private_revocation_urls=True,
                    timeout=10,
                )
                if revoked:
                    with self.assertRaises(utls.HandshakeError):
                        utls.connect("127.0.0.1", server.port, config=config, preset=utls.HelloChrome_120)
                else:
                    conn = utls.connect(
                        "127.0.0.1", server.port, config=config, preset=utls.HelloChrome_120
                    )
                    self.addCleanup(conn.close)
                    conn.close()
                server.wait(10)

    def test_config_crls_rejects_server(self):
        server = support.LocalServer(
            self.leaf,
            self.leaf_key,
            min_version=ssl.TLSVersion.TLSv1_3,
        )
        self.addCleanup(server.wait, 10)
        crl = self._crl(self.leaf.serial_number)
        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            crls=[crl.public_bytes(Encoding.DER)],
            timeout=10,
        )
        with self.assertRaises(utls.HandshakeError):
            utls.connect("127.0.0.1", server.port, config=config, preset=utls.HelloChrome_120)
        server.wait(10)


if __name__ == "__main__":
    unittest.main()
