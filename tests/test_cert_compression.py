"""Certificate compression decoding (RFC 8879)."""

from __future__ import annotations

import socket
import unittest
import zlib

import utls
from utls.messages import vec16, vec24

from . import support


class CertificateCompressionTests(unittest.TestCase):
    def setUp(self):
        self.ca = support.make_ca()
        self.cert, _ = support.issue_cert(self.ca)
        self.chain_der = [support.cert_der(self.cert)]
        self.conn = utls.UConn(
            socket.socket(), utls.Config(server_name="localhost", insecure_skip_verify=True), utls.HelloGolang
        )
        self.addCleanup(self.conn.sock.close)

    def _certificate_body(self):
        entries = b"".join(vec24(cert) + vec16(b"") for cert in self.chain_der)
        return b"\x00" + vec24(entries)

    def test_zlib(self):
        uncompressed = self._certificate_body()
        compressed = zlib.compress(uncompressed)
        body = (
            (1).to_bytes(2, "big")
            + len(uncompressed).to_bytes(3, "big")
            + len(compressed).to_bytes(3, "big")
            + compressed
        )
        chain = self.conn._parse_compressed_certificate(body, b"raw")
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0].subject, self.cert.subject)
        self.assertEqual(self.conn._peer_cert_der[0], self.chain_der[0])

    def test_unknown_algorithm(self):
        body = (99).to_bytes(2, "big") + (1).to_bytes(3, "big") + (1).to_bytes(3, "big") + b"x"
        with self.assertRaises(utls.UnsupportedFeatureError):
            self.conn._parse_compressed_certificate(body, b"raw")

    def test_brotli_missing_dependency_is_reported(self):
        import importlib.util

        if importlib.util.find_spec("brotli") is None:
            body = (2).to_bytes(2, "big") + (1).to_bytes(3, "big") + (1).to_bytes(3, "big") + b"x"
            with self.assertRaises(utls.UnsupportedFeatureError):
                self.conn._parse_compressed_certificate(body, b"raw")


if __name__ == "__main__":
    unittest.main()
