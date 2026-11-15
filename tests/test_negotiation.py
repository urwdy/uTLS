"""Regression tests for server parameter selection checks."""

from __future__ import annotations

import types
import unittest

import utls
from utls.constants import VERSION_TLS12, VERSION_TLS13


class _DummySocket:
    def settimeout(self, timeout):
        pass


class NegotiationTests(unittest.TestCase):
    def setUp(self):
        self.conn = utls.UConn(
            _DummySocket(),
            utls.Config(server_name="localhost", next_protos=["http/1.1"]),
            utls.HelloChrome_120,
        )
        self.conn.build_handshake_state()

    @staticmethod
    def _hello(version=VERSION_TLS13, cipher=0x1301, random=b"\x00" * 32):
        return types.SimpleNamespace(
            selected_version=version, cipher_suite=cipher, random=random
        )

    def test_rejects_unoffered_version(self):
        with self.assertRaises(utls.HandshakeError):
            self.conn._check_negotiation(self._hello(version=0x0300))

    def test_rejects_unoffered_cipher_suite(self):
        with self.assertRaises(utls.HandshakeError):
            self.conn._check_negotiation(self._hello(cipher=0x1305))

    def test_detects_tls12_downgrade_sentinel(self):
        with self.assertRaises(utls.HandshakeError):
            self.conn._check_negotiation(
                self._hello(
                    version=VERSION_TLS12,
                    cipher=0xC02F,
                    random=b"\x00" * 24 + b"DOWNGRD\x01",
                )
            )

    def test_accepts_tls12_server_without_sentinel(self):
        # A TLS 1.2-only server is not required to send the TLS 1.3 sentinel.
        self.conn._check_negotiation(
            self._hello(version=VERSION_TLS12, cipher=0xC02F)
        )

    def test_rejects_unoffered_signature_scheme(self):
        with self.assertRaises(utls.HandshakeError):
            self.conn._check_signature_scheme(0xDEAD)

    def test_rejects_unoffered_alpn(self):
        with self.assertRaises(utls.HandshakeError):
            self.conn._check_alpn("h2")
        self.conn._check_alpn("http/1.1")


if __name__ == "__main__":
    unittest.main()
