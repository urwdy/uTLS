"""Record layer unit tests (AEAD, CBC, TLS 1.3 inner content type)."""

from __future__ import annotations

import os
import types
import unittest

from utls.connection import Config, UConn
from utls.constants import (
    CIPHER_SUITES,
    CONTENT_APPLICATION_DATA,
    CONTENT_HANDSHAKE,
    VERSION_TLS12,
    VERSION_TLS13,
)
from utls.crypto import RecordCipher
from utls.errors import RecordError


class RecordLayerTests(unittest.TestCase):
    def _cipher(self, suite_id, mac_len=0):
        suite = CIPHER_SUITES[suite_id]
        key = os.urandom(suite.key_len)
        iv = os.urandom(suite.iv_len)
        mac = os.urandom(mac_len)
        return RecordCipher(suite, key, iv, version=VERSION_TLS12, mac_key=mac)

    def test_tls12_aead_roundtrip(self):
        for suite_id in (0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0x009C, 0x009D):
            with self.subTest(suite=suite_id):
                sender = self._cipher(suite_id)
                receiver = self._cipher(suite_id)
                receiver.key, receiver.iv = sender.key, sender.iv
                receiver.__post_init__()
                sealed = sender.seal_tls12(b"hello", CONTENT_APPLICATION_DATA, VERSION_TLS12)
                self.assertEqual(
                    receiver.open_tls12(sealed, CONTENT_APPLICATION_DATA, VERSION_TLS12),
                    b"hello",
                )

    def test_tls12_cbc_roundtrip_and_tamper(self):
        for suite_id in (0xC013, 0xC014, 0xC023, 0xC027, 0x002F, 0x0035, 0x003C, 0x003D, 0x000A):
            with self.subTest(suite=suite_id):
                suite = CIPHER_SUITES[suite_id]
                sender = self._cipher(suite_id, suite.mac_key_len)
                receiver = self._cipher(suite_id, suite.mac_key_len)
                receiver.key, receiver.iv = sender.key, sender.iv
                receiver.mac_key = sender.mac_key
                receiver.__post_init__()
                payload = b"application data" * 100
                sealed = sender.seal_tls12(payload, CONTENT_APPLICATION_DATA, VERSION_TLS12)
                self.assertEqual(
                    receiver.open_tls12(sealed, CONTENT_APPLICATION_DATA, VERSION_TLS12), payload
                )

                broken = bytearray(sealed)
                broken[-1] ^= 0xFF
                with self.assertRaises(RecordError):
                    self._cipher(suite_id, suite.mac_key_len).open_tls12(
                        bytes(broken), CONTENT_APPLICATION_DATA, VERSION_TLS12
                    )

    def test_tls13_roundtrip(self):
        for suite_id in (0x1301, 0x1302, 0x1303):
            with self.subTest(suite=suite_id):
                suite = CIPHER_SUITES[suite_id]
                sender = RecordCipher(suite, os.urandom(suite.key_len), os.urandom(12))
                receiver = RecordCipher(suite, sender.key, sender.iv)
                sealed = sender.seal_tls13(b"hello", CONTENT_HANDSHAKE)
                header = (
                    bytes([CONTENT_APPLICATION_DATA])
                    + (0x0303).to_bytes(2, "big")
                    + len(sealed).to_bytes(2, "big")
                )
                plaintext, inner = receiver.open_tls13(sealed, header)
                self.assertEqual(plaintext, b"hello")
                self.assertEqual(inner, CONTENT_HANDSHAKE)
                with self.assertRaises(RecordError):
                    receiver.open_tls13(sealed + b"x", header)


class _DummySocket:
    def settimeout(self, timeout):
        pass


class PlaintextRecordTests(unittest.TestCase):
    def _conn(self):
        return UConn(_DummySocket(), Config(server_name="example.test"))

    def test_tls13_rejects_plaintext_after_keys(self):
        conn = self._conn()
        conn._state.version = VERSION_TLS13
        conn._read_cipher = object()
        conn.reader = types.SimpleNamespace(
            read_record=lambda: (CONTENT_HANDSHAKE, 0x0303, b"x")
        )
        with self.assertRaises(RecordError):
            conn._read_decrypted_record()

    def test_tls12_rejects_plaintext_after_ccs(self):
        conn = self._conn()
        conn._state.version = VERSION_TLS12
        conn._tls12_server_ccs_seen = True
        conn._read_cipher = object()
        conn.reader = types.SimpleNamespace(
            read_record=lambda: (24, VERSION_TLS12, b"x")
        )
        with self.assertRaises(RecordError):
            conn._read_decrypted_record()


if __name__ == "__main__":
    unittest.main()
