"""Fingerprint helper tests."""

from __future__ import annotations

import unittest

import utls
from utls.fingerprint import describe, ja3, ja3_hash, parse_client_hello
from utls.hello import build_client_hello


class FingerprintTests(unittest.TestCase):
    def test_ja3_from_chrome_120(self):
        raw = build_client_hello(
            utls.utls_id_to_spec(utls.HelloChrome_120), server_name="example.com"
        ).raw
        value = ja3(raw)
        parts = value.split(",")
        self.assertEqual(len(parts), 5)
        # Chrome 120's TLS 1.3 + TLS 1.2 cipher list.
        self.assertTrue(parts[1].startswith("4865-4866-4867-49195-49199"))
        self.assertIn("29-23-24", parts[3])
        self.assertEqual(parts[4], "0")
        self.assertEqual(len(ja3_hash(raw)), 32)

    def test_describe(self):
        raw = build_client_hello(
            utls.utls_id_to_spec(utls.HelloFirefox_120), server_name="example.com"
        ).raw
        info = describe(raw)
        self.assertEqual(info["server_name"], "example.com")
        self.assertIn("h2", info["alpn"])
        self.assertIn("x25519", info["groups"])
        self.assertTrue(info["cipher_suites"][0].startswith("TLS_AES_128_GCM_SHA256"))

    def test_extension_lookup(self):
        raw = build_client_hello(
            utls.utls_id_to_spec(utls.HelloSafari_16_0), server_name="example.com"
        ).raw
        info = parse_client_hello(raw)
        self.assertIn(43, info.extension_map())
        self.assertIsInstance(info.extension_map()[43], bytes)


if __name__ == "__main__":
    unittest.main()
