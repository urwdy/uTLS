"""ClientHelloSpec JSON/raw round-trip tests."""

from __future__ import annotations

import json
import unittest

import utls


class SpecJSONTests(unittest.TestCase):
    def test_round_trip_modern_preset(self):
        spec = utls.utls_id_to_spec(utls.HelloChrome_155)
        payload = spec.to_dict()
        rebuilt = utls.ClientHelloSpec.from_dict(payload)
        self.assertEqual(rebuilt.tls_vers_min, spec.tls_vers_min)
        self.assertEqual(rebuilt.tls_vers_max, spec.tls_vers_max)
        self.assertEqual(rebuilt.cipher_suites, spec.cipher_suites)
        self.assertEqual(
            [ext.type_id for ext in rebuilt.extensions],
            [ext.type_id for ext in spec.extensions],
        )

        text = spec.to_json()
        from_text = utls.ClientHelloSpec.from_json(text)
        self.assertEqual(from_text.cipher_suites, spec.cipher_suites)
        self.assertEqual(len(from_text.extensions), len(spec.extensions))

    def test_extension_payloads_preserved(self):
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        rebuilt = utls.ClientHelloSpec.from_dict(spec.to_dict())
        self.assertIn(0xFE0D, [ext.type_id for ext in rebuilt.extensions])
        key_share = next(
            ext for ext in rebuilt.extensions if ext.type_id == 51
        )
        self.assertTrue(key_share.key_shares)

    def test_fingerprinter_raw_to_spec(self):
        built = utls.build_client_hello(
            utls.utls_id_to_spec(utls.HelloChrome_120),
            server_name="example.test",
        )
        spec = utls.Fingerprinter().FingerprintClientHello(built.raw)
        self.assertIn(0xFE0D, [ext.type_id for ext in spec.extensions])
        self.assertEqual(spec.tls_vers_max, utls.constants.VERSION_TLS13)
        text = utls.Fingerprinter().MarshalJSONClientHello(spec, indent=2)
        self.assertIn("extensions", json.loads(text))

    def test_unknown_extension_preserved(self):
        spec = utls.ClientHelloSpec(
            extensions=[utls.extensions.GenericExtension(0x1234, b"\x01\x02")]
        )
        rebuilt = utls.ClientHelloSpec.from_json(spec.to_json())
        self.assertEqual(rebuilt.extensions[0].type_id, 0x1234)
        self.assertEqual(rebuilt.extensions[0].data, b"\x01\x02")

    def test_psk_is_not_serialized(self):
        spec = utls.ClientHelloSpec(
            extensions=[
                utls.extensions.PreSharedKeyExtension(
                    b"p" * 32, b"ticket", 0, "sha256"
                )
            ]
        )
        with self.assertRaises(ValueError):
            spec.to_dict()


if __name__ == "__main__":
    unittest.main()
