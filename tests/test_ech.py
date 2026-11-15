"""Tests for ECH configuration parsing and ClientHello construction."""

from __future__ import annotations

import base64
import hashlib
import socket
import ssl
import types
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

import utls
from utls.ech import (
    ECHConfig,
    ECHConfigError,
    ECHContext,
    build_ech_client_hello,
    build_ech_hrr_client_hello,
    ech_accept_confirmation,
    hrr_accept_confirmation,
    locate_ech_payload,
    parse_ech_config_list,
    zero_ech_extension_payload,
)
from . import support


class _DummySocket:
    def settimeout(self, timeout):
        pass


class _CapturingSocket(_DummySocket):
    def __init__(self):
        self.data = b""

    def sendall(self, data):
        self.data += data


HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


def _synthetic_hrr(ech, *, cookie=b"", group=0x001D, confirmation=b"\x00" * 8):
    extensions = (
        b"\x00\x2b\x00\x02\x03\x04"
        + b"\x00\x33\x00\x02"
        + group.to_bytes(2, "big")
        + b"\xfe\x0d\x00\x08"
        + confirmation
    )
    if cookie:
        extensions += b"\x00\x2c" + len(cookie + b"\x00\x00").to_bytes(2, "big")
        extensions += len(cookie).to_bytes(2, "big") + cookie
    body = (
        b"\x03\x03"
        + HRR_RANDOM
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return b"\x02" + len(body).to_bytes(3, "big") + body


# ECHConfigList advertised by crypto.cloudflare.com at the time of writing.
CLOUDFLARE_ECH = (
    "AEX+DQBBZwAgACBxoBGc3/1oKLHSAwCqwR4DOpLnk96pdk1CvIZFE6fJTQAEAAEAAQAS"
    "Y2xvdWRmbGFyZS1lY2guY29tAAA="
)


def _make_config(**overrides) -> ECHConfig:
    private_key = x25519.X25519PrivateKey.generate()
    values = dict(
        version=0xFE0D,
        config_id=7,
        kem_id=0x0020,
        public_key=private_key.public_key().public_bytes_raw(),
        cipher_suites=((0x0001, 0x0001),),
        maximum_name_length=16,
        public_name="public.example",
    )
    values.update(overrides)
    return ECHConfig(**values)


class ECHConfigTests(unittest.TestCase):
    def test_parse_cloudflare_config(self):
        parsed = parse_ech_config_list(CLOUDFLARE_ECH)
        self.assertEqual(len(parsed.configs), 1)
        config = parsed.configs[0]
        self.assertEqual(config.version, 0xFE0D)
        self.assertEqual(config.kem_id, 0x0020)
        self.assertEqual(config.cipher_suites, ((0x0001, 0x0001),))
        self.assertEqual(config.public_name, "cloudflare-ech.com")
        self.assertEqual(len(config.public_key), 32)
        self.assertTrue(config.supported())

    def test_serialize_round_trip(self):
        raw = base64.b64decode(CLOUDFLARE_ECH)
        parsed = parse_ech_config_list(raw)
        self.assertEqual(parsed.serialize(), raw)
        self.assertEqual(parsed.configs[0].serialize(), raw[2:])

    def test_parse_without_padding_and_token_prefix(self):
        token = "ech=" + CLOUDFLARE_ECH.rstrip("=")
        parsed = parse_ech_config_list(token)
        self.assertEqual(parsed.configs[0].public_name, "cloudflare-ech.com")

    def test_truncated_list_rejected(self):
        raw = base64.b64decode(CLOUDFLARE_ECH)
        with self.assertRaises(ECHConfigError):
            parse_ech_config_list(raw[:-4])

    def test_unknown_mandatory_extension_rejected(self):
        config = _make_config(extensions=((0x8001, b""),))
        self.assertFalse(config.supported())
        # A config with only optional extensions remains usable.
        self.assertTrue(_make_config(extensions=((0x0001, b""),)).supported())

    def test_unsupported_kem_ignored(self):
        raw_config = _make_config().serialize()
        raw_list = len(raw_config).to_bytes(2, "big") + raw_config
        bad = parse_ech_config_list(raw_list.replace(b"\x00\x20", b"\x00\x21", 1))
        self.assertIsNone(bad.select())

    def test_invalid_public_name_rejected(self):
        for name in ("", ".example", "example.", "1.2.3.4", "example.0x7f", "bad_name"):
            with self.subTest(name=name):
                self.assertFalse(_make_config(public_name=name).supported())
        self.assertTrue(_make_config(public_name="cdn.example.com").supported())


class HPKETests(unittest.TestCase):
    def test_seal_matches_cryptography_hpke(self):
        private_key = x25519.X25519PrivateKey.generate()
        config = _make_config(
            public_key=private_key.public_key().public_bytes_raw(),
        )
        context = ECHContext.setup(config)
        ciphertext = context.seal(b"", b"secret message")
        suite = hpke.Suite(
            hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_128_GCM
        )
        plaintext = suite.decrypt(
            context.enc + ciphertext,
            private_key,
            info=b"tls ech\x00" + config.serialize(),
        )
        self.assertEqual(plaintext, b"secret message")

    def test_aead_associated_data_is_authenticated(self):
        context = ECHContext.setup(_make_config())
        ciphertext = context.seal(b"aad", b"payload")
        context.seq = 0
        self.assertEqual(context.open(b"aad", ciphertext), b"payload")
        context.seq = 0
        with self.assertRaises(InvalidTag):
            context.open(b"other", ciphertext)

    def test_p256_and_aes_256_gcm(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        config = _make_config(
            kem_id=0x0010,
            public_key=public_key,
            cipher_suites=((0x0001, 0x0002),),
        )
        context = ECHContext.setup(config)
        ciphertext = context.seal(b"", b"p256 payload")
        suite = hpke.Suite(
            hpke.KEM.P256, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM
        )
        plaintext = suite.decrypt(
            context.enc + ciphertext,
            private_key,
            info=b"tls ech\x00" + config.serialize(),
        )
        self.assertEqual(plaintext, b"p256 payload")


class ECHClientHelloTests(unittest.TestCase):
    def setUp(self):
        self.config = _make_config()
        self.spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        self.ech = build_ech_client_hello(
            self.spec, self.config, server_name="real.example"
        )

    def test_inner_and_outer_hello(self):
        self.assertIn(b"real.example", self.ech.inner_raw)
        self.assertNotIn(b"public.example", self.ech.inner_raw)
        self.assertIn(b"public.example", self.ech.outer_raw)
        self.assertNotIn(b"real.example", self.ech.outer_raw)
        # Outer ECH extension is the outer variant; the inner one is empty.
        self.assertIn(b"\xfe\x0d\x00\x01\x01", self.ech.inner_raw)
        self.assertIn(b"\xfe\x0d", self.ech.outer_raw)

    def test_encoded_inner_has_empty_session_id_and_padding(self):
        encoded = self.ech.encoded_inner
        self.assertEqual(encoded[34], 0)
        self.assertEqual(len(encoded) % 32, 0)

    def test_outer_aad_decrypts_to_encoded_inner(self):
        offset, length = locate_ech_payload(self.ech.outer_built.body)
        body = bytearray(self.ech.outer_built.body)
        payload = bytes(body[offset : offset + length])
        body[offset : offset + length] = b"\x00" * length
        self.ech.context.seq = 0
        self.assertEqual(self.ech.context.open(bytes(body), payload), self.ech.encoded_inner)

    def test_accept_confirmation(self):
        zero_random = b"\x00" * 32
        body = (
            b"\x03\x03"
            + zero_random
            + b"\x00"
            + b"\x13\x01"
            + b"\x00"
            + b"\x00\x00"
        )
        raw = b"\x02" + len(body).to_bytes(3, "big") + body
        confirmation = ech_accept_confirmation(
            self.ech.inner_raw, raw, "sha256", self.ech.inner_random
        )
        random = b"\x00" * 24 + confirmation
        body = b"\x03\x03" + random + b"\x00" + b"\x13\x01" + b"\x00" + b"\x00\x00"
        raw = b"\x02" + len(body).to_bytes(3, "big") + body
        server_hello = types.SimpleNamespace(
            cipher_suite=0x1301, random=random, raw=raw
        )
        self.assertTrue(self.ech.accepts(server_hello))

        rejected = types.SimpleNamespace(
            cipher_suite=0x1301,
            random=b"\x00" * 24 + b"\xff" * 8,
            raw=raw,
        )
        self.assertFalse(self.ech.accepts(rejected))


class ECHPSKTests(unittest.TestCase):
    def setUp(self):
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        spec.extensions.append(
            utls.extensions.PreSharedKeyExtension(
                psk=b"p" * 32,
                ticket=b"real-ticket",
                age_millis=1234,
                hash_name="sha256",
            )
        )
        self.ech = build_ech_client_hello(
            spec, _make_config(), server_name="real.example"
        )

    @staticmethod
    def _psk_body_lengths(body: bytes):
        reader = utls.messages.Reader(body)
        identities = utls.messages.Reader(reader.vec16())
        identity_lens = []
        while len(identities):
            identity_lens.append(len(identities.vec16()))
            identities.take(4)
        binders = utls.messages.Reader(reader.vec16())
        binder_lens = []
        while len(binders):
            binder_lens.append(len(binders.vec8()))
        return identity_lens, binder_lens

    def test_inner_psk_is_real_and_last(self):
        info = utls.parse_client_hello(self.ech.inner_raw)
        self.assertEqual(info.extension_ids[-1], 41)
        ech_index = info.extension_ids.index(0xFE0D)
        self.assertEqual(ech_index, len(info.extension_ids) - 2)
        self.assertIn(b"real-ticket", info.extension_map()[41])
        identity_lens, binder_lens = self._psk_body_lengths(info.extension_map()[41])
        self.assertEqual(identity_lens, [len(b"real-ticket")])
        self.assertEqual(binder_lens, [32])

    def test_outer_omits_psk_and_keeps_ech_last(self):
        info = utls.parse_client_hello(self.ech.outer_raw)
        self.assertEqual(info.extension_ids[-1], 0xFE0D)
        self.assertNotIn(41, info.extension_ids)
        self.assertNotIn(b"real-ticket", self.ech.outer_raw)

    def test_encoded_inner_contains_real_psk(self):
        offset, length = locate_ech_payload(self.ech.outer_built.body)
        body = bytearray(self.ech.outer_built.body)
        payload = bytes(body[offset : offset + length])
        body[offset : offset + length] = b"\x00" * length
        self.ech.context.seq = 0
        encoded = self.ech.context.open(bytes(body), payload)
        self.assertIn(b"real-ticket", encoded)
        self.assertEqual(encoded[34], 0)
        self.assertEqual(len(encoded) % 32, 0)


class ECHEarlyDataTests(unittest.TestCase):
    def setUp(self):
        self.psk = b"p" * 32
        self.ticket = b"early-ticket"
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        spec.extensions.append(utls.extensions.EarlyDataExtension())
        spec.extensions.append(
            utls.extensions.PreSharedKeyExtension(
                psk=self.psk,
                ticket=self.ticket,
                age_millis=42,
                hash_name="sha256",
            )
        )
        self.config = _make_config()
        self.ech = build_ech_client_hello(
            spec, self.config, server_name="real.example"
        )

    def test_extension_ordering(self):
        inner = utls.parse_client_hello(self.ech.inner_raw)
        outer = utls.parse_client_hello(self.ech.outer_raw)
        self.assertLess(inner.extension_ids.index(42), inner.extension_ids.index(0xFE0D))
        self.assertLess(inner.extension_ids.index(0xFE0D), inner.extension_ids.index(41))
        self.assertEqual(inner.extension_ids[-1], 41)
        self.assertIn(42, outer.extension_ids)
        self.assertNotIn(41, outer.extension_ids)
        self.assertEqual(outer.extension_ids[-1], 0xFE0D)

    def test_encoded_inner_contains_early_data_and_psk(self):
        offset, length = locate_ech_payload(self.ech.outer_built.body)
        body = bytearray(self.ech.outer_built.body)
        payload = bytes(body[offset : offset + length])
        body[offset : offset + length] = b"\x00" * length
        self.ech.context.seq = 0
        encoded = self.ech.context.open(bytes(body), payload)
        info = utls.parse_client_hello(encoded)
        self.assertIn(42, info.extension_ids)
        self.assertIn(self.ticket, encoded)
        self.assertEqual(info.extension_ids[-1], 41)

    def test_early_traffic_secret_uses_inner_client_hello(self):
        from utls.crypto import derive_secret, hkdf_extract

        session = utls.SessionState(
            version=0x0304,
            cipher_suite_id=0x1301,
            server_name="real.example",
            ticket=self.ticket,
            psk=self.psk,
            max_early_data=1024,
        )
        config = utls.Config(
            server_name="real.example",
            session=session,
            early_data=b"GET / HTTP/1.1\r\n\r\n",
            ech_config_list=self.config,
        )
        conn = utls.UConn(_DummySocket(), config, utls.HelloChrome_120)
        conn.build_handshake_state()
        self.assertIsNotNone(conn._ech)
        early_secret = hkdf_extract("sha256", b"", self.psk)
        transcript = hashlib.new("sha256", conn._ech.inner_raw).digest()
        expected = derive_secret("sha256", early_secret, "c e traffic", transcript)
        self.assertEqual(conn._early_traffic_secret, expected)
        self.assertIsNotNone(conn._early_write_cipher)


class ECHHRRTests(unittest.TestCase):
    def setUp(self):
        self.config = _make_config()
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        self.first = build_ech_client_hello(
            spec, self.config, server_name="real.example"
        )
        self.cookie = b"retry-cookie"
        hrr_zero = _synthetic_hrr(self.first, cookie=self.cookie)
        self.hrr_raw = hrr_zero
        confirmation = hrr_accept_confirmation(
            self.first.inner_raw, hrr_zero, "sha256", self.first.inner_random
        )
        self.hrr_raw = _synthetic_hrr(
            self.first, cookie=self.cookie, confirmation=confirmation
        )
        self.hrr = types.SimpleNamespace(
            key_share_group=0x001D,
            cookie=self.cookie,
            raw=self.hrr_raw,
            cipher_suite=0x1301,
        )

    def test_zero_confirmation_payload(self):
        zeroed = zero_ech_extension_payload(self.hrr_raw)
        self.assertEqual(len(zeroed), len(self.hrr_raw))
        self.assertIn(b"\xfe\x0d\x00\x08" + b"\x00" * 8, zeroed)
        self.assertNotIn(b"\xfe\x0d\x00\x08" + b"\x00" * 8, self.hrr_raw)

    def test_second_client_hello(self):
        second = build_ech_hrr_client_hello(self.first, self.hrr)
        inner = utls.parse_client_hello(second.inner_raw)
        outer = utls.parse_client_hello(second.outer_raw)
        self.assertEqual(inner.extension_ids[-1], 0xFE0D)
        self.assertIn(44, inner.extension_ids)
        self.assertNotIn(41, inner.extension_ids)
        self.assertNotIn(42, inner.extension_ids)
        self.assertEqual(outer.extension_ids[-1], 0xFE0D)
        self.assertNotIn(41, outer.extension_ids)
        self.assertIn(b"real.example", second.inner_raw)
        self.assertIn(b"public.example", second.outer_raw)
        # The HRR-selected group is used for both key shares.
        for info in (inner, outer):
            key_share = info.extension_map()[51]
            self.assertEqual(key_share[2:4], b"\x00\x1d")

    def test_second_outer_uses_empty_enc_and_fresh_nonce(self):
        second = build_ech_hrr_client_hello(self.first, self.hrr)
        offset, length = locate_ech_payload(second.outer_built.body)
        start = second.outer_built.body.index(b"\xfe\x0d")
        ext_len = int.from_bytes(
            second.outer_built.body[start + 2 : start + 4], "big"
        )
        body = second.outer_built.body[start + 4 : start + 4 + ext_len]
        self.assertEqual(body[0], 0)
        enc_len = int.from_bytes(body[6:8], "big")
        self.assertEqual(enc_len, 0)

        outer_body = bytearray(second.outer_built.body)
        payload = bytes(outer_body[offset : offset + length])
        outer_body[offset : offset + length] = b"\x00" * length
        second.context.seq = 1
        encoded = second.context.open(bytes(outer_body), payload)
        self.assertEqual(encoded, second.encoded_inner)

    def test_accept_confirmation_after_hrr(self):
        second = build_ech_hrr_client_hello(self.first, self.hrr)
        digest = hashlib.sha256(self.first.inner_raw).digest()
        prefix = bytes([254]) + len(digest).to_bytes(3, "big") + digest + self.hrr_raw
        zero_random = b"\x00" * 32
        body = (
            b"\x03\x03"
            + zero_random
            + b"\x00"
            + b"\x13\x01"
            + b"\x00"
            + b"\x00\x00"
        )
        raw = b"\x02" + len(body).to_bytes(3, "big") + body
        confirmation = ech_accept_confirmation(
            prefix + second.inner_raw, raw, "sha256", second.inner_random
        )
        random = b"\x00" * 24 + confirmation
        body = b"\x03\x03" + random + b"\x00" + b"\x13\x01" + b"\x00" + b"\x00\x00"
        raw = b"\x02" + len(body).to_bytes(3, "big") + body
        server_hello = types.SimpleNamespace(
            cipher_suite=0x1301, random=random, raw=raw
        )
        self.assertTrue(second.accepts(server_hello, prefix))

    def test_connection_hrr_wiring(self):
        sock = _CapturingSocket()
        conn = utls.UConn(sock, utls.Config(server_name="real.example"))
        conn._ech = self.first
        conn._ech_hrr_prefix = None
        msg_type, body, total = utls.messages.parse_handshake_header(self.hrr_raw)
        self.assertEqual(msg_type, 2)
        self.assertEqual(total, len(self.hrr_raw))
        sh = utls.messages.parse_server_hello(body, self.hrr_raw)
        conn._handle_ech_hrr(sh)
        self.assertIsNotNone(conn._ech_hrr_prefix)
        self.assertEqual(
            conn._transcript,
            bytearray(conn._ech_hrr_prefix + conn._ech.inner_raw),
        )
        self.assertEqual(conn._client_hello_raw, conn._ech.outer_raw)
        self.assertEqual(conn._session_id, self.first.session_id)
        self.assertTrue(sock.data)
        self.assertEqual(conn._ech.context.seq, 2)


class ECHRejectionTests(unittest.TestCase):
    """A server without ECH support must be treated as a rejection."""

    def setUp(self):
        self.ca = support.make_ca()
        self.cert, self.key = support.issue_cert(self.ca, common_name="localhost")
        self.private_key = x25519.X25519PrivateKey.generate()
        self.ech_config = ECHConfig(
            version=0xFE0D,
            config_id=1,
            kem_id=0x0020,
            public_key=self.private_key.public_key().public_bytes_raw(),
            cipher_suites=((0x0001, 0x0001),),
            maximum_name_length=0,
            public_name="localhost",
        )

    def _server(self):
        server = support.LocalServer(
            self.cert,
            self.key,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            alpn=("http/1.1",),
        )
        self.addCleanup(server.sock.close)
        return server

    def _config(self, *, fallback: bool):
        return utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            next_protos=["http/1.1"],
            ech_config_list=self.ech_config,
            ech_allow_fallback=fallback,
        )

    def test_rejected_ech_can_fall_back_to_outer(self):
        server = self._server()
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        self.addCleanup(sock.close)
        conn = utls.UConn(sock, self._config(fallback=True), utls.HelloChrome_120)
        conn.handshake()
        self.assertIs(conn.connection_state().ech_accepted, False)
        conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn(b"HTTP/1.1", conn.recv())

    def test_rejected_ech_hrr_can_fall_back_to_outer(self):
        server = self._server()
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        self.addCleanup(sock.close)
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        for ext in spec.extensions:
            if isinstance(ext, utls.extensions.KeyShareExtension):
                ext.key_shares = [
                    utls.extensions.KeyShareEntry(utls.constants.GREASE_PLACEHOLDER)
                ]
        conn = utls.UConn(
            sock,
            self._config(fallback=True),
            spec=spec,
        )
        conn.handshake()
        self.assertIs(conn.connection_state().ech_accepted, False)
        conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn(b"HTTP/1.1", conn.recv())

    def test_rejected_ech_hrr_raises_by_default(self):
        server = self._server()
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        self.addCleanup(sock.close)
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        for ext in spec.extensions:
            if isinstance(ext, utls.extensions.KeyShareExtension):
                ext.key_shares = [
                    utls.extensions.KeyShareEntry(utls.constants.GREASE_PLACEHOLDER)
                ]
        conn = utls.UConn(
            sock,
            self._config(fallback=False),
            spec=spec,
        )
        with self.assertRaises(utls.ECHRejectedError):
            conn.handshake()

    def test_rejected_ech_raises_by_default(self):
        server = self._server()
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        self.addCleanup(sock.close)
        conn = utls.UConn(sock, self._config(fallback=False), utls.HelloChrome_120)
        with self.assertRaises(utls.ECHRejectedError):
            conn.handshake()


if __name__ == "__main__":
    unittest.main()
