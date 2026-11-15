"""Interop tests against a local OpenSSL (Python ssl) TLS server."""

from __future__ import annotations

import ssl
import unittest

import utls
from utls.constants import VERSION_TLS12, VERSION_TLS13
from utls.constants import CIPHER_SUITES
from utls.extensions import KeyShareEntry, KeyShareExtension, SupportedGroupsExtension

from . import support


class TLSTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = support.make_ca()
        cls.server_cert_rsa, cls.server_key_rsa = support.issue_cert(cls.ca, key_type="rsa")
        cls.server_cert_ec, cls.server_key_ec = support.issue_cert(cls.ca, key_type="ec")
        cls.other_ca = support.make_ca("untrusted CA")
        cls.client_cert, cls.client_key = support.issue_cert(cls.ca, "client.test")

    def _connect(self, server_kwargs, preset=utls.HelloChrome_120, config=None, **kwargs):
        server = support.LocalServer(**server_kwargs)
        if config is None:
            config = utls.Config(
                server_name="localhost",
                root_cas=[support.cert_der(self.ca[0])],
                timeout=10,
            )
        conn = utls.connect(
            "127.0.0.1",
            server.port,
            config=config,
            preset=preset,
            timeout=10,
            **kwargs,
        )
        self.addCleanup(server.wait, 5)
        self.addCleanup(conn.close)
        return conn, server

    def _request(self, conn):
        conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = b""
        while True:
            chunk = conn.recv()
            if not chunk:
                break
            data += chunk
        return data

    def _legacy_config(self, **kwargs):
        return utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            timeout=10,
            allow_legacy_ciphers=True,
            allow_rsa_key_exchange=True,
            **kwargs,
        )


class TLS13Tests(TLSTestBase):
    def test_presets(self):
        presets = [
            utls.HelloChrome_120,
            utls.HelloChrome_133,
            utls.HelloChrome_155,
            utls.HelloChrome_70,
            utls.HelloChrome_106_Shuffle,
            utls.HelloFirefox_120,
            utls.HelloFirefox_148,
            utls.HelloFirefox_99,
            utls.HelloFirefox_105,
            utls.HelloSafari_16_0,
            utls.HelloSafari_26_3,
            utls.HelloIOS_14,
            utls.HelloIOS_13,
            utls.HelloEdge_106,
            utls.HelloEdge_85,
            utls.HelloGolang,
            utls.Hello360_11_0,
            utls.HelloQQ_11_1,
        ]
        for preset in presets:
            with self.subTest(preset=preset):
                server_kwargs = dict(
                    server_cert=self.server_cert_rsa,
                    server_key=self.server_key_rsa,
                    min_version=ssl.TLSVersion.TLSv1_3,
                    max_version=ssl.TLSVersion.TLSv1_3,
                )
                conn, server = self._connect(server_kwargs, preset, alpn=["http/1.1"])
                self.assertEqual(conn.connection_state().version, VERSION_TLS13)
                self.assertIn(conn.connection_state().cipher_suite_id, (0x1301, 0x1302, 0x1303))
                data = self._request(conn)
                self.assertIn(b"HTTP/1.1 200 OK", data)
                server.wait(5)
                self.assertFalse(server.errors, server.errors)

    def test_socket_compatibility(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            alpn=["http/1.1"],
        )
        conn, server = self._connect(server_kwargs, preset=utls.HelloChrome_120)
        self.assertGreater(conn.fileno(), 0)
        self.assertIsNotNone(conn.gettimeout())
        conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        with conn.makefile("rb") as stream:
            self.assertIn(b"HTTP/1.1 200 OK", stream.readline())
            self.assertIn(b"ok", stream.read())
        conn.close()
        server.wait(5)

    def test_keylog_and_verify_callback(self):
        keylog = []
        verified = []

        def writer(line):
            keylog.append(line)

        def verify(chain, name):
            verified.append((len(chain), name))

        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            alpn=["http/1.1"],
        )
        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            next_protos=["http/1.1"],
            keylog_writer=writer,
            verify_peer_certificate=verify,
            timeout=10,
        )
        conn, server = self._connect(server_kwargs, config=config)
        self.assertIn(b"HTTP/1.1 200 OK", self._request(conn))
        self.assertTrue(verified)
        self.assertEqual(verified[0][1], "localhost")
        self.assertTrue(
            any(line.startswith("CLIENT_HANDSHAKE_TRAFFIC_SECRET ") for line in keylog)
        )
        self.assertTrue(
            any(line.endswith("\n") and len(line.split()) == 3 for line in keylog)
        )
        server.wait(5)

    def test_verify_connection_callback_and_go_aliases(self):
        seen = []

        def verify(conn):
            seen.append(conn.connection_state().handshake_complete)

        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            next_protos=["http/1.1"],
            timeout=10,
        )
        config.VerifyConnection = verify
        config.MinVersion = utls.constants.VERSION_TLS12
        config.MaxVersion = utls.constants.VERSION_TLS13
        self.assertEqual(config.MinVersion, utls.constants.VERSION_TLS12)
        self.assertEqual(config.MaxVersion, utls.constants.VERSION_TLS13)
        self.assertIs(config.VerifyConnection, verify)
        mapped = utls.Config.from_go(
            ServerName="mapped.test",
            MinVersion=utls.constants.VERSION_TLS12,
        )
        self.assertEqual(mapped.server_name, "mapped.test")
        self.assertEqual(mapped.min_version, utls.constants.VERSION_TLS12)
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            alpn=["http/1.1"],
        )
        conn, server = self._connect(server_kwargs, config=config)
        self.assertIn(b"HTTP/1.1 200 OK", self._request(conn))
        self.assertEqual(seen, [True])
        server.wait(5)

    def test_client_certificate_callback_tls13(self):
        cert, key = support.issue_cert(self.ca, "callback.test")
        seen = []

        def select(acceptable_cas, signature_algorithms):
            seen.append((list(acceptable_cas), list(signature_algorithms)))
            return [support.cert_pem(cert)], support.key_pem(key)

        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            client_ca=self.ca[0],
            require_client_cert=True,
            alpn=["http/1.1"],
        )
        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            next_protos=["http/1.1"],
            get_client_certificate=select,
            timeout=10,
        )
        conn, server = self._connect(server_kwargs, config=config)
        self.assertIn(b"HTTP/1.1 200 OK", self._request(conn))
        self.assertTrue(seen)
        self.assertTrue(seen[0][1])
        server.wait(5)
        self.assertIn("callback.test", str(server.info.get("peer_cert")))

    def test_client_certificate_callback_can_decline(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            client_ca=self.ca[0],
            require_client_cert=False,
            alpn=["http/1.1"],
        )
        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            next_protos=["http/1.1"],
            get_client_certificate=lambda cas, algs: None,
            timeout=10,
        )
        conn, server = self._connect(server_kwargs, config=config)
        self.assertIn(b"HTTP/1.1 200 OK", self._request(conn))
        server.wait(5)

    def test_truncated_connection_is_rejected(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            alpn=["http/1.1"],
            clean_close=False,
        )
        conn, server = self._connect(server_kwargs, preset=utls.HelloChrome_120)
        conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn(b"HTTP/1.1 200 OK", conn.recv())
        with self.assertRaises(utls.RecordError):
            conn.recv()
        server.wait(5)

    def test_randomized_preset(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_3,
        )
        conn, server = self._connect(
            server_kwargs, utls.HelloRandomized, alpn=["http/1.1"]
        )
        self.assertIn(conn.connection_state().version, (VERSION_TLS12, VERSION_TLS13))
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(5)

    def test_ecdsa_server_certificate(self):
        server_kwargs = dict(
            server_cert=self.server_cert_ec,
            server_key=self.server_key_ec,
            min_version=ssl.TLSVersion.TLSv1_3,
        )
        conn, server = self._connect(server_kwargs, utls.HelloChrome_133, alpn=["http/1.1"])
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(5)
        self.assertFalse(server.errors, server.errors)

    def test_alpn(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            alpn=("h2", "http/1.1"),
            min_version=ssl.TLSVersion.TLSv1_3,
        )
        conn, server = self._connect(server_kwargs, utls.HelloFirefox_148, alpn=["http/1.1"])
        self.assertEqual(conn.connection_state().alpn_protocol, "http/1.1")
        self._request(conn)
        server.wait(5)
        self.assertEqual(server.info.get("alpn"), "http/1.1")

    def test_large_response(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            response=b"y" * 100000,
        )
        conn, server = self._connect(server_kwargs, utls.HelloChrome_120, alpn=["http/1.1"])
        conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = b""
        while True:
            chunk = conn.recv()
            if not chunk:
                break
            data += chunk
        self.assertEqual(len(data), 100000)
        server.wait(5)

    def test_forced_tls12(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_3,
        )
        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            max_version=VERSION_TLS12,
            timeout=10,
        )
        conn, server = self._connect(
            server_kwargs, utls.HelloChrome_133, config=config, alpn=["http/1.1"]
        )
        self.assertEqual(conn.connection_state().version, VERSION_TLS12)
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(5)

    def test_hello_retry_request(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            ecdh_curve="prime256v1",
        )
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        for ext in spec.extensions:
            if isinstance(ext, KeyShareExtension):
                ext.key_shares = [KeyShareEntry(utls.constants.GROUP_X25519)]
            if isinstance(ext, SupportedGroupsExtension):
                ext.curves = [utls.constants.GROUP_X25519, utls.constants.GROUP_SECP256R1]
        conn, server = self._connect(
            server_kwargs, client_hello=spec, alpn=["http/1.1"]
        )
        self.assertEqual(conn.connection_state().version, VERSION_TLS13)
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(5)


class TLS12Tests(TLSTestBase):
    def test_presets(self):
        presets = [
            utls.HelloChrome_120,
            utls.HelloChrome_133,
            utls.HelloChrome_155,
            utls.HelloChrome_58,
            utls.HelloChrome_70,
            utls.HelloChrome_106_Shuffle,
            utls.HelloFirefox_120,
            utls.HelloFirefox_148,
            utls.HelloFirefox_55,
            utls.HelloFirefox_99,
            utls.HelloSafari_16_0,
            utls.HelloIOS_14,
            utls.HelloIOS_11_1,
            utls.HelloIOS_13,
            utls.HelloAndroid_11_OkHttp,
            utls.HelloEdge_106,
            utls.HelloEdge_85,
            utls.HelloGolang,
            utls.Hello360_7_5,
            utls.Hello360_11_0,
            utls.HelloQQ_11_1,
        ]
        for preset in presets:
            with self.subTest(preset=preset):
                server_kwargs = dict(
                    server_cert=self.server_cert_rsa,
                    server_key=self.server_key_rsa,
                    min_version=ssl.TLSVersion.TLSv1_2,
                    max_version=ssl.TLSVersion.TLSv1_2,
                )
                conn, server = self._connect(
                    server_kwargs,
                    preset,
                    config=self._legacy_config(),
                    alpn=["http/1.1"],
                )
                self.assertEqual(conn.connection_state().version, VERSION_TLS12)
                data = self._request(conn)
                self.assertIn(b"HTTP/1.1 200 OK", data)
                server.wait(5)
                self.assertFalse(server.errors, server.errors)

    def test_cbc_and_rsa_key_exchange(self):
        cases = [
            ("ECDHE-RSA-AES128-SHA", 0xC013),
            ("ECDHE-RSA-AES256-SHA", 0xC014),
            ("ECDHE-RSA-AES128-SHA256", 0xC027),
            ("AES128-SHA", 0x002F),
            ("AES256-SHA", 0x0035),
            ("AES128-GCM-SHA256", 0x009C),
        ]
        for cipher, suite_id in cases:
            with self.subTest(cipher=cipher):
                server_kwargs = dict(
                    server_cert=self.server_cert_rsa,
                    server_key=self.server_key_rsa,
                    min_version=ssl.TLSVersion.TLSv1_2,
                    max_version=ssl.TLSVersion.TLSv1_2,
                    ciphers=cipher,
                )
                conn, server = self._connect(
                    server_kwargs,
                    utls.HelloIOS_14,
                    config=self._legacy_config(),
                    alpn=["http/1.1"],
                )
                self.assertEqual(conn.connection_state().version, VERSION_TLS12)
                self.assertEqual(conn.connection_state().cipher_suite_id, suite_id)
                self.assertIn(b"200 OK", self._request(conn))
                server.wait(5)
                self.assertFalse(server.errors, server.errors)

    def test_ems_and_cipher_suites(self):
        for preset in (utls.HelloChrome_120, utls.HelloFirefox_120):
            with self.subTest(preset=preset):
                server_kwargs = dict(
                    server_cert=self.server_cert_ec,
                    server_key=self.server_key_ec,
                    min_version=ssl.TLSVersion.TLSv1_2,
                    max_version=ssl.TLSVersion.TLSv1_2,
                )
                conn, server = self._connect(server_kwargs, preset, alpn=["http/1.1"])
                suite = CIPHER_SUITES[conn.connection_state().cipher_suite_id]
                self.assertIn(suite.aead, {"aes-gcm", "chacha20-poly1305"})
                self.assertIn(b"200 OK", self._request(conn))
                server.wait(5)


class VerificationTests(TLSTestBase):
    def _server(self):
        return dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
        )

    def test_custom_ca_success(self):
        conn, server = self._connect(self._server(), alpn=["http/1.1"])
        self.assertTrue(conn.get_peer_certificates())
        self._request(conn)
        server.wait(5)

    def test_untrusted_root_rejected(self):
        config = utls.Config(
            server_name="localhost", root_cas=[support.cert_der(self.other_ca[0])], timeout=10
        )
        with self.assertRaises(utls.HandshakeError):
            self._connect(self._server(), config=config, alpn=["http/1.1"])

    def test_hostname_mismatch_rejected(self):
        config = utls.Config(
            server_name="wrong.example", root_cas=[support.cert_der(self.ca[0])], timeout=10
        )
        with self.assertRaises(utls.HandshakeError):
            self._connect(self._server(), config=config, alpn=["http/1.1"])

    def test_insecure_skip_verify(self):
        config = utls.Config(server_name="wrong.example", insecure_skip_verify=True, timeout=10)
        conn, server = self._connect(
            self._server(), config=config, alpn=["http/1.1"]
        )
        self.assertTrue(conn.get_peer_certificates())
        self._request(conn)
        server.wait(5)


class ClientAuthTests(TLSTestBase):
    def _client_config(self):
        return utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            client_cert_chain=[support.cert_pem(self.client_cert)],
            client_private_key=support.key_pem(self.client_key),
            timeout=10,
        )

    def test_tls13_client_certificate(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            client_ca=self.ca[0],
            require_client_cert=True,
        )
        conn, server = self._connect(
            server_kwargs, utls.HelloChrome_133, config=self._client_config(), alpn=["http/1.1"]
        )
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(5)
        self.assertIn("client.test", str(server.info.get("peer_cert")))

    def test_tls13_ecdsa_client_certificate(self):
        client_cert, client_key = support.issue_cert(self.ca, "client-ec.test", key_type="ec")
        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            client_cert_chain=[support.cert_pem(client_cert)],
            client_private_key=support.key_pem(client_key),
            timeout=10,
        )
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_3,
            client_ca=self.ca[0],
            require_client_cert=True,
        )
        conn, server = self._connect(
            server_kwargs, utls.HelloChrome_133, config=config, alpn=["http/1.1"]
        )
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(5)
        self.assertIn("client-ec.test", str(server.info.get("peer_cert")))

    def test_tls12_client_certificate(self):
        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
            client_ca=self.ca[0],
            require_client_cert=True,
        )
        conn, server = self._connect(
            server_kwargs, utls.HelloFirefox_120, config=self._client_config(), alpn=["http/1.1"]
        )
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(5)
        self.assertIn("client.test", str(server.info.get("peer_cert")))

    def test_tls12_client_certificate_callback(self):
        cert, key = support.issue_cert(self.ca, "tls12-callback.test")
        seen = []

        def select(acceptable_cas, signature_algorithms):
            seen.append((list(acceptable_cas), list(signature_algorithms)))
            return [support.cert_der(cert)], support.key_pem(key)

        server_kwargs = dict(
            server_cert=self.server_cert_rsa,
            server_key=self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
            client_ca=self.ca[0],
            require_client_cert=True,
        )
        config = utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            get_client_certificate=select,
            timeout=10,
        )
        conn, server = self._connect(
            server_kwargs, utls.HelloFirefox_120, config=config, alpn=["http/1.1"]
        )
        self.assertIn(b"200 OK", self._request(conn))
        self.assertTrue(seen)
        server.wait(5)
        self.assertIn("tls12-callback.test", str(server.info.get("peer_cert")))


class LegacyTLSTests(TLSTestBase):
    def _legacy_spec(self, version):
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        spec.tls_vers_min = version
        spec.tls_vers_max = version
        spec.extensions = [
            ext for ext in spec.extensions if getattr(ext, "type_id", None) != 43
        ]
        return spec

    def test_tls10_and_tls11(self):
        cases = [
            (ssl.TLSVersion.TLSv1, utls.constants.VERSION_TLS10, "AES128-SHA:@SECLEVEL=0", 0x002F),
            (ssl.TLSVersion.TLSv1, utls.constants.VERSION_TLS10, "ECDHE-RSA-AES128-SHA:@SECLEVEL=0", 0xC013),
            (ssl.TLSVersion.TLSv1_1, utls.constants.VERSION_TLS11, "AES128-SHA:@SECLEVEL=0", 0x002F),
            (ssl.TLSVersion.TLSv1_1, utls.constants.VERSION_TLS11, "ECDHE-RSA-AES128-SHA:@SECLEVEL=0", 0xC013),
        ]
        for ssl_version, tls_version, cipher, suite_id in cases:
            with self.subTest(version=hex(tls_version), cipher=cipher):
                server = support.LocalServer(
                    self.server_cert_rsa,
                    self.server_key_rsa,
                    min_version=ssl_version,
                    max_version=ssl_version,
                    ciphers=cipher,
                    alpn=["http/1.1"],
                )
                self.addCleanup(server.wait, 10)
                conn = utls.connect(
                    "127.0.0.1",
                    server.port,
                    config=self._legacy_config(),
                    client_hello=self._legacy_spec(tls_version),
                    alpn=["http/1.1"],
                )
                self.addCleanup(conn.close)
                self.assertEqual(conn.connection_state().version, tls_version)
                self.assertEqual(conn.connection_state().cipher_suite_id, suite_id)
                self.assertIn(b"200 OK", self._request(conn))
                server.wait(10)
                self.assertFalse(server.errors, server.errors)

    def test_tls10_resumption(self):
        server = support.LocalServer(
            self.server_cert_rsa,
            self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1,
            max_version=ssl.TLSVersion.TLSv1,
            ciphers="AES128-SHA:@SECLEVEL=0",
            connections=2,
            alpn=["http/1.1"],
        )
        self.addCleanup(server.wait, 10)
        spec = self._legacy_spec(utls.constants.VERSION_TLS10)
        first = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._legacy_config(),
            client_hello=spec,
            alpn=["http/1.1"],
        )
        self.addCleanup(first.close)
        self._request(first)
        session = first.session
        self.assertIsNotNone(session)
        first.close()
        second = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._legacy_config(session=session),
            client_hello=spec,
            alpn=["http/1.1"],
        )
        self.addCleanup(second.close)
        self.assertTrue(second.connection_state().did_resume)
        self.assertIn(b"200 OK", self._request(second))
        server.wait(10)
        self.assertFalse(server.errors, server.errors)

    def test_tls10_client_certificate(self):
        server = support.LocalServer(
            self.server_cert_rsa,
            self.server_key_rsa,
            min_version=ssl.TLSVersion.TLSv1,
            max_version=ssl.TLSVersion.TLSv1,
            ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0",
            client_ca=self.ca[0],
            require_client_cert=True,
            alpn=["http/1.1"],
        )
        self.addCleanup(server.wait, 10)
        client_cert, client_key = support.issue_cert(self.ca, "legacy-client.test")
        conn = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._legacy_config(
                client_cert_chain=[support.cert_pem(client_cert)],
                client_private_key=support.key_pem(client_key),
            ),
            client_hello=self._legacy_spec(utls.constants.VERSION_TLS10),
            alpn=["http/1.1"],
        )
        self.addCleanup(conn.close)
        self.assertIn(b"200 OK", self._request(conn))
        server.wait(10)
        self.assertIn("legacy-client.test", str(server.info.get("peer_cert")))


if __name__ == "__main__":
    unittest.main()
