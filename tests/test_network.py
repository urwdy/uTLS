"""Optional tests against the public internet (set UTLS_NETWORK_TESTS=1)."""

from __future__ import annotations

import json
import os
import unittest

import utls

NETWORK = os.environ.get("UTLS_NETWORK_TESTS") == "1"


@unittest.skipUnless(NETWORK, "set UTLS_NETWORK_TESTS=1 to run network tests")
class NetworkTests(unittest.TestCase):
    def _fetch_peet(self, preset):
        conn = utls.connect(
            "tls.peet.ws",
            443,
            server_name="tls.peet.ws",
            preset=preset,
            alpn=["http/1.1"],
            timeout=20,
        )
        self.addCleanup(conn.close)
        conn.sendall(
            b"GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\n"
            b"User-Agent: uTLS-tests\r\nConnection: close\r\n\r\n"
        )
        data = b""
        while True:
            try:
                chunk = conn.recv()
            except utls.RecordError:
                break
            if not chunk:
                break
            data += chunk
        body = data.split(b"\r\n\r\n", 1)[-1]
        return conn, json.loads(body)

    def test_fingerprint_matches_peer_observation(self):
        for preset in (utls.HelloChrome_120, utls.HelloFirefox_148, utls.HelloSafari_26_3):
            with self.subTest(preset=preset):
                conn, info = self._fetch_peet(preset)
                self.assertTrue(conn.get_peer_certificates())
                self.assertGreaterEqual(conn.connection_state().version, 0x0303)
                self.assertEqual(info["tls"]["ja3"], utls.ja3(conn.get_client_hello()))

    def test_ech_cloudflare(self):
        host = "crypto.cloudflare.com"
        config_list = utls.fetch_ech_config_list(host)
        conn = utls.connect(
            host,
            443,
            server_name=host,
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
            timeout=20,
            ech_config_list=config_list,
        )
        self.addCleanup(conn.close)
        self.assertIs(conn.connection_state().ech_accepted, True)
        conn.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        data = b""
        while True:
            try:
                chunk = conn.recv()
            except utls.RecordError:
                break
            if not chunk:
                break
            data += chunk
        self.assertIn(b"HTTP/1.1", data)

    def test_ech_resumption(self):
        host = "crypto.cloudflare.com"
        config_list = utls.fetch_ech_config_list(host)
        first = utls.connect(
            host,
            443,
            server_name=host,
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
            timeout=20,
            ech_config_list=config_list,
        )
        self.addCleanup(first.close)
        first.sendall(
            f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        while True:
            try:
                chunk = first.recv()
            except utls.RecordError:
                break
            if not chunk:
                break
        session = first.session
        if session is None:
            self.skipTest("server did not issue a session ticket")
        first.close()

        second = utls.connect(
            host,
            443,
            config=utls.Config(
                server_name=host,
                session=session,
                next_protos=["http/1.1"],
                ech_config_list=config_list,
                timeout=20,
            ),
            preset=utls.HelloChrome_120,
        )
        self.addCleanup(second.close)
        self.assertIs(second.connection_state().ech_accepted, True)
        self.assertTrue(second.connection_state().did_resume)

    def test_ech_hello_retry_request(self):
        host = "crypto.cloudflare.com"
        config_list = utls.fetch_ech_config_list(host)
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        for ext in spec.extensions:
            if isinstance(ext, utls.extensions.KeyShareExtension):
                ext.key_shares = [
                    utls.extensions.KeyShareEntry(utls.constants.GREASE_PLACEHOLDER)
                ]
        conn = utls.connect(
            host,
            443,
            server_name=host,
            client_hello=spec,
            alpn=["http/1.1"],
            timeout=20,
            ech_config_list=config_list,
        )
        self.addCleanup(conn.close)
        self.assertIsNotNone(conn._ech_hrr_prefix)
        self.assertIs(conn.connection_state().ech_accepted, True)
        conn.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        self.assertIn(b"HTTP/1.1", conn.recv())

    def test_modern_web_sites(self):
        for host in ("github.com", "www.apple.com"):
            with self.subTest(host=host):
                conn = utls.connect(
                    host,
                    443,
                    server_name=host,
                    preset=utls.HelloChrome_133,
                    alpn=["http/1.1"],
                    timeout=20,
                )
                self.addCleanup(conn.close)
                conn.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )
                data = b""
                while True:
                    try:
                        chunk = conn.recv()
                    except utls.RecordError:
                        break
                    if not chunk:
                        break
                    data += chunk
                self.assertIn(b"HTTP/1.1", data)


if __name__ == "__main__":
    unittest.main()
