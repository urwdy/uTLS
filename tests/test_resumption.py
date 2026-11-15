"""Session resumption tests (TLS 1.3 PSK and TLS 1.2 tickets/session IDs)."""

from __future__ import annotations

import os
import ssl
import unittest

import utls
from utls.constants import VERSION_TLS12, VERSION_TLS13

from . import support


class ResumptionTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = support.make_ca()
        cls.server_cert, cls.server_key = support.issue_cert(cls.ca)

    def _config(self, **kwargs):
        return utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            timeout=10,
            **kwargs,
        )

    def _fetch(self, conn):
        conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = b""
        while True:
            try:
                chunk = conn.recv()
            except utls.RecordError:
                break
            if not chunk:
                break
            data += chunk
        return data

    def _run_two(self, version, *, options=0):
        server = support.LocalServer(
            self.server_cert,
            self.server_key,
            min_version=version,
            max_version=version,
            alpn=["http/1.1"],
            connections=2,
            options=options,
        )
        self.addCleanup(server.wait, 10)
        first = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._config(),
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
        )
        self.addCleanup(first.close)
        self.assertIn(b"200 OK", self._fetch(first))
        session = first.session
        self.assertIsNotNone(session)
        first.close()

        second = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._config(session=session),
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
        )
        self.addCleanup(second.close)
        data = self._fetch(second)
        self.assertIn(b"200 OK", data)
        return second, session, server


class TLS13ResumptionTests(ResumptionTestBase):
    def test_psk_resumption(self):
        second, session, server = self._run_two(ssl.TLSVersion.TLSv1_3)
        self.assertEqual(session.version, VERSION_TLS13)
        self.assertTrue(session.ticket)
        self.assertTrue(session.psk)
        self.assertTrue(second.connection_state().did_resume)
        self.assertEqual(second.connection_state().version, VERSION_TLS13)
        server.wait(10)
        self.assertFalse(server.errors, server.errors)

    def test_psk_resumption_with_cache(self):
        cache = utls.ClientSessionCache()
        server = support.LocalServer(
            self.server_cert,
            self.server_key,
            min_version=ssl.TLSVersion.TLSv1_3,
            alpn=["http/1.1"],
            connections=2,
        )
        self.addCleanup(server.wait, 10)
        first = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._config(session_cache=cache),
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
        )
        self.addCleanup(first.close)
        self.assertIn(b"200 OK", self._fetch(first))
        first.close()
        self.assertEqual(len(cache), 1)
        second = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._config(session_cache=cache),
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
        )
        self.addCleanup(second.close)
        self.assertTrue(second.connection_state().did_resume)
        self.assertIn(b"200 OK", self._fetch(second))
        server.wait(10)

    def test_server_ignoring_psk_falls_back(self):
        server = support.LocalServer(
            self.server_cert,
            self.server_key,
            min_version=ssl.TLSVersion.TLSv1_3,
            alpn=["http/1.1"],
            connections=1,
        )
        self.addCleanup(server.wait, 10)
        bogus = utls.SessionState(
            version=VERSION_TLS13,
            cipher_suite_id=0x1301,
            server_name="localhost",
            alpn="http/1.1",
            lifetime=3600,
            ticket=os.urandom(80),
            ticket_age_add=1234,
            psk=os.urandom(32),
        )
        conn = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._config(session=bogus),
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
        )
        self.addCleanup(conn.close)
        self.assertFalse(conn.connection_state().did_resume)
        self.assertTrue(conn.get_peer_certificates())
        self.assertIn(b"200 OK", self._fetch(conn))
        server.wait(10)


class TLS12ResumptionTests(ResumptionTestBase):
    def test_ticket_resumption(self):
        second, session, server = self._run_two(ssl.TLSVersion.TLSv1_2)
        self.assertEqual(session.version, VERSION_TLS12)
        self.assertTrue(session.ticket or session.session_id)
        self.assertTrue(second.connection_state().did_resume)
        self.assertEqual(second.connection_state().version, VERSION_TLS12)
        server.wait(10)
        self.assertFalse(server.errors, server.errors)

    def test_session_id_resumption(self):
        second, session, server = self._run_two(
            ssl.TLSVersion.TLSv1_2, options=ssl.OP_NO_TICKET
        )
        self.assertEqual(session.version, VERSION_TLS12)
        self.assertTrue(session.session_id)
        self.assertTrue(second.connection_state().did_resume)
        server.wait(10)
        self.assertFalse(server.errors, server.errors)

    def test_ticket_resumption_with_cache(self):
        cache = utls.ClientSessionCache()
        server = support.LocalServer(
            self.server_cert,
            self.server_key,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
            alpn=["http/1.1"],
            connections=2,
        )
        self.addCleanup(server.wait, 10)
        first = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._config(session_cache=cache),
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
        )
        self.addCleanup(first.close)
        self.assertIn(b"200 OK", self._fetch(first))
        first.close()
        second = utls.connect(
            "127.0.0.1",
            server.port,
            config=self._config(session_cache=cache),
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
        )
        self.addCleanup(second.close)
        self.assertTrue(second.connection_state().did_resume)
        self.assertIn(b"200 OK", self._fetch(second))
        server.wait(10)


if __name__ == "__main__":
    unittest.main()
