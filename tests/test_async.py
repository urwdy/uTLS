"""Tests for the asyncio adapter."""

from __future__ import annotations

import socket
import ssl
import unittest

import utls
from . import support


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = support.make_ca()
        cls.cert, cls.key = support.issue_cert(cls.ca, "localhost")

    def _config(self):
        return utls.Config(
            server_name="localhost",
            root_cas=[support.cert_der(self.ca[0])],
            next_protos=["http/1.1"],
            timeout=10,
        )

    def _server(self):
        server = support.LocalServer(
            self.cert,
            self.key,
            min_version=ssl.TLSVersion.TLSv1_3,
            max_version=ssl.TLSVersion.TLSv1_3,
            alpn=["http/1.1"],
        )
        self.addCleanup(server.sock.close)
        return server

    async def _request(self, conn):
        await conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        data = b""
        while True:
            chunk = await conn.recv()
            if not chunk:
                break
            data += chunk
        return data

    async def test_async_connect_and_io(self):
        server = self._server()
        conn = await utls.AsyncUConn.connect(
            "127.0.0.1",
            server.port,
            config=self._config(),
            preset=utls.HelloChrome_120,
        )
        self.addAsyncCleanup(conn.close)
        self.assertIsNotNone(conn.connection_state())
        self.assertIn(b"HTTP/1.1 200 OK", await self._request(conn))
        server.wait(5)

    async def test_async_wrap_socket(self):
        server = self._server()
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        self.addCleanup(sock.close)
        conn = await utls.AsyncUConn.wrap_socket(
            sock,
            "localhost",
            config=self._config(),
            client_hello=utls.HelloChrome_120,
        )
        self.addAsyncCleanup(conn.close)
        self.assertIn(b"HTTP/1.1 200 OK", await self._request(conn))
        server.wait(5)

    async def test_async_context_manager(self):
        server = self._server()
        async with await utls.AsyncUConn.connect(
            "127.0.0.1",
            server.port,
            config=self._config(),
            preset=utls.HelloChrome_120,
        ) as conn:
            self.assertIn(b"HTTP/1.1 200 OK", await self._request(conn))
        server.wait(5)


if __name__ == "__main__":
    unittest.main()
