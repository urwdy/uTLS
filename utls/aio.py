"""Asyncio adapter for :class:`utls.connection.UConn`.

The TLS state machine is synchronous; this adapter runs blocking socket I/O in
a worker thread via :func:`asyncio.to_thread`.  It keeps the core unchanged and
allows independent reads and writes to proceed concurrently.
"""

from __future__ import annotations

import asyncio

from .connection import Config, UConn, connect as _connect, wrap_socket as _wrap_socket
from .hello import ClientHelloSpec
from .presets import ClientHelloID


class AsyncUConn:
    """An asyncio-friendly wrapper around a synchronous ``UConn``."""

    def __init__(self, conn: UConn) -> None:
        self._conn = conn
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._handshake_lock = asyncio.Lock()
        self._closed = False

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int = 443,
        *,
        server_name: str | None = None,
        client_hello: ClientHelloID | str | ClientHelloSpec | None = None,
        preset: ClientHelloID | str | ClientHelloSpec | None = None,
        insecure: bool = False,
        alpn: list[str] | None = None,
        timeout: float | None = 30.0,
        config: Config | None = None,
        ech_config_list=None,
    ) -> "AsyncUConn":
        conn = await asyncio.to_thread(
            _connect,
            host,
            port,
            server_name=server_name,
            client_hello=client_hello,
            preset=preset,
            insecure=insecure,
            alpn=alpn,
            timeout=timeout,
            config=config,
            ech_config_list=ech_config_list,
        )
        return cls(conn)

    @classmethod
    async def wrap_socket(
        cls,
        sock,
        server_hostname: str | None = None,
        *,
        config: Config | None = None,
        client_hello: ClientHelloID | str | ClientHelloSpec | None = None,
        insecure: bool = False,
        alpn: list[str] | None = None,
        ech_config_list=None,
    ) -> "AsyncUConn":
        conn = await asyncio.to_thread(
            _wrap_socket,
            sock,
            server_hostname,
            config=config,
            client_hello=client_hello,
            insecure=insecure,
            alpn=alpn,
            ech_config_list=ech_config_list,
        )
        return cls(conn)

    @property
    def conn(self) -> UConn:
        return self._conn

    @property
    def closed(self) -> bool:
        return self._closed

    async def handshake(self) -> None:
        async with self._handshake_lock:
            await asyncio.to_thread(self._conn.handshake)

    async def sendall(self, data: bytes) -> None:
        async with self._write_lock:
            await asyncio.to_thread(self._conn.sendall, data)

    async def write(self, data: bytes) -> int:
        await self.sendall(data)
        return len(data)

    async def send(self, data: bytes) -> int:
        return await self.write(data)

    async def recv(self, bufsize: int = 65536) -> bytes:
        async with self._read_lock:
            return await asyncio.to_thread(self._conn.recv, bufsize)

    async def read(self, n: int | None = None) -> bytes:
        if n is None or n <= 0:
            return await self.recv()
        return await self.recv(n)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        async with self._write_lock:
            await asyncio.to_thread(self._conn.close)

    unwrap = close

    def connection_state(self):
        return self._conn.connection_state()

    def get_client_hello(self) -> bytes:
        return self._conn.get_client_hello()

    def get_peer_certificates(self) -> list[bytes]:
        return self._conn.get_peer_certificates()

    def get_peer_certificate_objects(self):
        return self._conn.get_peer_certificate_objects()

    @property
    def session(self):
        return self._conn.session

    @property
    def server_name(self) -> str:
        return self._conn.server_name

    @property
    def config(self) -> Config:
        return self._conn.config

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_conn"), name)

    async def __aenter__(self) -> "AsyncUConn":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()


async def connect(host: str, port: int = 443, **kwargs) -> AsyncUConn:
    """Async equivalent of :func:`utls.connect`."""
    return await AsyncUConn.connect(host, port, **kwargs)


async def wrap_socket(sock, server_hostname: str | None = None, **kwargs) -> AsyncUConn:
    """Async equivalent of :func:`utls.wrap_socket`."""
    return await AsyncUConn.wrap_socket(sock, server_hostname, **kwargs)


connect_async = connect
wrap_socket_async = wrap_socket

__all__ = [
    "AsyncUConn",
    "connect",
    "connect_async",
    "wrap_socket",
    "wrap_socket_async",
]
