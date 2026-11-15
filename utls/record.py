"""TLS record layer framing."""

from __future__ import annotations

import struct

from .errors import RecordError

MAX_PLAINTEXT = 16384
MAX_CIPHERTEXT = MAX_PLAINTEXT + 2048

u16 = struct.Struct("!H")


class RecordReader:
    def __init__(self, sock) -> None:
        self.sock = sock
        self.buffer = bytearray()

    def _recv_more(self, n: int) -> bytes:
        chunks = []
        while n > 0:
            try:
                chunk = self.sock.recv(n)
            except InterruptedError:
                continue
            if not chunk:
                raise EOFError("connection closed by peer")
            chunks.append(chunk)
            n -= len(chunk)
        return b"".join(chunks)

    def read_record(self) -> tuple[int, int, bytes]:
        header = bytes(self._recv_more(5))
        content_type, version, length = header[0], int.from_bytes(header[1:3], "big"), int.from_bytes(header[3:5], "big")
        if length > MAX_CIPHERTEXT:
            raise RecordError(f"record too large: {length}")
        payload = self._recv_more(length) if length else b""
        return content_type, version, payload


def send_record(sock, content_type: int, version: int, payload: bytes) -> None:
    if len(payload) > MAX_PLAINTEXT:
        raise RecordError("record payload too large")
    header = bytes([content_type]) + u16.pack(version) + u16.pack(len(payload))
    sock.sendall(header + payload)


def send_records(sock, content_type: int, version: int, payload: bytes) -> None:
    """Split ``payload`` into max-sized TLS records."""
    for i in range(0, len(payload), MAX_PLAINTEXT):
        send_record(sock, content_type, version, payload[i : i + MAX_PLAINTEXT])


def encode_plaintext_record(content_type: int, version: int, payload: bytes) -> bytes:
    return bytes([content_type]) + u16.pack(version) + u16.pack(len(payload)) + payload
