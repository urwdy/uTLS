"""File-like wrappers for :class:`utls.connection.UConn`.

``socket.makefile`` cannot be reused directly because TLS records must go
through the connection's record layer.  The small wrapper here implements the
binary file API needed by ``http.client`` and similar consumers.
"""

from __future__ import annotations

import io


class TLSFile(io.RawIOBase):
    """Buffered-free binary file object backed by a ``UConn``."""

    def __init__(self, conn, mode: str = "rb") -> None:
        super().__init__()
        self._conn = conn
        self._mode = mode
        self._closed = False
        self._buffer = bytearray()

    @property
    def closed(self) -> bool:
        return self._closed

    def readable(self) -> bool:
        return "r" in self._mode

    def writable(self) -> bool:
        return "w" in self._mode or "a" in self._mode

    def seekable(self) -> bool:
        return False

    def fileno(self) -> int:
        if self._closed:
            raise ValueError("I/O operation on closed file")
        return self._conn.fileno()

    def read(self, size: int = -1) -> bytes:
        if not self.readable():
            raise io.UnsupportedOperation("not readable")
        if self._closed:
            raise ValueError("I/O operation on closed file")
        if size == 0:
            return b""
        if size is None or size < 0:
            chunks = [bytes(self._buffer)]
            self._buffer.clear()
            while True:
                chunk = self._conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

        while len(self._buffer) < size:
            chunk = self._conn.recv(65536)
            if not chunk:
                break
            self._buffer += chunk
        out = bytes(self._buffer[:size])
        del self._buffer[: len(out)]
        return out

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def readline(self, size: int = -1) -> bytes:
        if not self.readable():
            raise io.UnsupportedOperation("not readable")
        if self._closed:
            raise ValueError("I/O operation on closed file")
        limit = None if size is None or size < 0 else size
        while b"\n" not in self._buffer:
            if limit is not None and len(self._buffer) >= limit:
                break
            chunk = self._conn.recv(4096)
            if not chunk:
                break
            self._buffer += chunk
        end = self._buffer.find(b"\n")
        if end >= 0:
            end += 1
        else:
            end = len(self._buffer)
        if limit is not None:
            end = min(end, limit)
        out = bytes(self._buffer[:end])
        del self._buffer[:end]
        return out

    def write(self, data) -> int:
        if not self.writable():
            raise io.UnsupportedOperation("not writable")
        if self._closed:
            raise ValueError("I/O operation on closed file")
        if isinstance(data, str):
            data = data.encode()
        self._conn.sendall(bytes(data))
        return len(data)

    def flush(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed file")

    def close(self) -> None:
        self._closed = True
        self._buffer.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()
