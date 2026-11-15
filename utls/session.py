"""TLS session state used for resumption (TLS 1.2 tickets and TLS 1.3 PSK)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .constants import VERSION_TLS12, VERSION_TLS13


@dataclass
class SessionState:
    """A resumable session handed out by the server.

    The object contains key material; treat it like a password.  It can be
    stored by the application and passed back via ``Config.session`` to resume
    a later connection to the same server.
    """

    version: int
    cipher_suite_id: int
    server_name: str = ""
    alpn: str | None = None
    created_at: float = field(default_factory=time.time)
    lifetime: int = 0  # seconds, 0 = no explicit expiry
    ticket: bytes = b""
    session_id: bytes = b""
    ems: bool = False
    ticket_age_add: int = 0
    ticket_nonce: bytes = b""
    max_early_data: int = 0
    master_secret: bytes | None = field(default=None, repr=False)
    psk: bytes | None = field(default=None, repr=False)

    @property
    def is_tls13(self) -> bool:
        return self.version == VERSION_TLS13

    def is_expired(self) -> bool:
        if self.lifetime <= 0:
            return False
        return time.time() > self.created_at + self.lifetime

    def age_millis(self) -> int:
        return max(0, int((time.time() - self.created_at) * 1000))


__all__ = ["SessionState", "ClientSessionCache", "VERSION_TLS12", "VERSION_TLS13"]


class ClientSessionCache:
    """Small thread-safe LRU cache for :class:`SessionState` objects.

    Keys are server names; ALPN and certificate checks are performed when the
    cached session is actually used.
    """

    def __init__(self, max_entries: int = 64) -> None:
        from collections import OrderedDict
        import threading

        self.max_entries = max(1, max_entries)
        self._entries: "OrderedDict[str, SessionState]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> SessionState | None:
        with self._lock:
            session = self._entries.get(key)
            if session is None:
                return None
            if session.is_expired():
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return session

    def put(self, key: str, session: SessionState) -> None:
        with self._lock:
            self._entries[key] = session
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
