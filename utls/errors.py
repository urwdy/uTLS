"""Exception types."""

from __future__ import annotations


class UTLSError(Exception):
    """Base class for all uTLS errors."""


class HandshakeError(UTLSError):
    """The TLS handshake failed."""

    def __init__(self, message: str, alert: int | None = None) -> None:
        super().__init__(message)
        self.alert = alert


class AlertError(UTLSError):
    """The peer sent a TLS alert."""

    def __init__(self, description: int, name: str, level: int = 2) -> None:
        super().__init__(f"tls: peer alert {name} ({description})")
        self.description = description
        self.name = name
        self.level = level


class UnsupportedFeatureError(UTLSError):
    """A feature outside the supported subset was requested by the peer."""


class ECHRejectedError(HandshakeError):
    """The server rejected ECH; ``retry_configs`` may replace the keys."""

    def __init__(self, retry_configs: bytes = b"") -> None:
        super().__init__("server rejected ECH", alert=121)
        self.retry_configs = retry_configs


class RecordError(UTLSError):
    """Malformed TLS record."""
