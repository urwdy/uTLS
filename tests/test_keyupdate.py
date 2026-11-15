"""TLS 1.3 KeyUpdate handling, exercised with a socketpair."""

from __future__ import annotations

import os
import socket
import unittest

import utls
from utls.constants import CONTENT_APPLICATION_DATA, CONTENT_HANDSHAKE, CIPHER_SUITES, VERSION_TLS13
from utls.crypto import RecordCipher, derive_secret
from utls.messages import make_handshake, parse_handshake_header


class KeyUpdateTests(unittest.TestCase):
    def test_key_update_and_response(self):
        suite = CIPHER_SUITES[0x1301]
        server_secret = os.urandom(32)
        client_secret = os.urandom(32)
        client_sock, server_sock = socket.socketpair()
        self.addCleanup(client_sock.close)
        self.addCleanup(server_sock.close)

        conn = utls.UConn(client_sock, utls.Config(server_name="x", insecure_skip_verify=True), utls.HelloGolang)
        conn._suite = suite
        conn._hash_name = suite.hash
        conn._state.version = VERSION_TLS13
        conn._server_app_secret = server_secret
        conn._client_app_secret = client_secret
        conn._install_app_keys()
        conn._handshake_done = True
        conn._state.handshake_complete = True

        server_read = RecordCipher(
            suite,
            utls.crypto.hkdf_expand_label("sha256", server_secret, "key", b"", suite.key_len),
            utls.crypto.hkdf_expand_label("sha256", server_secret, "iv", b"", 12),
        )
        update = make_handshake(24, b"\x01")
        encrypted = server_read.seal_tls13(update, CONTENT_HANDSHAKE)
        header = (
            bytes([CONTENT_APPLICATION_DATA])
            + (0x0303).to_bytes(2, "big")
            + len(encrypted).to_bytes(2, "big")
        )
        server_sock.sendall(header + encrypted)

        server_secret = derive_secret("sha256", server_secret, "traffic upd", b"")
        new_server_read = RecordCipher(
            suite,
            utls.crypto.hkdf_expand_label("sha256", server_secret, "key", b"", suite.key_len),
            utls.crypto.hkdf_expand_label("sha256", server_secret, "iv", b"", 12),
        )
        payload = new_server_read.seal_tls13(b"hello", CONTENT_APPLICATION_DATA)
        server_sock.sendall(
            bytes([CONTENT_APPLICATION_DATA])
            + (0x0303).to_bytes(2, "big")
            + len(payload).to_bytes(2, "big")
            + payload
        )

        self.assertEqual(conn.recv(), b"hello")

        # The client must answer KeyUpdate(update_requested) with its own
        # KeyUpdate under the *new* client key.
        client_secret = derive_secret("sha256", client_secret, "traffic upd", b"")
        new_client_read = RecordCipher(
            suite,
            utls.crypto.hkdf_expand_label("sha256", client_secret, "key", b"", suite.key_len),
            utls.crypto.hkdf_expand_label("sha256", client_secret, "iv", b"", 12),
        )
        raw = b""
        while len(raw) < 5:
            raw += server_sock.recv(5 - len(raw))
        length = int.from_bytes(raw[3:5], "big")
        body = b""
        while len(body) < length:
            body += server_sock.recv(length - len(body))
        plaintext, inner = new_client_read.open_tls13(body, raw)
        self.assertEqual(inner, CONTENT_HANDSHAKE)
        msg_type, msg_body, _ = parse_handshake_header(plaintext)
        self.assertEqual(msg_type, 24)
        self.assertEqual(msg_body, b"\x00")


if __name__ == "__main__":
    unittest.main()
