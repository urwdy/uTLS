"""TLS 1.3 0-RTT / early data tests against OpenSSL s_server."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

import utls
from utls.crypto import derive_secret, hkdf_extract

from . import support


def _openssl_binary() -> str | None:
    candidates = [
        os.environ.get("OPENSSL"),
        shutil.which("openssl"),
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        "/usr/bin/openssl",
        "/usr/local/bin/openssl",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


@unittest.skipUnless(_openssl_binary(), "OpenSSL binary is required")
class EarlyDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="utls-early-")
        ca = support.make_ca()
        cert, key = support.issue_cert(ca)
        cls.cert_path = os.path.join(cls.tmp, "cert.pem")
        cls.key_path = os.path.join(cls.tmp, "key.pem")
        cls.keylog_path = os.path.join(cls.tmp, "keylog.txt")
        cls.stderr_path = os.path.join(cls.tmp, "server.err")
        with open(cls.cert_path, "wb") as f:
            f.write(support.cert_pem(cert))
        with open(cls.key_path, "wb") as f:
            f.write(support.key_pem(key))
        with open(cls.keylog_path, "w"):
            pass
        cls.stderr_file = open(cls.stderr_path, "w")

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        cls.port = sock.getsockname()[1]
        sock.close()
        cls.proc = subprocess.Popen(
            [
                _openssl_binary(),
                "s_server",
                "-accept",
                f"127.0.0.1:{cls.port}",
                "-cert",
                cls.cert_path,
                "-key",
                cls.key_path,
                "-tls1_3",
                "-max_early_data",
                "16384",
                "-early_data",
                "-num_tickets",
                "2",
                "-keylogfile",
                cls.keylog_path,
                "-www",
                "-quiet",
            ],
            stdout=subprocess.DEVNULL,
            stderr=cls.stderr_file,
        )
        time.sleep(0.8)
        if cls.proc.poll() is not None:
            cls.stderr_file.flush()
            try:
                with open(cls.stderr_path, "r", errors="replace") as f:
                    error = f.read()[-800:]
            except OSError:
                error = ""
            cls.stderr_file.close()
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise unittest.SkipTest(f"OpenSSL s_server did not start: {error}")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.stderr_file.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _connect(self, **config_kwargs):
        return utls.connect(
            "127.0.0.1",
            self.port,
            server_name="localhost",
            insecure=True,
            preset=utls.HelloChrome_120,
            alpn=["http/1.1"],
            timeout=10,
            config=utls.Config(server_name="localhost", insecure_skip_verify=True, timeout=10, **config_kwargs),
        )

    def test_early_data_accepted_and_key_schedule(self):
        first = self._connect()
        first.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        while True:
            try:
                if not first.recv():
                    break
            except utls.RecordError:
                break
        session = first.session
        first.close()
        self.assertIsNotNone(session)
        assert session is not None
        self.assertGreater(session.max_early_data, 0)

        early = b"GET /early HTTP/1.1\r\nHost: localhost\r\n\r\n"
        second = self._connect(session=session, early_data=early)
        self.addCleanup(second.close)
        self.assertTrue(second.connection_state().early_data_accepted)
        time.sleep(0.3)
        with open(self.stderr_path, "r", errors="replace") as f:
            errors = f.read()
        self.assertNotIn("bad record MAC", errors)
        self.assertNotIn("Error reading early data", errors)

        suite = utls.constants.CIPHER_SUITES[session.cipher_suite_id]
        early_secret = hkdf_extract(suite.hash, b"", session.psk)
        transcript_hash = hashlib.new(suite.hash, second.get_client_hello()).digest()
        expected = derive_secret(suite.hash, early_secret, "c e traffic", transcript_hash)

        with open(self.keylog_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if (
                    len(parts) == 3
                    and parts[0] == "CLIENT_EARLY_TRAFFIC_SECRET"
                    and parts[1] == second._client_random.hex()
                ):
                    self.assertEqual(parts[2], expected.hex())
                    break
            else:
                self.fail("server did not log CLIENT_EARLY_TRAFFIC_SECRET")

    def test_early_data_requires_session(self):
        with self.assertRaises(utls.HandshakeError):
            utls.connect(
                "127.0.0.1",
                self.port,
                server_name="localhost",
                insecure=True,
                preset=utls.HelloChrome_120,
                config=utls.Config(
                    server_name="localhost",
                    insecure_skip_verify=True,
                    early_data=b"x",
                    timeout=10,
                ),
            )


if __name__ == "__main__":
    unittest.main()
