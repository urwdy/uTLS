"""ML-KEM-768 tests, including cross-checks against Go's crypto/mlkem."""

from __future__ import annotations

import json
import os
import unittest

from utls import mlkem

DATA = os.path.join(os.path.dirname(__file__), "data")


class MLKEMTests(unittest.TestCase):
    def test_roundtrip(self):
        ek, dk = mlkem.keygen(bytes(range(64)))
        self.assertEqual(len(ek), mlkem.EK_SIZE)
        self.assertEqual(len(dk), mlkem.DK_SIZE)
        ct, ss = mlkem.encapsulate(ek)
        self.assertEqual(len(ct), mlkem.CT_SIZE)
        self.assertEqual(mlkem.decapsulate(dk, ct), ss)

    def test_go_encapsulation_vector(self):
        with open(os.path.join(DATA, "mlkem_go_vector.json"), encoding="utf-8") as f:
            vector = json.load(f)
        ek, dk = mlkem.keygen(bytes(range(64)))
        # Go's EncapsulationKey.Bytes() for the same seed must match ours.
        self.assertEqual(ek.hex(), vector["ek"])
        # Decapsulate a ciphertext produced by Go.
        self.assertEqual(
            mlkem.decapsulate(dk, bytes.fromhex(vector["ct"])).hex(), vector["ss"]
        )

    def test_python_encapsulation_vector(self):
        with open(os.path.join(DATA, "mlkem_py_vector.json"), encoding="utf-8") as f:
            vector = json.load(f)
        ct, ss = mlkem.encapsulate_deterministic(
            mlkem.keygen(bytes(range(64)))[0], bytes(range(32))
        )
        self.assertEqual(ct.hex(), vector["ct"])
        self.assertEqual(ss.hex(), vector["ss"])

    def test_rejects_bad_ciphertext(self):
        ek, dk = mlkem.keygen(bytes(range(64)))
        ct, ss = mlkem.encapsulate(ek)
        broken = bytearray(ct)
        broken[0] ^= 1
        # Implicit rejection returns a different (pseudorandom) key.
        self.assertNotEqual(mlkem.decapsulate(dk, bytes(broken)), ss)
        self.assertEqual(len(mlkem.decapsulate(dk, bytes(broken))), 32)


if __name__ == "__main__":
    unittest.main()
