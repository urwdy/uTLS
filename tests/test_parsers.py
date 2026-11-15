"""Small parser regression tests for optional extensions."""

from __future__ import annotations

import unittest

from utls import messages


class ExtensionParserTests(unittest.TestCase):
    def test_alps_protocols(self):
        # The extension body is ApplicationSettings: vec16(vec8(protocol)...).
        ext_data = messages.vec16(messages.vec8(b"h2"))
        extension = messages.uint16(17513) + messages.vec16(ext_data)
        body = messages.vec16(extension)
        parsed = messages.parse_encrypted_extensions(body)
        self.assertEqual(parsed.alps_protocols, ["h2"])


if __name__ == "__main__":
    unittest.main()
