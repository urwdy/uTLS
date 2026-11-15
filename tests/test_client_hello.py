"""ClientHello construction: structure comparison against Go uTLS goldens."""

from __future__ import annotations

import json
import os
import unittest

import utls
from utls import constants as C
from utls.extensions import (
    ALPNExtension,
    GREASEEcHExtension,
    SNIExtension,
    SupportedGroupsExtension,
    SupportedPointsExtension,
    SupportedVersionsExtension,
    boring_padding_style,
)
from utls.fingerprint import describe, ja3, parse_client_hello
from utls.hello import ClientHelloSpec, build_client_hello, build_client_hello_from_parsed

DATA = os.path.join(os.path.dirname(__file__), "data")

GOLDENS = {
    "go_chrome120": utls.HelloChrome_120,
    "go_chrome131": utls.HelloChrome_131,
    "go_chrome133": utls.HelloChrome_133,
    "go_chrome155": utls.HelloChrome_155,
    "go_firefox120": utls.HelloFirefox_120,
    "go_firefox148": utls.HelloFirefox_148,
    "go_safari16": utls.HelloSafari_16_0,
    "go_safari263": utls.HelloSafari_26_3,
    "go_ios14": utls.HelloIOS_14,
    "go_android11": utls.HelloAndroid_11_OkHttp,
    "go_edge106": utls.HelloEdge_106,
    "go_360_7_5": utls.Hello360_7_5,
    "go_360_11": utls.Hello360_11_0,
    "go_qq11": utls.HelloQQ_11_1,
    "go_chrome58": utls.HelloChrome_58,
    "go_chrome70": utls.HelloChrome_70,
    "go_chrome72": utls.HelloChrome_72,
    "go_chrome83": utls.HelloChrome_83,
    "go_chrome87": utls.HelloChrome_87,
    "go_chrome96": utls.HelloChrome_96,
    "go_chrome100": utls.HelloChrome_100,
    "go_chrome102": utls.HelloChrome_102,
    "go_chrome106": utls.HelloChrome_106_Shuffle,
    "go_firefox55": utls.HelloFirefox_55,
    "go_firefox63": utls.HelloFirefox_63,
    "go_firefox99": utls.HelloFirefox_99,
    "go_firefox102": utls.HelloFirefox_102,
    "go_firefox105": utls.HelloFirefox_105,
    "go_ios111": utls.HelloIOS_11_1,
    "go_ios121": utls.HelloIOS_12_1,
    "go_ios13": utls.HelloIOS_13,
    "go_edge85": utls.HelloEdge_85,
}


def _norm(value: int) -> int:
    return 0x0A0A if C.is_grease(value) else value


def _norm_list(values) -> tuple[int, ...]:
    return tuple(_norm(v) for v in values)


def _norm_versions(versions) -> tuple[int, ...]:
    # The position of the GREASE version is preserved by uTLS.
    return tuple(_norm(v) for v in versions)


def _grease_bytes(hello_bytes: bytes) -> set[bytes]:
    info = parse_client_hello(hello_bytes)
    values = set()
    for value in info.cipher_suites:
        if C.is_grease(value):
            values.add(value.to_bytes(2, "big"))
    for value in info.extension_ids:
        if C.is_grease(value):
            values.add(value.to_bytes(2, "big"))
    for group in info.groups:
        if C.is_grease(group):
            values.add(group.to_bytes(2, "big"))
    return values


def _mask_grease(body: bytes, values: set[bytes]) -> bytes:
    out = body
    for value in values:
        out = out.replace(value, b"\x0a\x0a")
    return out


def _ext_view(hello: bytes) -> dict[int, object]:
    info = parse_client_hello(hello)
    grease = _grease_bytes(hello)
    view: dict[int, list] = {}
    for ext_type, body in info.extensions:
        key = _norm(ext_type)
        if key == C.EXT_PADDING:
            continue
        if key == C.EXT_SUPPORTED_GROUPS:
            value = _norm_list(_parse_u16_vector(body))
        elif key == C.EXT_SIGNATURE_ALGORITHMS:
            value = _norm_list(_parse_u16_vector(body))
        elif key == C.EXT_SUPPORTED_VERSIONS:
            value = _norm_versions(_parse_u16_vector(body[1:]))
        elif key == C.EXT_KEY_SHARE:
            value = []
            payload = body[2:]
            pos = 0
            while pos < len(payload):
                group = int.from_bytes(payload[pos : pos + 2], "big")
                length = int.from_bytes(payload[pos + 2 : pos + 4], "big")
                value.append((_norm(group), length))
                pos += 4 + length
            value = tuple(sorted(value))
        elif key == 0xFE0D:
            value = ("ech", len(body))
        elif key == 0x0A0A:
            value = ("grease", len(body))
        else:
            value = _mask_grease(body, grease)
        view.setdefault(key, []).append(value)
    return {k: tuple(v) for k, v in view.items()}


def _parse_u16_vector(data: bytes) -> list[int]:
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]


class ClientHelloGoldenTests(unittest.TestCase):
    def test_structure_matches_utls(self):
        for filename, preset in GOLDENS.items():
            with self.subTest(preset=preset):
                with open(os.path.join(DATA, filename + ".json"), encoding="utf-8") as f:
                    golden = bytes.fromhex(json.load(f)["raw"])
                spec = utls.utls_id_to_spec(preset)
                ours = build_client_hello(spec, server_name="example.com").raw

                gi, oi = parse_client_hello(golden), parse_client_hello(ours)
                self.assertEqual(gi.legacy_version, oi.legacy_version)
                self.assertEqual(len(gi.session_id), len(oi.session_id))
                self.assertEqual(_norm_list(gi.cipher_suites), _norm_list(oi.cipher_suites))
                self.assertEqual(gi.compression_methods, oi.compression_methods)
                self.assertEqual(_norm_list(gi.groups), _norm_list(oi.groups))
                self.assertEqual(
                    sorted(_norm(t) for t in gi.extension_ids if t != C.EXT_PADDING),
                    sorted(_norm(t) for t in oi.extension_ids if t != C.EXT_PADDING),
                )
                if not preset.client == "Chrome":
                    self.assertEqual(
                        [_norm(t) for t in gi.extension_ids if t != C.EXT_PADDING],
                        [_norm(t) for t in oi.extension_ids if t != C.EXT_PADDING],
                    )

                gview, oview = _ext_view(golden), _ext_view(ours)
                for ext_type in set(gview) | set(oview):
                    if ext_type == 0xFE0D:
                        # Both sides pick a random GREASE-ECH payload length.
                        self.assertEqual(len(gview[ext_type]), 1)
                        self.assertIn(gview[ext_type][0][1], {186, 218, 250, 281, 282})
                        self.assertIn(oview[ext_type][0][1], {186, 218, 250, 281, 282})
                        continue
                    self.assertEqual(gview.get(ext_type), oview.get(ext_type), f"ext {ext_type:#06x}")

    def test_padding_styles(self):
        self.assertEqual(boring_padding_style(494), (14, True))
        self.assertEqual(boring_padding_style(313), (195, True))
        self.assertEqual(boring_padding_style(512), (0, False))
        self.assertEqual(boring_padding_style(200), (0, False))

    def test_chrome_padding_pads_to_512(self):
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        for ext in spec.extensions:
            if isinstance(ext, GREASEEcHExtension):
                ext.payload_lens = [128]
        built = build_client_hello(spec, server_name="example.com")
        self.assertEqual(len(built.raw), 512)
        info = parse_client_hello(built.raw)
        padding = [len(b) for t, b in info.extensions if t == C.EXT_PADDING]
        self.assertEqual(padding, [14])

    def test_chrome_padding_omitted_for_large_hello(self):
        spec = utls.utls_id_to_spec(utls.HelloChrome_120)
        for ext in spec.extensions:
            if isinstance(ext, GREASEEcHExtension):
                ext.payload_lens = [224]
        built = build_client_hello(spec, server_name="example.com")
        info = parse_client_hello(built.raw)
        self.assertGreater(len(built.raw), 512)
        self.assertNotIn(C.EXT_PADDING, info.extension_ids)

    def test_second_grease_extension_has_one_byte_body(self):
        spec = utls.utls_id_to_spec(utls.HelloSafari_16_0)
        built = build_client_hello(spec, server_name="example.com")
        info = parse_client_hello(built.raw)
        grease = [len(b) for t, b in info.extensions if C.is_grease(t)]
        self.assertEqual(sorted(grease), [0, 1])

    def test_sni_omitted_for_ip(self):
        spec = utls.utls_id_to_spec(utls.HelloFirefox_120)
        built = build_client_hello(spec, server_name="127.0.0.1")
        info = parse_client_hello(built.raw)
        self.assertNotIn(C.EXT_SNI, info.extension_ids)
        self.assertEqual(describe(built.raw)["server_name"], "")

    def test_randomized_hello_is_valid(self):
        for _ in range(5):
            built = build_client_hello(
                utls.utls_id_to_spec(utls.HelloRandomized), server_name="example.com"
            )
            info = parse_client_hello(built.raw)
            self.assertGreater(len(info.cipher_suites), 2)
            self.assertTrue(info.extensions)


class ClientHelloParsingTests(unittest.TestCase):
    def test_roundtrip_parsed_spec(self):
        original = build_client_hello(
            utls.utls_id_to_spec(utls.HelloChrome_120), server_name="example.com"
        ).raw
        parsed = build_client_hello_from_parsed(original)
        rebuilt = build_client_hello(parsed, server_name="example.com").raw
        a, b = parse_client_hello(original), parse_client_hello(rebuilt)
        self.assertEqual(_norm_list(a.cipher_suites), _norm_list(b.cipher_suites))
        self.assertEqual(
            sorted(_norm(t) for t in a.extension_ids),
            sorted(_norm(t) for t in b.extension_ids),
        )
        self.assertEqual(_norm_list(a.groups), _norm_list(b.groups))

    def test_ja3(self):
        spec = ClientHelloSpec(
            tls_vers_min=C.VERSION_TLS12,
            tls_vers_max=C.VERSION_TLS13,
            cipher_suites=[0x1301, 0xC02F],
            extensions=[
                SNIExtension(),
                ALPNExtension(["http/1.1"]),
                SupportedGroupsExtension([C.GROUP_X25519, C.GROUP_SECP256R1]),
                SupportedPointsExtension(b"\x00"),
                SupportedVersionsExtension([C.VERSION_TLS13, C.VERSION_TLS12]),
            ],
        )
        raw = build_client_hello(spec, server_name="example.com").raw
        expected = (
            "771,4865-49199,0-16-10-11-43,29-23,0"
        )
        self.assertEqual(ja3(raw), expected)

    def test_unknown_extension_preserved(self):
        spec = ClientHelloSpec(
            tls_vers_max=C.VERSION_TLS12,
            cipher_suites=[0xC02F],
            extensions=[],
        )
        from utls.extensions import GenericExtension

        spec.extensions.append(GenericExtension(0x1234, b"\x01\x02"))
        raw = build_client_hello(spec, server_name="").raw
        parsed = build_client_hello_from_parsed(raw)
        bodies = {getattr(e, "type_id", None): getattr(e, "data", None) for e in parsed.extensions}
        self.assertEqual(bodies[0x1234], b"\x01\x02")


if __name__ == "__main__":
    unittest.main()
