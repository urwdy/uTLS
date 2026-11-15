#!/usr/bin/env python3
"""Generate ``utls/_legacy_presets.py`` from a Go uTLS spec dump.

Input format is a JSON object mapping preset names to::

    {
      "min_vers": 769,
      "max_vers": 771,
      "cipher_suites": [..],
      "compression_methods": [0],
      "extensions": [{"type": "sni"}, ...]
    }

The dump is intentionally kept as a separate fixture because it is produced by
a small Go helper linked against upstream uTLS (``UTLSIdToSpec``).  This script
only performs the deterministic Python translation.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

HEADER = '''"""Generated legacy ClientHello presets (from uTLS specs).

This module is generated from Go uTLS' ClientHelloSpec definitions.
Do not edit by hand.
"""

from __future__ import annotations

from .extensions import (
    ALPNExtension,
    ApplicationSettingsExtension,
    CompressCertificateExtension,
    ExtendedMasterSecretExtension,
    FakeChannelIDExtension,
    FakeDelegatedCredentialsExtension,
    FakeRecordSizeLimitExtension,
    GREASEExtension,
    KeyShareEntry,
    KeyShareExtension,
    NPNExtension,
    PaddingExtension,
    PSKKeyExchangeModesExtension,
    RenegotiationInfoExtension,
    SNIExtension,
    SCTExtension,
    SessionTicketExtension,
    SignatureAlgorithmsExtension,
    StatusRequestExtension,
    SupportedGroupsExtension,
    SupportedPointsExtension,
    SupportedVersionsExtension,
    boring_padding_style,
)
from .hello import ClientHelloSpec


def _ext(e):
    t = e["type"]
    if t == "sni":
        return SNIExtension()
    if t == "status_request":
        return StatusRequestExtension()
    if t == "supported_groups":
        return SupportedGroupsExtension(e["groups"])
    if t == "supported_points":
        return SupportedPointsExtension(bytes.fromhex(e["points"]))
    if t == "signature_algorithms":
        return SignatureAlgorithmsExtension(e["algorithms"])
    if t == "alpn":
        return ALPNExtension(e["protocols"])
    if t == "sct":
        return SCTExtension()
    if t == "padding":
        if e.get("dynamic"):
            return PaddingExtension(padding_len_func=boring_padding_style)
        return PaddingExtension(pad_len=e["length"])
    if t == "ems":
        return ExtendedMasterSecretExtension()
    if t == "compress_certificate":
        return CompressCertificateExtension(e["algorithms"])
    if t == "record_size_limit":
        return FakeRecordSizeLimitExtension(e["limit"])
    if t == "delegated_credentials":
        return FakeDelegatedCredentialsExtension(e["algorithms"])
    if t == "session_ticket":
        return SessionTicketExtension()
    if t == "supported_versions":
        return SupportedVersionsExtension(e["versions"])
    if t == "psk_modes":
        return PSKKeyExchangeModesExtension(e["modes"])
    if t == "key_share":
        entries = []
        for share in e["shares"]:
            data = b"\\x00" if share["len"] == 1 else None
            entries.append(KeyShareEntry(share["group"], data))
        return KeyShareExtension(entries)
    if t == "grease":
        return GREASEExtension()
    if t == "alps":
        return ApplicationSettingsExtension(e["protocols"])
    if t == "alps_new":
        return ApplicationSettingsExtension(e["protocols"], new=True)
    if t == "channel_id":
        return FakeChannelIDExtension(old=e.get("old", False))
    if t == "npn":
        return NPNExtension()
    if t == "renegotiation":
        return RenegotiationInfoExtension()
    raise ValueError(f"unsupported legacy extension {t}")


'''


def render(data: dict, skip: set[str]) -> str:
    parts = [HEADER, "LEGACY_SPECS = {\n"]
    for name in sorted(data):
        if name in skip:
            continue
        spec = data[name]
        parts.append(f'    "{name}": {{\n')
        parts.append(f'        "min_vers": {spec["min_vers"]},\n')
        parts.append(f'        "max_vers": {spec["max_vers"]},\n')
        parts.append(f'        "cipher_suites": {spec["cipher_suites"]},\n')
        parts.append(
            f'        "compression_methods": {spec["compression_methods"]},\n'
        )
        parts.append(f'        "extensions": {spec["extensions"]!r},\n')
        parts.append("    },\n")
    parts.append("}\n\n\n")
    parts.append('''def build_legacy_spec(name: str) -> ClientHelloSpec:
    spec = LEGACY_SPECS[name]
    min_vers = spec["min_vers"]
    max_vers = spec["max_vers"]
    if not max_vers:
        for ext in spec["extensions"]:
            if ext.get("type") == "supported_versions":
                versions = [v for v in ext["versions"] if not ((v & 0x0F0F) == 0x0A0A)]
                if versions:
                    min_vers, max_vers = min(versions), max(versions)
                break
    if not min_vers:
        min_vers = 0x0301
    if not max_vers:
        max_vers = 0x0303
    return ClientHelloSpec(
        tls_vers_min=min_vers,
        tls_vers_max=max_vers,
        cipher_suites=list(spec["cipher_suites"]),
        compression_methods=list(spec["compression_methods"]),
        extensions=[_ext(e) for e in spec["extensions"]],
    )
''')
    return "".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="Go uTLS JSON dump")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "utls" / "_legacy_presets.py",
    )
    parser.add_argument(
        "--skip",
        action="append",
        default=["Chrome-115PQ", "Chrome-120PQ"],
        help="preset name to omit (may be repeated)",
    )
    args = parser.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    args.output.write_text(render(data, set(args.skip)), encoding="utf-8")
    print(f"wrote {args.output} ({len(data) - len(set(args.skip))} presets)")


if __name__ == "__main__":
    main()
