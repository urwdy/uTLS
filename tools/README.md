# Tooling

## `gen_legacy_presets.py`

Regenerates `utls/_legacy_presets.py` from a JSON dump produced by upstream
Go uTLS. The dump contains one `ClientHelloSpec` per preset and is kept in
`tools/legacy_specs.json` as a reviewable snapshot.

```bash
uv run python tools/gen_legacy_presets.py tools/legacy_specs.json
```

The Go-side dumper should call `tls.UTLSIdToSpec` and serialize:

```json
{
  "Chrome-58": {
    "min_vers": 769,
    "max_vers": 771,
    "cipher_suites": [2570, 49195],
    "compression_methods": [0],
    "extensions": [{"type": "sni"}]
  }
}
```

Extension names and fields follow `utls/_legacy_presets.py`'s generated
schema. Unsupported/deprecated presets can be omitted with `--skip`.
