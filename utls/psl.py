"""Public Suffix List matching used for wildcard certificate checks.

The bundled list is the official Public Suffix List
(https://publicsuffix.org/), distributed under the Mozilla Public License 2.0.
"""

from __future__ import annotations

_rules: frozenset[str] | None = None
_wildcards: frozenset[str] | None = None
_exceptions: frozenset[str] | None = None


def _normalize(name: str) -> str:
    name = name.strip().rstrip(".").lower()
    if not name:
        return name
    try:
        return name.encode("idna").decode()
    except UnicodeError:
        return name


def _load() -> None:
    global _rules, _wildcards, _exceptions
    if _rules is not None:
        return
    from importlib.resources import files

    text = files(__package__).joinpath("_public_suffix_list.dat").read_text(
        encoding="utf-8"
    )
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(_normalize(line[1:]))
        elif line.startswith("*."):
            wildcards.add(_normalize(line[2:]))
        else:
            rules.add(_normalize(line))
    _rules = frozenset(rules)
    _wildcards = frozenset(wildcards)
    _exceptions = frozenset(exceptions)


def is_public_suffix(name: str) -> bool:
    """Return whether ``name`` itself is a public suffix."""
    _load()
    assert _rules is not None and _wildcards is not None and _exceptions is not None
    normalized = _normalize(name)
    if not normalized:
        return False
    if normalized in _exceptions:
        return False
    if normalized in _rules:
        return True
    labels = normalized.split(".")
    if len(labels) == 1:
        return True
    for index in range(1, len(labels)):
        suffix = ".".join(labels[index:])
        if suffix in _wildcards and len(labels) == len(suffix.split(".")) + 1:
            return True
    return False
