"""Pure-Python ML-KEM-768 (FIPS 203).

The TLS hybrid group ``X25519MLKEM768`` (0x11ec) is used by current Chrome and
Firefox fingerprints.  ``cryptography`` does not expose ML-KEM, so this module
implements the KEM directly.  It is small and dependency free; it is *not*
constant time and therefore only suitable for fingerprinting clients, not for
long-term secret protection against a local attacker.

The implementation follows the algorithms of FIPS 203 (K-PKE + ML-KEM) with
plain modular arithmetic (no Montgomery representation) to keep the code
auditable.  ``tests/test_mlkem.py`` cross-checks it against Go's
``crypto/mlkem`` implementation.
"""

from __future__ import annotations

import hashlib
import hmac
import os

Q = 3329
N = 256
K = 3
ETA1 = 2
ETA2 = 2
DU = 10
DV = 4

EK_SIZE = 384 * K + 32  # 1184
DK_SIZE = 768 * K + 96  # 2400
CT_SIZE = 32 * (DU * K + DV)  # 1088

_R = 1 << 16
_INV128 = pow(128, -1, Q)


def _bit_reverse7(x: int) -> int:
    r = 0
    for _ in range(7):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


# Twiddle factors zeta_i = 17^bitrev7(i) mod q (plain domain).
ZETAS = [pow(17, _bit_reverse7(i), Q) for i in range(128)]
# FIPS 203 Algorithm 11 uses gamma_i = 17^(2*bitrev7(i)+1) for coefficient pair i.
GAMMAS = [pow(17, 2 * _bit_reverse7(i) + 1, Q) for i in range(128)]


# ---------------------------------------------------------------------------
# Polynomial helpers
# ---------------------------------------------------------------------------


def _poly_add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


def _ntt(poly: list[int]) -> list[int]:
    r = list(poly)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = zeta * r[j + length] % Q
                r[j + length] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
            start += 2 * length
        length //= 2
    return r


def _inv_ntt(poly: list[int]) -> list[int]:
    r = list(poly)
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = r[j]
                r[j] = (t + r[j + length]) % Q
                r[j + length] = (r[j + length] - t) * zeta % Q
            start += 2 * length
        length *= 2
    return [x * _INV128 % Q for x in r]


def _basemul(a: list[int], b: list[int], zeta: int) -> tuple[int, int]:
    r0 = (a[1] * b[1] % Q * zeta + a[0] * b[0]) % Q
    r1 = (a[0] * b[1] + a[1] * b[0]) % Q
    return r0, r1


def _poly_basemul(a: list[int], b: list[int]) -> list[int]:
    r = [0] * N
    for i in range(128):
        r[2 * i], r[2 * i + 1] = _basemul(a[2 * i : 2 * i + 2], b[2 * i : 2 * i + 2], GAMMAS[i])
    return r


def _poly_tomont(poly: list[int]) -> list[int]:
    """Unused in the plain-domain implementation, kept for reference."""
    f = _R * _R % Q
    return [x * f % Q for x in poly]


# ---------------------------------------------------------------------------
# Encoding / compression
# ---------------------------------------------------------------------------


def _compress(d: int, x: int) -> int:
    return (((x << d) + Q // 2) // Q) & ((1 << d) - 1)


def _decompress(d: int, y: int) -> int:
    return (Q * y + (1 << (d - 1))) >> d


def _poly_decompress(d: int, poly: list[int]) -> list[int]:
    return [_decompress(d, y) for y in poly]


def byte_encode(d: int, poly: list[int]) -> bytes:
    out = bytearray(32 * d)
    acc = 0
    bits = 0
    pos = 0
    mask = (1 << d) - 1
    for c in poly:
        acc |= (c & mask) << bits
        bits += d
        while bits >= 8:
            out[pos] = acc & 0xFF
            pos += 1
            acc >>= 8
            bits -= 8
    return bytes(out)


def byte_decode(d: int, data: bytes) -> list[int]:
    if len(data) != 32 * d:
        raise ValueError("bad polynomial encoding length")
    out = [0] * N
    acc = 0
    bits = 0
    pos = 0
    mask = (1 << d) - 1
    for i in range(N):
        while bits < d:
            acc |= data[pos] << bits
            pos += 1
            bits += 8
        out[i] = acc & mask
        acc >>= d
        bits -= d
    return out


def _sample_ntt(seed: bytes) -> list[int]:
    """Rejection sampling from SHAKE128 (Algorithm 7)."""
    out: list[int] = []
    xof = hashlib.shake_128(seed)
    # Ask for a generous prefix; extend it if rejection sampling needs more.
    produced = 168 * 8
    buf = xof.digest(produced)
    pos = 0
    while len(out) < N:
        if pos + 3 > len(buf):
            produced *= 2
            buf = xof.digest(produced)
        d1 = buf[pos] | ((buf[pos + 1] & 0x0F) << 8)
        d2 = (buf[pos + 1] >> 4) | (buf[pos + 2] << 4)
        pos += 3
        if d1 < Q:
            out.append(d1)
        if d2 < Q and len(out) < N:
            out.append(d2)
    return out


def _sample_cbd(eta: int, stream: bytes) -> list[int]:
    """Centered binomial distribution (Algorithm 8).

    ``stream`` is the already-expanded PRF output (``64 * eta`` bytes).
    """
    need = 64 * eta
    if len(stream) != need:
        raise ValueError(f"expected {need} bytes of PRF output")
    bits = 0
    acc = 0
    pos = 0
    out = [0] * N
    mask = (1 << eta) - 1
    for i in range(N):
        while bits < 2 * eta:
            acc |= stream[pos] << bits
            pos += 1
            bits += 8
        a = (acc & mask).bit_count()
        b = ((acc >> eta) & mask).bit_count()
        acc >>= 2 * eta
        bits -= 2 * eta
        out[i] = (a - b) % Q
    return out


def _prf(eta: int, seed: bytes, nonce: int) -> bytes:
    return hashlib.shake_256(seed + bytes([nonce])).digest(64 * eta)


def _gen_matrix(rho: bytes, transposed: bool) -> list[list[list[int]]]:
    matrix: list[list[list[int]]] = []
    for i in range(K):
        row = []
        for j in range(K):
            if transposed:
                seed = rho + bytes([i, j])
            else:
                seed = rho + bytes([j, i])
            row.append(_sample_ntt(seed))
        matrix.append(row)
    return matrix


# ---------------------------------------------------------------------------
# K-PKE
# ---------------------------------------------------------------------------


def _kpke_keygen(d: bytes) -> tuple[bytes, bytes]:
    if len(d) != 32:
        raise ValueError("d must be 32 bytes")
    digest = hashlib.sha3_512(d + bytes([K])).digest()
    rho, sigma = digest[:32], digest[32:]
    matrix = _gen_matrix(rho, transposed=False)

    s = [_sample_cbd(ETA1, _prf(ETA1, sigma, i)) for i in range(K)]
    e = [_sample_cbd(ETA1, _prf(ETA1, sigma, K + i)) for i in range(K)]
    s_hat = [_ntt(p) for p in s]
    e_hat = [_ntt(p) for p in e]

    t_hat = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _poly_add(acc, _poly_basemul(matrix[i][j], s_hat[j]))
        t_hat.append(_poly_add(acc, e_hat[i]))

    ek = b"".join(byte_encode(12, p) for p in t_hat) + rho
    dk = b"".join(byte_encode(12, p) for p in s_hat)
    return ek, dk


def _kpke_encrypt(ek: bytes, m: bytes, coins: bytes) -> bytes:
    if len(ek) != EK_SIZE:
        raise ValueError("bad encapsulation key length")
    if len(m) != 32 or len(coins) != 32:
        raise ValueError("bad message or coins length")

    t_hat = [byte_decode(12, ek[384 * i : 384 * (i + 1)]) for i in range(K)]
    rho = ek[384 * K :]
    matrix_t = _gen_matrix(rho, transposed=True)

    r = [_sample_cbd(ETA1, _prf(ETA1, coins, i)) for i in range(K)]
    e1 = [_sample_cbd(ETA2, _prf(ETA2, coins, K + i)) for i in range(K)]
    e2 = _sample_cbd(ETA2, _prf(ETA2, coins, 2 * K))
    r_hat = [_ntt(p) for p in r]

    u = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = _poly_add(acc, _poly_basemul(matrix_t[i][j], r_hat[j]))
        u.append(_poly_add(_inv_ntt(acc), e1[i]))

    acc = [0] * N
    for j in range(K):
        acc = _poly_add(acc, _poly_basemul(t_hat[j], r_hat[j]))
    msg = _poly_decompress(1, byte_decode(1, m))
    v = _poly_add(_poly_add(_inv_ntt(acc), e2), msg)

    c1 = b"".join(byte_encode(DU, [_compress(DU, x) for x in u[i]]) for i in range(K))
    c2 = byte_encode(DV, [_compress(DV, x) for x in v])
    return c1 + c2


def _kpke_decrypt(dk: bytes, c: bytes) -> bytes:
    if len(dk) != 384 * K:
        raise ValueError("bad decryption key length")
    if len(c) != CT_SIZE:
        raise ValueError("bad ciphertext length")

    s_hat = [byte_decode(12, dk[384 * i : 384 * (i + 1)]) for i in range(K)]
    u = []
    pos = 0
    for _ in range(K):
        poly = byte_decode(DU, c[pos : pos + 32 * DU])
        pos += 32 * DU
        u.append([_decompress(DU, x) for x in poly])
    v = [_decompress(DV, x) for x in byte_decode(DV, c[pos:])]

    u_hat = [_ntt(p) for p in u]
    acc = [0] * N
    for j in range(K):
        acc = _poly_add(acc, _poly_basemul(s_hat[j], u_hat[j]))
    w = _poly_sub(v, _inv_ntt(acc))
    m_poly = [_compress(1, x) for x in w]
    return byte_encode(1, m_poly)


# ---------------------------------------------------------------------------
# ML-KEM
# ---------------------------------------------------------------------------


def keygen(seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(encapsulation_key, decapsulation_key)``."""
    if seed is None:
        seed = os.urandom(64)
    if len(seed) != 64:
        raise ValueError("seed must be 64 bytes (d || z)")
    d, z = seed[:32], seed[32:]
    ek_pke, dk_pke = _kpke_keygen(d)
    dk = dk_pke + ek_pke + hashlib.sha3_256(ek_pke).digest() + z
    return ek_pke, dk


def encapsulate(ek: bytes, m: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(ciphertext, shared_secret)``."""
    if len(ek) != EK_SIZE:
        raise ValueError("bad encapsulation key length")
    if m is None:
        m = os.urandom(32)
    if len(m) != 32:
        raise ValueError("m must be 32 bytes")
    kr = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
    key, coins = kr[:32], kr[32:]
    c = _kpke_encrypt(ek, m, coins)
    return c, key


def decapsulate(dk: bytes, c: bytes) -> bytes:
    if len(dk) != DK_SIZE:
        raise ValueError("bad decapsulation key length")
    if len(c) != CT_SIZE:
        raise ValueError("bad ciphertext length")
    dk_pke = dk[: 384 * K]
    ek_pke = dk[384 * K : 384 * K + EK_SIZE]
    h = dk[384 * K + EK_SIZE : 384 * K + EK_SIZE + 32]
    z = dk[384 * K + EK_SIZE + 32 :]

    m_prime = _kpke_decrypt(dk_pke, c)
    kr = hashlib.sha3_512(m_prime + h).digest()
    key_prime, coins = kr[:32], kr[32:]
    c_prime = _kpke_encrypt(ek_pke, m_prime, coins)

    if hmac.compare_digest(c, c_prime):
        return key_prime
    return hashlib.shake_256(z + c).digest(32)


def encapsulate_deterministic(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """Test helper mirroring Go's ``EncapsulateDeterministically``."""
    if len(ek) != EK_SIZE:
        raise ValueError("bad encapsulation key length")
    kr = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
    key, coins = kr[:32], kr[32:]
    return _kpke_encrypt(ek, m, coins), key
