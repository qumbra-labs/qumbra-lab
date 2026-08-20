#!/usr/bin/env python3
"""Keccak-256 (original pad10*1, 0x01 domain byte).

Matches `qlab_devnet::hash::keccak256` / tiny-keccak. NIST SHA3-256 is a
different domain byte (0x06) and must not be used here: the genesis hash
the join doc and this release lane pin is keccak256 over the file's
canonical bincode (`GenesisFile::hash`).

stdin or a filename → 64 hex chars on stdout. No third-party packages —
preflight runs on a stock ubuntu-latest image.
"""
from __future__ import annotations

import sys

RATE = 136  # 1088-bit rate / 8
ROUNDS = 24
ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
RC = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)


def _rotl64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(state: list[int]) -> None:
    for round_i in range(ROUNDS):
        # θ
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # ρ + π
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], ROT[x][y])
        # χ
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                state[x + 5 * y] &= 0xFFFFFFFFFFFFFFFF
        # ι
        state[0] ^= RC[round_i]


def keccak256(data: bytes) -> bytes:
    state = [0] * 25
    offset = 0
    while offset + RATE <= len(data):
        for i in range(RATE // 8):
            state[i] ^= int.from_bytes(data[offset + i * 8 : offset + i * 8 + 8], "little")
        _keccak_f(state)
        offset += RATE
    last = bytearray(RATE)
    rem = data[offset:]
    last[: len(rem)] = rem
    last[len(rem)] ^= 0x01
    last[RATE - 1] ^= 0x80
    for i in range(RATE // 8):
        state[i] ^= int.from_bytes(last[i * 8 : i * 8 + 8], "little")
    _keccak_f(state)
    out = bytearray(32)
    for i in range(4):
        out[i * 8 : i * 8 + 8] = state[i].to_bytes(8, "little")
    return bytes(out)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in ("-h", "--help"):
        with open(sys.argv[1], "rb") as f:
            data = f.read()
    else:
        if len(sys.argv) > 1:
            sys.stderr.write("usage: keccak256.py [file]  (or stdin)\n")
            return 2
        data = sys.stdin.buffer.read()
    sys.stdout.write(keccak256(data).hex() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
