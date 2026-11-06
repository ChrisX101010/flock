from __future__ import annotations

import hashlib
import struct

DEPTH = 256

EMPTY_LEAF = hashlib.sha256(b"FLOCKEMPTY1").digest()

EMPTY = [b""] * (DEPTH + 1)
EMPTY[DEPTH] = EMPTY_LEAF

for d in range(DEPTH - 1, -1, -1):
    EMPTY[d] = hashlib.sha256(
        b"FLOCKNODE1" + EMPTY[d + 1] + EMPTY[d + 1]
    ).digest()


def _leaf(address: bytes, value: tuple[int, int]) -> bytes:
    nonce, balance = value

    return hashlib.sha256(
        b"FLOCKLEAF1"
        + address
        + struct.pack(">Q", nonce)
        + struct.pack(">Q", balance)
    ).digest()


def state_root_alt(state: dict[bytes, tuple[int, int]]) -> bytes:
    entries = sorted(
        (
            int.from_bytes(address, "big"),
            address,
            value,
        )
        for address, value in state.items()
    )

    def subtree(depth: int, entries_here):
        if not entries_here:
            return EMPTY[depth]

        if depth == DEPTH:
            if len(entries_here) != 1:
                raise ValueError("duplicate sparse-tree key")
            _, address, value = entries_here[0]
            return _leaf(address, value)

        bit_shift = DEPTH - depth - 1
        left = []
        right = []

        for entry in entries_here:
            if (entry[0] >> bit_shift) & 1:
                right.append(entry)
            else:
                left.append(entry)

        lhash = subtree(depth + 1, left)
        rhash = subtree(depth + 1, right)

        return hashlib.sha256(
            b"FLOCKNODE1" + lhash + rhash
        ).digest()

    return subtree(0, entries)
