from __future__ import annotations

import hashlib
import struct

EMPTY_DOMAIN = b"FLOCKEMPTY1"
LEAF_DOMAIN = b"FLOCKLEAF1"
NODE_DOMAIN = b"FLOCKNODE1"

TREE_DEPTH = 256
HASH_SIZE = 32
U64_MAX = (1 << 64) - 1


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


EMPTY = [b""] * (TREE_DEPTH + 1)
EMPTY[TREE_DEPTH] = h(EMPTY_DOMAIN)

for depth in range(TREE_DEPTH - 1, -1, -1):
    EMPTY[depth] = h(NODE_DOMAIN + EMPTY[depth + 1] + EMPTY[depth + 1])


def leaf_hash(address: bytes, nonce: int, balance: int) -> bytes:
    if len(address) != 32:
        raise ValueError("account id must be 32 bytes")
    if not 0 <= nonce <= U64_MAX:
        raise ValueError("nonce outside u64")
    if not 0 <= balance <= U64_MAX:
        raise ValueError("balance outside u64")

    return h(
        LEAF_DOMAIN
        + address
        + struct.pack(">Q", nonce)
        + struct.pack(">Q", balance)
    )


def state_root(state: dict[bytes, tuple[int, int]]) -> bytes:
    nodes = {
        int.from_bytes(address, "big"): leaf_hash(address, nonce, balance)
        for address, (nonce, balance) in state.items()
    }

    if not nodes:
        return EMPTY[0]

    for depth in range(TREE_DEPTH - 1, -1, -1):
        child_empty = EMPTY[depth + 1]
        parents = {index >> 1 for index in nodes}

        nodes = {
            parent: h(
                NODE_DOMAIN
                + nodes.get(parent << 1, child_empty)
                + nodes.get((parent << 1) | 1, child_empty)
            )
            for parent in parents
        }

    return nodes[0]


def make_proof(
    state: dict[bytes, tuple[int, int]],
    address: bytes,
) -> list[bytes]:
    if len(address) != 32:
        raise ValueError("account id must be 32 bytes")

    target = int.from_bytes(address, "big")

    nodes = {
        int.from_bytes(key, "big"): leaf_hash(key, nonce, balance)
        for key, (nonce, balance) in state.items()
    }

    proof: list[bytes] = []

    for depth in range(TREE_DEPTH - 1, -1, -1):
        child_empty = EMPTY[depth + 1]
        proof.append(nodes.get(target ^ 1, child_empty))

        parents = {index >> 1 for index in nodes}
        nodes = {
            parent: h(
                NODE_DOMAIN
                + nodes.get(parent << 1, child_empty)
                + nodes.get((parent << 1) | 1, child_empty)
            )
            for parent in parents
        }

        target >>= 1

    return proof


def verify_proof(
    address: bytes,
    value: tuple[int, int] | None,
    proof: list[bytes],
    expected_root: bytes,
) -> bool:
    if len(address) != 32 or len(expected_root) != HASH_SIZE:
        return False
    if len(proof) != TREE_DEPTH:
        return False
    if any(len(sibling) != HASH_SIZE for sibling in proof):
        return False

    target = int.from_bytes(address, "big")

    if value is None:
        node = EMPTY[TREE_DEPTH]
    else:
        node = leaf_hash(address, value[0], value[1])

    for sibling in proof:
        if target & 1:
            node = h(NODE_DOMAIN + sibling + node)
        else:
            node = h(NODE_DOMAIN + node + sibling)
        target >>= 1

    return node == expected_root


def parse_canonical_state(data: bytes) -> dict[bytes, tuple[int, int]]:
    domain = b"FLOCKSTATE1"

    if not data.startswith(domain):
        raise ValueError("wrong state domain")

    at = len(domain)

    if len(data) < at + 4:
        raise ValueError("truncated account count")

    count = struct.unpack_from(">I", data, at)[0]
    at += 4

    state: dict[bytes, tuple[int, int]] = {}
    previous: bytes | None = None

    for _ in range(count):
        if len(data) < at + 48:
            raise ValueError("truncated account")

        address = data[at : at + 32]
        nonce = struct.unpack_from(">Q", data, at + 32)[0]
        balance = struct.unpack_from(">Q", data, at + 40)[0]
        at += 48

        if previous is not None and address <= previous:
            raise ValueError("accounts are not in canonical order")
        if address in state:
            raise ValueError("duplicate account")

        state[address] = (nonce, balance)
        previous = address

    if at != len(data):
        raise ValueError("trailing state bytes")

    return state
