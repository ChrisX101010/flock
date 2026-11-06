from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from tools.authenticated_state import state_root
from tools.reference_model import Tx, apply_tx, encode_tx

U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
HASH_SIZE = 32

BLOCK_DOMAIN = b"FLOCKBLK1"
BLOCK_HASH_DOMAIN = b"FLOCKBLOCKHASH1"

TX_ITEM_DOMAIN = b"FLOCKTXITEM1"
TX_NODE_DOMAIN = b"FLOCKTXNODE1"
TX_PAD_DOMAIN = b"FLOCKTXPAD1"
TX_EMPTY_DOMAIN = b"FLOCKTXEMPTY1"
TX_ROOT_DOMAIN = b"FLOCKTXROOT1"

RECEIPT_DOMAIN = b"FLOCKRCPT1"
RECEIPT_ITEM_DOMAIN = b"FLOCKRCPTITEM1"
RECEIPT_NODE_DOMAIN = b"FLOCKRCPTNODE1"
RECEIPT_PAD_DOMAIN = b"FLOCKRCPTPAD1"
RECEIPT_EMPTY_DOMAIN = b"FLOCKRCPTEMPTY1"
RECEIPT_ROOT_DOMAIN = b"FLOCKRCPTROOT1"


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _u32(value: int) -> bytes:
    if not 0 <= value <= U32_MAX:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    if not 0 <= value <= U64_MAX:
        raise ValueError("u64 out of range")
    return struct.pack(">Q", value)


def ordered_list_root(
    items: list[bytes],
    *,
    item_domain: bytes,
    node_domain: bytes,
    pad_domain: bytes,
    empty_domain: bytes,
    root_domain: bytes,
) -> bytes:
    if len(items) > U32_MAX:
        raise ValueError("too many committed items")

    leaves = [
        h(item_domain + _u32(index) + _u32(len(item)) + item)
        for index, item in enumerate(items)
    ]

    if not leaves:
        tree = h(empty_domain)
    else:
        level = 0
        current = leaves

        while len(current) > 1:
            nxt: list[bytes] = []

            for at in range(0, len(current), 2):
                left = current[at]

                if at + 1 < len(current):
                    right = current[at + 1]
                else:
                    right = h(pad_domain + _u32(level) + _u32(at + 1))

                nxt.append(h(node_domain + left + right))

            current = nxt
            level += 1

        tree = current[0]

    return h(root_domain + _u32(len(items)) + tree)


def transaction_root(tx_bytes: list[bytes]) -> bytes:
    return ordered_list_root(
        tx_bytes,
        item_domain=TX_ITEM_DOMAIN,
        node_domain=TX_NODE_DOMAIN,
        pad_domain=TX_PAD_DOMAIN,
        empty_domain=TX_EMPTY_DOMAIN,
        root_domain=TX_ROOT_DOMAIN,
    )


def encode_receipt(
    index: int,
    tx_bytes: bytes,
    success: bool,
    post_state_root: bytes,
) -> bytes:
    if len(post_state_root) != HASH_SIZE:
        raise ValueError("post-state root must be 32 bytes")

    return b"".join(
        (
            RECEIPT_DOMAIN,
            _u32(index),
            h(tx_bytes),
            b"\x01" if success else b"\x00",
            post_state_root,
        )
    )


def receipts_root(receipts: list[bytes]) -> bytes:
    return ordered_list_root(
        receipts,
        item_domain=RECEIPT_ITEM_DOMAIN,
        node_domain=RECEIPT_NODE_DOMAIN,
        pad_domain=RECEIPT_PAD_DOMAIN,
        empty_domain=RECEIPT_EMPTY_DOMAIN,
        root_domain=RECEIPT_ROOT_DOMAIN,
    )


def encode_block_header(
    *,
    chain_id: int,
    height: int,
    parent_block_hash: bytes,
    pre_state_root: bytes,
    tx_root: bytes,
    receipt_root: bytes,
    post_state_root: bytes,
    tx_count: int,
) -> bytes:
    roots = (
        parent_block_hash,
        pre_state_root,
        tx_root,
        receipt_root,
        post_state_root,
    )
    if any(len(value) != HASH_SIZE for value in roots):
        raise ValueError("all block hashes and roots must be 32 bytes")

    header = b"".join(
        (
            BLOCK_DOMAIN,
            _u32(chain_id),
            _u64(height),
            parent_block_hash,
            pre_state_root,
            tx_root,
            receipt_root,
            post_state_root,
            _u32(tx_count),
        )
    )

    if len(header) != 185:
        raise AssertionError("canonical block header width changed")

    return header


def canonical_block_hash(header: bytes) -> bytes:
    if len(header) != 185 or not header.startswith(BLOCK_DOMAIN):
        raise ValueError("not a canonical Phase 3 block header")
    return h(BLOCK_HASH_DOMAIN + header)


@dataclass(frozen=True)
class BlockCommitment:
    header: bytes
    block_hash: bytes
    pre_state_root: bytes
    tx_root: bytes
    receipt_root: bytes
    post_state_root: bytes
    tx_bytes: tuple[bytes, ...]
    receipts: tuple[bytes, ...]
    final_state: dict[bytes, tuple[int, int]]


def build_block_commitment(
    pre_state: dict[bytes, tuple[int, int]],
    txs: list[Tx],
    *,
    chain_id: int,
    height: int,
    parent_block_hash: bytes,
) -> BlockCommitment:
    current = dict(pre_state)
    pre_root = state_root(current)
    encoded = [encode_tx(tx) for tx in txs]
    receipts: list[bytes] = []

    for index, (tx, raw) in enumerate(zip(txs, encoded, strict=True)):
        if tx.chain_id != chain_id:
            nxt, success = dict(current), False
        else:
            nxt, success = apply_tx(current, tx)

        current = nxt
        root_after = state_root(current)
        receipts.append(encode_receipt(index, raw, success, root_after))

    txr = transaction_root(encoded)
    rr = receipts_root(receipts)
    post_root = state_root(current)

    header = encode_block_header(
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
        pre_state_root=pre_root,
        tx_root=txr,
        receipt_root=rr,
        post_state_root=post_root,
        tx_count=len(encoded),
    )

    return BlockCommitment(
        header=header,
        block_hash=canonical_block_hash(header),
        pre_state_root=pre_root,
        tx_root=txr,
        receipt_root=rr,
        post_state_root=post_root,
        tx_bytes=tuple(encoded),
        receipts=tuple(receipts),
        final_state=current,
    )
