from __future__ import annotations

import hashlib

from tools.authenticated_state_alt import state_root_alt
from tools.reference_model_alt import encode_transaction, transition

MAX32 = 0xFFFFFFFF
MAX64 = 0xFFFFFFFFFFFFFFFF


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _be(value: int, width: int) -> bytes:
    if value < 0 or value >= (1 << (width * 8)):
        raise ValueError("integer outside canonical width")
    return value.to_bytes(width, "big")


def _list_commit(
    values: list[bytes],
    item_tag: bytes,
    node_tag: bytes,
    pad_tag: bytes,
    empty_tag: bytes,
    root_tag: bytes,
) -> bytes:
    if len(values) > MAX32:
        raise ValueError("too many values")

    layer: list[bytes] = []
    for i in range(len(values)):
        value = values[i]
        layer.append(
            _hash(item_tag + _be(i, 4) + _be(len(value), 4) + value)
        )

    if len(layer) == 0:
        tree = _hash(empty_tag)
    else:
        depth = 0
        while len(layer) != 1:
            out: list[bytes] = []
            pair = 0

            while pair < len(layer):
                left = layer[pair]
                missing = pair + 1

                if missing < len(layer):
                    right = layer[missing]
                else:
                    right = _hash(pad_tag + _be(depth, 4) + _be(missing, 4))

                out.append(_hash(node_tag + left + right))
                pair += 2

            layer = out
            depth += 1

        tree = layer[0]

    return _hash(root_tag + _be(len(values), 4) + tree)


def tx_root_alt(raw_txs: list[bytes]) -> bytes:
    return _list_commit(
        raw_txs,
        b"FLOCKTXITEM1",
        b"FLOCKTXNODE1",
        b"FLOCKTXPAD1",
        b"FLOCKTXEMPTY1",
        b"FLOCKTXROOT1",
    )


def _receipt(index: int, raw: bytes, ok: bool, root_after: bytes) -> bytes:
    if len(root_after) != 32:
        raise ValueError("bad state root")
    status = bytes((1 if ok else 0,))
    return (
        b"FLOCKRCPT1"
        + _be(index, 4)
        + _hash(raw)
        + status
        + root_after
    )


def receipt_root_alt(raw_receipts: list[bytes]) -> bytes:
    return _list_commit(
        raw_receipts,
        b"FLOCKRCPTITEM1",
        b"FLOCKRCPTNODE1",
        b"FLOCKRCPTPAD1",
        b"FLOCKRCPTEMPTY1",
        b"FLOCKRCPTROOT1",
    )


def build_block_alt(
    pre_state: dict[bytes, dict],
    txs: list[dict],
    *,
    chain_id: int,
    height: int,
    parent: bytes,
):
    if not 0 <= chain_id <= MAX32:
        raise ValueError("chain id")
    if not 0 <= height <= MAX64:
        raise ValueError("height")
    if len(parent) != 32:
        raise ValueError("parent width")

    state = {
        address: {"nonce": value["nonce"], "balance": value["balance"]}
        for address, value in pre_state.items()
    }

    pre_root = state_root_alt(
        {a: (v["nonce"], v["balance"]) for a, v in state.items()}
    )

    raws: list[bytes] = []
    raw_receipts: list[bytes] = []

    for i, tx in enumerate(txs):
        raw = encode_transaction(tx)
        raws.append(raw)

        if tx["chain_id"] != chain_id:
            next_state = {
                a: {"nonce": v["nonce"], "balance": v["balance"]}
                for a, v in state.items()
            }
            ok = False
        else:
            next_state, ok = transition(state, tx)

        state = next_state
        root_after = state_root_alt(
            {a: (v["nonce"], v["balance"]) for a, v in state.items()}
        )
        raw_receipts.append(_receipt(i, raw, ok, root_after))

    txr = tx_root_alt(raws)
    rr = receipt_root_alt(raw_receipts)
    post_root = state_root_alt(
        {a: (v["nonce"], v["balance"]) for a, v in state.items()}
    )

    header = (
        b"FLOCKBLK1"
        + _be(chain_id, 4)
        + _be(height, 8)
        + parent
        + pre_root
        + txr
        + rr
        + post_root
        + _be(len(raws), 4)
    )

    if len(header) != 185:
        raise AssertionError("header width")

    bh = _hash(b"FLOCKBLOCKHASH1" + header)

    normalized = {
        a: (v["nonce"], v["balance"])
        for a, v in state.items()
    }

    return {
        "header": header,
        "block_hash": bh,
        "pre_state_root": pre_root,
        "tx_root": txr,
        "receipt_root": rr,
        "post_state_root": post_root,
        "tx_bytes": tuple(raws),
        "receipts": tuple(raw_receipts),
        "final_state": normalized,
    }
