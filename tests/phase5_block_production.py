from __future__ import annotations

import itertools
import tempfile
from pathlib import Path

from tools.authenticated_state import parse_canonical_state
from tools.block_producer import BlockLimits, produce_block
from tools.chain_store import ChainStore, encode_persisted_block
from tools.reference_model import Tx

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)
CAROL = bytes.fromhex("33" * 32)
DAVE = bytes.fromhex("44" * 32)
ZERO = bytes(32)


def tx(
    sender: bytes,
    recipient: bytes,
    nonce: int,
    amount: int,
    *,
    chain_id: int = 1,
    compute: int = 10,
    state: int = 2,
    memory: int = 4,
    payload: bytes = b"p5",
) -> Tx:
    return Tx(
        chain_id=chain_id,
        nonce=nonce,
        sender=sender,
        recipient=recipient,
        amount=amount,
        compute_limit=compute,
        state_limit=state,
        memory_limit=memory,
        payload=payload,
    )


def main() -> None:
    genesis = {
        ALICE: (0, 1000),
        BOB: (0, 500),
        CAROL: (0, 0),
        DAVE: (0, 0),
    }

    a0 = tx(ALICE, BOB, 0, 100, payload=b"a0")
    a1 = tx(ALICE, CAROL, 1, 50, payload=b"a1")
    b0 = tx(BOB, DAVE, 0, 25, payload=b"b0")
    bad_nonce = tx(CAROL, DAVE, 7, 1, payload=b"bad-nonce")
    wrong_chain = tx(DAVE, ALICE, 0, 1, chain_id=2, payload=b"wrong-chain")
    too_compute = tx(DAVE, ALICE, 0, 1, compute=10_000, payload=b"too-compute")

    # Keep the baseline count budget loose enough that invalid candidates
    # reach their own admission checks. A separate case below tests max_txs.
    limits = BlockLimits(
        max_txs=10,
        max_tx_bytes=4096,
        max_compute=100,
        max_state=100,
        max_memory=100,
    )

    candidates = [b0, wrong_chain, a1, a0, bad_nonce, too_compute, a0]

    baseline = produce_block(
        genesis,
        candidates,
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits,
    )

    assert baseline.selected == (a0, a1, b0)
    assert baseline.commitment.tx_bytes == baseline.selected_bytes
    assert baseline.total_compute == 30
    assert baseline.total_state == 6
    assert baseline.total_memory == 12
    assert any(r.reason == "chain_id" for r in baseline.rejected)
    assert any(r.reason == "state_transition" for r in baseline.rejected)
    assert any(r.reason == "compute" for r in baseline.rejected)
    print("CANONICAL_SELECTION=GREEN")
    print("INVALID_CANDIDATES_FILTERED=GREEN")
    print("DUPLICATE_CANDIDATE_DEDUPED=GREEN")

    # Every permutation of a compact four-item set must yield exactly the same
    # block. This proves arrival/input order is not part of block identity.
    small = [a0, a1, b0, wrong_chain]
    expected_hash = None
    expected_header = None
    expected_txs = None
    for perm in itertools.permutations(small):
        result = produce_block(
            genesis,
            list(perm),
            chain_id=1,
            height=0,
            parent_block_hash=ZERO,
            limits=limits,
        )
        if expected_hash is None:
            expected_hash = result.commitment.block_hash
            expected_header = result.commitment.header
            expected_txs = result.commitment.tx_bytes
        else:
            assert result.commitment.block_hash == expected_hash
            assert result.commitment.header == expected_header
            assert result.commitment.tx_bytes == expected_txs
    print("INPUT_ORDER_INVARIANT=GREEN")

    # Tight count limit deterministically admits only the first two canonical
    # valid transactions.
    count_limited = produce_block(
        genesis,
        [b0, a1, a0],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=BlockLimits(
            max_txs=2,
            max_tx_bytes=4096,
            max_compute=100,
            max_state=100,
            max_memory=100,
        ),
    )
    assert count_limited.selected == (a0, a1)
    assert any(r.reason == "tx_count" for r in count_limited.rejected)
    print("BLOCK_TX_COUNT_LIMIT=GREEN")

    # A compute-heavy candidate is skipped without consuming budget, so later
    # canonical candidates may still enter.
    budgeted = produce_block(
        genesis,
        [too_compute, b0, a0],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits,
    )
    assert budgeted.selected == (a0, b0)
    assert budgeted.total_compute == 20
    print("BLOCK_RESOURCE_LIMITS=GREEN")

    # Phase 5 output must be a valid Phase 4 record and survive restart.
    with tempfile.TemporaryDirectory(prefix="flock-phase5-") as td:
        store = ChainStore(Path(td) / "chain")
        rec0 = encode_persisted_block(baseline.commitment)
        appended0 = store.append(rec0)
        assert appended0.block_hash == baseline.commitment.block_hash

        restarted = ChainStore(Path(td) / "chain")
        tip0 = restarted.tip()
        assert tip0 is not None
        state0 = parse_canonical_state(tip0.post_state_bytes)

        c0 = tx(CAROL, DAVE, 0, 10, payload=b"c0")
        d0 = tx(DAVE, ALICE, 0, 5, payload=b"d0")
        next_result = produce_block(
            state0,
            [d0, c0],
            chain_id=1,
            height=tip0.fields.height + 1,
            parent_block_hash=tip0.block_hash,
            limits=limits,
        )
        rec1 = encode_persisted_block(next_result.commitment)
        appended1 = restarted.append(rec1)

        assert appended1.fields.height == 1
        assert appended1.fields.parent_block_hash == tip0.block_hash
        verified = ChainStore(Path(td) / "chain").verify_chain()
        assert len(verified) == 2
        assert verified[-1].block_hash == next_result.commitment.block_hash
        print("PHASE4_STORE_INTEGRATION=GREEN")
        print("RESTARTED_PRODUCTION_CHAIN=GREEN")

    # Repeat production byte-for-byte.
    again = produce_block(
        genesis,
        list(reversed(candidates)),
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits,
    )
    assert encode_persisted_block(again.commitment) == encode_persisted_block(baseline.commitment)
    print("PHASE5_REPEATED_BLOCK=BYTE_IDENTICAL")

    print(f"PHASE5_BLOCK_HASH={baseline.commitment.block_hash.hex()}")
    print(f"PHASE5_TX_COUNT={len(baseline.selected)}")
    print("FLOCK_PHASE5_BLOCK_PRODUCTION=GREEN")


if __name__ == "__main__":
    main()
