from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.authenticated_state import parse_canonical_state, state_root  # noqa: E402
from tools.block_commitment import build_block_commitment  # noqa: E402
from tools.block_commitment_alt import build_block_alt  # noqa: E402
from tools.reference_model import Tx, encode_state  # noqa: E402


if len(sys.argv) != 3:
    raise SystemExit(
        "usage: phase3_block_commitment.py GOOSE_TX.bin GOOSE_STATE.bin"
    )

goose_tx = Path(sys.argv[1]).read_bytes()
goose_state = Path(sys.argv[2]).read_bytes()

alice = bytes.fromhex("11" * 32)
bob = bytes.fromhex("22" * 32)
zero_parent = bytes(32)

genesis = {
    alice: (0, 1000),
    bob: (0, 0),
}

tx1 = Tx(
    chain_id=1,
    nonce=0,
    sender=alice,
    recipient=bob,
    amount=125,
    compute_limit=100000,
    state_limit=64,
    memory_limit=1048576,
    payload=b"phase0",
)

# Invalid nonce: must receive a failure receipt and leave state unchanged.
tx2 = Tx(
    chain_id=1,
    nonce=99,
    sender=alice,
    recipient=bob,
    amount=50,
    compute_limit=100000,
    state_limit=64,
    memory_limit=1048576,
    payload=b"invalid",
)

# Valid only after tx1 has funded Bob.
tx3 = Tx(
    chain_id=1,
    nonce=0,
    sender=bob,
    recipient=alice,
    amount=25,
    compute_limit=100000,
    state_limit=64,
    memory_limit=1048576,
    payload=b"return",
)


def alt_tx(tx: Tx) -> dict:
    return {
        "chain_id": tx.chain_id,
        "nonce": tx.nonce,
        "sender": tx.sender,
        "recipient": tx.recipient,
        "amount": tx.amount,
        "compute_limit": tx.compute_limit,
        "state_limit": tx.state_limit,
        "memory_limit": tx.memory_limit,
        "payload": tx.payload,
    }


def alt_state(state: dict[bytes, tuple[int, int]]) -> dict:
    return {
        address: {"nonce": nonce, "balance": balance}
        for address, (nonce, balance) in state.items()
    }


# Single-transaction canonical vector, fed by Phase 1 Goose bytes.
single = build_block_commitment(
    genesis,
    [tx1],
    chain_id=1,
    height=1,
    parent_block_hash=zero_parent,
)
single_alt = build_block_alt(
    alt_state(genesis),
    [alt_tx(tx1)],
    chain_id=1,
    height=1,
    parent=zero_parent,
)

assert goose_tx == single.tx_bytes[0]
assert parse_canonical_state(goose_state) == single.final_state
assert goose_state == encode_state(single.final_state)

assert single.header == single_alt["header"]
assert single.block_hash == single_alt["block_hash"]
assert single.pre_state_root == single_alt["pre_state_root"]
assert single.tx_root == single_alt["tx_root"]
assert single.receipt_root == single_alt["receipt_root"]
assert single.post_state_root == single_alt["post_state_root"]
assert single.receipts == single_alt["receipts"]

# Frozen Phase 3 vector. These values must not change without a new version.
assert single.pre_state_root.hex() == (
    "8aaadb338ccf9c7f00142f3d2ec2689acf1c20e4311ed97c51f3e4ae5131a832"
)
assert single.post_state_root.hex() == (
    "5a9bf29928781c70b63dd7c60a9f0b368fd2bd81a08d13a3cca5f3d5fb008cad"
)
assert single.tx_root.hex() == (
    "6a56925ba5ac050d6e0e62332700d93c43f97f3fe183b4a4880fd19b114d8b8f"
)
assert single.receipt_root.hex() == (
    "b3f7203a62e406f2ca9fc147d00f8c0df22180a0c814ae64ad2d21662462fd81"
)
assert single.block_hash.hex() == (
    "e2b616d283d58d774bdca4d1c9fa40f9990900e9bcea76ab40b53332d913f782"
)
assert len(single.header) == 185

# Three transactions exercise order, invalid atomicity and odd-tree padding.
ordered = build_block_commitment(
    genesis,
    [tx1, tx2, tx3],
    chain_id=1,
    height=2,
    parent_block_hash=single.block_hash,
)
ordered_alt = build_block_alt(
    alt_state(genesis),
    [alt_tx(tx1), alt_tx(tx2), alt_tx(tx3)],
    chain_id=1,
    height=2,
    parent=single.block_hash,
)

assert ordered.header == ordered_alt["header"]
assert ordered.block_hash == ordered_alt["block_hash"]
assert ordered.final_state == ordered_alt["final_state"]
assert ordered.receipts == ordered_alt["receipts"]
assert ordered.final_state == {
    alice: (1, 900),
    bob: (1, 100),
}

# Receipt status byte sits after domain + index + tx hash.
status_offset = len(b"FLOCKRCPT1") + 4 + 32
assert ordered.receipts[0][status_offset] == 1
assert ordered.receipts[1][status_offset] == 0
assert ordered.receipts[2][status_offset] == 1

# The failed second transaction must commit the same state root as after tx1.
root_after_tx1 = ordered.receipts[0][-32:]
root_after_invalid = ordered.receipts[1][-32:]
assert root_after_invalid == root_after_tx1

# Order is consensus-visible.
reordered = build_block_commitment(
    genesis,
    [tx3, tx1, tx2],
    chain_id=1,
    height=2,
    parent_block_hash=single.block_hash,
)
assert reordered.tx_root != ordered.tx_root
assert reordered.receipt_root != ordered.receipt_root
assert reordered.block_hash != ordered.block_hash

# Empty block keeps state unchanged.
empty = build_block_commitment(
    genesis,
    [],
    chain_id=1,
    height=2,
    parent_block_hash=single.block_hash,
)
empty_alt = build_block_alt(
    alt_state(genesis),
    [],
    chain_id=1,
    height=2,
    parent=single.block_hash,
)
assert empty.header == empty_alt["header"]
assert empty.block_hash == empty_alt["block_hash"]
assert empty.pre_state_root == empty.post_state_root == state_root(genesis)
assert empty.final_state == genesis

# Header metadata is committed.
height_changed = build_block_commitment(
    genesis,
    [tx1],
    chain_id=1,
    height=2,
    parent_block_hash=zero_parent,
)
parent_changed = build_block_commitment(
    genesis,
    [tx1],
    chain_id=1,
    height=1,
    parent_block_hash=bytes.fromhex("aa" * 32),
)
assert height_changed.block_hash != single.block_hash
assert parent_changed.block_hash != single.block_hash

# A wrong-chain transaction is a receipt-level invalid transition.
wrong_chain = Tx(
    chain_id=2,
    nonce=0,
    sender=alice,
    recipient=bob,
    amount=125,
    compute_limit=100000,
    state_limit=64,
    memory_limit=1048576,
    payload=b"phase0",
)
wrong = build_block_commitment(
    genesis,
    [wrong_chain],
    chain_id=1,
    height=1,
    parent_block_hash=zero_parent,
)
assert wrong.final_state == genesis
assert wrong.receipts[0][status_offset] == 0

# Determinism gate.
repeat = build_block_commitment(
    genesis,
    [tx1],
    chain_id=1,
    height=1,
    parent_block_hash=zero_parent,
)
assert repeat.header == single.header
assert repeat.block_hash == single.block_hash
assert repeat.receipts == single.receipts

print(f"PRE_STATE_ROOT={single.pre_state_root.hex()}")
print(f"TX_ROOT={single.tx_root.hex()}")
print(f"RECEIPT_ROOT={single.receipt_root.hex()}")
print(f"POST_STATE_ROOT={single.post_state_root.hex()}")
print(f"BLOCK_HASH={single.block_hash.hex()}")
print("BLOCK_ORACLE_A_EQUALS_B=GREEN")
print("GOOSE_TX_FEEDS_BLOCK=GREEN")
print("GOOSE_POST_STATE_FEEDS_BLOCK=GREEN")
print("ORDERED_TX_ROOT=GREEN")
print("INVALID_TX_RECEIPT_ATOMICITY=GREEN")
print("EMPTY_BLOCK_STATE_INVARIANT=GREEN")
print("HEADER_METADATA_COMMITTED=GREEN")
print("PHASE3_REPEATED_BLOCK=BYTE_IDENTICAL")
print("FLOCK_PHASE3_BLOCK_COMMITMENTS=GREEN")
