from __future__ import annotations

from dataclasses import dataclass
import hashlib

from tools.block_commitment import BlockCommitment, build_block_commitment
from tools.reference_model import Tx, apply_tx, encode_tx


@dataclass(frozen=True)
class BlockLimits:
    max_txs: int
    max_tx_bytes: int
    max_compute: int
    max_state: int
    max_memory: int

    def __post_init__(self) -> None:
        for name, value in (
            ("max_txs", self.max_txs),
            ("max_tx_bytes", self.max_tx_bytes),
            ("max_compute", self.max_compute),
            ("max_state", self.max_state),
            ("max_memory", self.max_memory),
        ):
            if value < 0:
                raise ValueError(f"{name} must be non-negative")


@dataclass(frozen=True)
class RejectedCandidate:
    tx_hash: bytes
    reason: str


@dataclass(frozen=True)
class ProductionResult:
    commitment: BlockCommitment
    selected: tuple[Tx, ...]
    selected_bytes: tuple[bytes, ...]
    rejected: tuple[RejectedCandidate, ...]
    total_tx_bytes: int
    total_compute: int
    total_state: int
    total_memory: int


def _candidate_key(tx: Tx, raw: bytes) -> tuple[bytes, int, bytes, int, bytes]:
    return (
        tx.sender,
        tx.nonce,
        tx.recipient,
        tx.amount,
        hashlib.sha256(raw).digest(),
    )


def produce_block(
    pre_state: dict[bytes, tuple[int, int]],
    candidates: list[Tx],
    *,
    chain_id: int,
    height: int,
    parent_block_hash: bytes,
    limits: BlockLimits,
) -> ProductionResult:
    encoded: list[tuple[Tx, bytes]] = []
    rejected: list[RejectedCandidate] = []

    for tx in candidates:
        try:
            raw = encode_tx(tx)
        except ValueError:
            # Invalid encodings cannot enter the canonical candidate set.
            # Use a stable digest of the repr only for local diagnostics;
            # it is never committed into the block.
            rejected.append(
                RejectedCandidate(
                    hashlib.sha256(repr(tx).encode("utf-8")).digest(),
                    "encoding",
                )
            )
            continue
        encoded.append((tx, raw))

    # Exact canonical duplicates are one candidate. Sorting by an explicit key
    # makes a candidate set independent of arrival/input order.
    unique: dict[bytes, Tx] = {}
    for tx, raw in encoded:
        unique.setdefault(raw, tx)

    ordered = sorted(
        ((tx, raw) for raw, tx in unique.items()),
        key=lambda item: _candidate_key(item[0], item[1]),
    )

    current = dict(pre_state)
    selected: list[Tx] = []
    selected_bytes: list[bytes] = []
    total_tx_bytes = 0
    total_compute = 0
    total_state = 0
    total_memory = 0

    for tx, raw in ordered:
        tx_hash = hashlib.sha256(raw).digest()

        if tx.chain_id != chain_id:
            rejected.append(RejectedCandidate(tx_hash, "chain_id"))
            continue

        next_count = len(selected) + 1
        next_bytes = total_tx_bytes + len(raw)
        next_compute = total_compute + tx.compute_limit
        next_state = total_state + tx.state_limit
        next_memory = total_memory + tx.memory_limit

        if next_count > limits.max_txs:
            rejected.append(RejectedCandidate(tx_hash, "tx_count"))
            continue
        if next_bytes > limits.max_tx_bytes:
            rejected.append(RejectedCandidate(tx_hash, "tx_bytes"))
            continue
        if next_compute > limits.max_compute:
            rejected.append(RejectedCandidate(tx_hash, "compute"))
            continue
        if next_state > limits.max_state:
            rejected.append(RejectedCandidate(tx_hash, "state"))
            continue
        if next_memory > limits.max_memory:
            rejected.append(RejectedCandidate(tx_hash, "memory"))
            continue

        nxt, success = apply_tx(current, tx)
        if not success:
            rejected.append(RejectedCandidate(tx_hash, "state_transition"))
            continue

        current = nxt
        selected.append(tx)
        selected_bytes.append(raw)
        total_tx_bytes = next_bytes
        total_compute = next_compute
        total_state = next_state
        total_memory = next_memory

    commitment = build_block_commitment(
        pre_state,
        selected,
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
    )

    if commitment.final_state != current:
        raise AssertionError("producer state diverged from block commitment execution")
    if commitment.tx_bytes != tuple(selected_bytes):
        raise AssertionError("producer encoding diverged from block commitment encoding")

    return ProductionResult(
        commitment=commitment,
        selected=tuple(selected),
        selected_bytes=tuple(selected_bytes),
        rejected=tuple(rejected),
        total_tx_bytes=total_tx_bytes,
        total_compute=total_compute,
        total_state=total_state,
        total_memory=total_memory,
    )
