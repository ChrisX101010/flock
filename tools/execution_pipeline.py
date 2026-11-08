from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from tools.authenticated_state import state_root
from tools.block_commitment import receipts_root, transaction_root
from tools.block_producer import BlockLimits, RejectedCandidate
from tools.contract_runtime import ContractRegistry, call_contract
from tools.contract_state import ContractState, contract_state_root
from tools.reference_model import Tx, apply_tx, encode_tx

COMBINED_STATE_DOMAIN = b"FLOCKUSTATE1"
EXECUTION_RECEIPT_DOMAIN = b"FLOCKEXECRES1"
EXECUTION_BLOCK_DOMAIN = b"FLOCKEXECBLK1"
EXECUTION_BLOCK_HASH_DOMAIN = b"FLOCKEXECBLKHASH1"

ACTION_TRANSFER = 0
ACTION_CONTRACT_CALL = 1
HASH_SIZE = 32


@dataclass(frozen=True)
class UnifiedState:
    accounts: dict[bytes, tuple[int, int]]
    contracts: ContractState


@dataclass(frozen=True)
class ExecutionReceipt:
    tx_hash: bytes
    action: int
    success: bool
    pre_state_root: bytes
    post_state_root: bytes
    detail_hash: bytes


@dataclass(frozen=True)
class TxExecution:
    tx: Tx
    raw: bytes
    receipt: ExecutionReceipt
    final_state: UnifiedState


@dataclass(frozen=True)
class UnifiedBlockResult:
    chain_id: int
    height: int
    parent_block_hash: bytes
    registry_root: bytes
    pre_state_root: bytes
    tx_root: bytes
    receipt_root: bytes
    post_state_root: bytes
    block_hash: bytes
    selected: tuple[Tx, ...]
    selected_bytes: tuple[bytes, ...]
    receipts: tuple[bytes, ...]
    rejected: tuple[RejectedCandidate, ...]
    final_state: UnifiedState
    total_tx_bytes: int
    total_compute: int
    total_state: int
    total_memory: int


def _check_hash(value: bytes, name: str) -> None:
    if len(value) != HASH_SIZE:
        raise ValueError(f"{name} must be 32 bytes")


def combined_state_root(
    state: UnifiedState,
    registry: ContractRegistry,
) -> bytes:
    account_root = state_root(state.accounts)
    contract_root = contract_state_root(state.contracts)
    registry_commitment = registry.root()

    return hashlib.sha256(
        COMBINED_STATE_DOMAIN
        + account_root
        + contract_root
        + registry_commitment
    ).digest()


def _receipt_bytes(receipt: ExecutionReceipt) -> bytes:
    _check_hash(receipt.tx_hash, "transaction hash")
    _check_hash(receipt.pre_state_root, "pre-state root")
    _check_hash(receipt.post_state_root, "post-state root")
    _check_hash(receipt.detail_hash, "detail hash")
    if receipt.action not in (ACTION_TRANSFER, ACTION_CONTRACT_CALL):
        raise ValueError("unknown execution action")

    return b"".join(
        (
            EXECUTION_RECEIPT_DOMAIN,
            receipt.tx_hash,
            struct.pack(">B", receipt.action),
            b"\x01" if receipt.success else b"\x00",
            receipt.pre_state_root,
            receipt.post_state_root,
            receipt.detail_hash,
        )
    )


def _copy_state(state: UnifiedState) -> UnifiedState:
    return UnifiedState(
        accounts=dict(state.accounts),
        contracts={
            contract_id: dict(slots)
            for contract_id, slots in state.contracts.items()
        },
    )


def execute_transaction(
    state: UnifiedState,
    registry: ContractRegistry,
    tx: Tx,
    *,
    chain_id: int,
) -> TxExecution:
    raw = encode_tx(tx)
    tx_hash = hashlib.sha256(raw).digest()
    pre_root = combined_state_root(state, registry)

    if tx.chain_id != chain_id:
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_TRANSFER,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(b"FLOCKFAIL1chain_id").digest(),
        )
        return TxExecution(tx, raw, receipt, _copy_state(state))

    contract = registry.get(tx.recipient)

    if contract is None:
        next_accounts, success = apply_tx(state.accounts, tx)
        if success:
            final_state = UnifiedState(
                accounts=next_accounts,
                contracts={
                    contract_id: dict(slots)
                    for contract_id, slots in state.contracts.items()
                },
            )
            post_root = combined_state_root(final_state, registry)
        else:
            final_state = _copy_state(state)
            post_root = pre_root

        detail = hashlib.sha256(
            b"FLOCKTRANSFER1"
            + state_root(state.accounts)
            + state_root(final_state.accounts)
        ).digest()
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_TRANSFER,
            success=success,
            pre_state_root=pre_root,
            post_state_root=post_root,
            detail_hash=detail,
        )
        return TxExecution(tx, raw, receipt, final_state)

    # Contract calls are atomic across both account transfer and contract state.
    next_accounts, transfer_ok = apply_tx(state.accounts, tx)
    if not transfer_ok:
        final_state = _copy_state(state)
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_CONTRACT_CALL,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(
                b"FLOCKCALLFAIL1transfer"
                + contract.code_hash
            ).digest(),
        )
        return TxExecution(tx, raw, receipt, final_state)

    call = call_contract(
        registry,
        state.contracts,
        tx.recipient,
        tx,
    )
    if not call.execution.committed:
        final_state = _copy_state(state)
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_CONTRACT_CALL,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(call.receipt).digest(),
        )
        return TxExecution(tx, raw, receipt, final_state)

    final_state = UnifiedState(
        accounts=next_accounts,
        contracts={
            contract_id: dict(slots)
            for contract_id, slots in call.execution.final_state.items()
        },
    )
    post_root = combined_state_root(final_state, registry)
    receipt = ExecutionReceipt(
        tx_hash=tx_hash,
        action=ACTION_CONTRACT_CALL,
        success=True,
        pre_state_root=pre_root,
        post_state_root=post_root,
        detail_hash=hashlib.sha256(call.receipt).digest(),
    )
    return TxExecution(tx, raw, receipt, final_state)


def _candidate_key(tx: Tx, raw: bytes) -> tuple[bytes, int, bytes, int, bytes]:
    return (
        tx.sender,
        tx.nonce,
        tx.recipient,
        tx.amount,
        hashlib.sha256(raw).digest(),
    )


def _execution_block_hash(
    *,
    chain_id: int,
    height: int,
    parent_block_hash: bytes,
    registry_root_value: bytes,
    pre_state_root: bytes,
    tx_root_value: bytes,
    receipt_root_value: bytes,
    post_state_root: bytes,
    tx_count: int,
) -> bytes:
    for value, name in (
        (parent_block_hash, "parent block hash"),
        (registry_root_value, "registry root"),
        (pre_state_root, "pre-state root"),
        (tx_root_value, "transaction root"),
        (receipt_root_value, "receipt root"),
        (post_state_root, "post-state root"),
    ):
        _check_hash(value, name)

    if not 0 <= chain_id <= (1 << 32) - 1:
        raise ValueError("chain id outside u32")
    if not 0 <= height <= (1 << 64) - 1:
        raise ValueError("height outside u64")
    if not 0 <= tx_count <= (1 << 32) - 1:
        raise ValueError("tx count outside u32")

    header = b"".join(
        (
            EXECUTION_BLOCK_DOMAIN,
            struct.pack(">I", chain_id),
            struct.pack(">Q", height),
            parent_block_hash,
            registry_root_value,
            pre_state_root,
            tx_root_value,
            receipt_root_value,
            post_state_root,
            struct.pack(">I", tx_count),
        )
    )
    return hashlib.sha256(EXECUTION_BLOCK_HASH_DOMAIN + header).digest()


def execute_block(
    pre_state: UnifiedState,
    registry: ContractRegistry,
    candidates: list[Tx],
    *,
    chain_id: int,
    height: int,
    parent_block_hash: bytes,
    limits: BlockLimits,
) -> UnifiedBlockResult:
    _check_hash(parent_block_hash, "parent block hash")

    encoded: list[tuple[Tx, bytes]] = []
    rejected: list[RejectedCandidate] = []

    for tx in candidates:
        try:
            raw = encode_tx(tx)
        except ValueError:
            rejected.append(
                RejectedCandidate(
                    hashlib.sha256(repr(tx).encode("utf-8")).digest(),
                    "encoding",
                )
            )
            continue
        encoded.append((tx, raw))

    unique: dict[bytes, Tx] = {}
    for tx, raw in encoded:
        unique.setdefault(raw, tx)

    ordered = sorted(
        ((tx, raw) for raw, tx in unique.items()),
        key=lambda item: _candidate_key(item[0], item[1]),
    )

    current = _copy_state(pre_state)
    pre_root = combined_state_root(current, registry)

    selected: list[Tx] = []
    selected_bytes: list[bytes] = []
    receipt_bytes: list[bytes] = []
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

        executed = execute_transaction(
            current,
            registry,
            tx,
            chain_id=chain_id,
        )

        if not executed.receipt.success:
            rejected.append(RejectedCandidate(tx_hash, "execution"))
            continue

        current = executed.final_state
        selected.append(tx)
        selected_bytes.append(raw)
        receipt_bytes.append(_receipt_bytes(executed.receipt))
        total_tx_bytes = next_bytes
        total_compute = next_compute
        total_state = next_state
        total_memory = next_memory

    txr = transaction_root(selected_bytes)
    rr = receipts_root(receipt_bytes)
    post_root = combined_state_root(current, registry)
    registry_root_value = registry.root()
    block_hash = _execution_block_hash(
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
        registry_root_value=registry_root_value,
        pre_state_root=pre_root,
        tx_root_value=txr,
        receipt_root_value=rr,
        post_state_root=post_root,
        tx_count=len(selected),
    )

    return UnifiedBlockResult(
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
        registry_root=registry_root_value,
        pre_state_root=pre_root,
        tx_root=txr,
        receipt_root=rr,
        post_state_root=post_root,
        block_hash=block_hash,
        selected=tuple(selected),
        selected_bytes=tuple(selected_bytes),
        receipts=tuple(receipt_bytes),
        rejected=tuple(rejected),
        final_state=current,
        total_tx_bytes=total_tx_bytes,
        total_compute=total_compute,
        total_state=total_state,
        total_memory=total_memory,
    )
