from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from tools.block_commitment import receipts_root, transaction_root
from tools.block_producer import BlockLimits, RejectedCandidate
from tools.contract_runtime import (
    ContractRegistry,
    derive_contract_id,
    encode_deployment_receipt,
)
from tools.execution_pipeline import (
    ACTION_CONTRACT_CALL,
    ACTION_TRANSFER,
    EXECUTION_RECEIPT_DOMAIN,
    ExecutionReceipt,
    UnifiedState,
    _receipt_bytes,
    combined_state_root,
    execute_transaction,
)
from tools.flock_vm_state import decode_program
from tools.reference_model import Tx, U64_MAX, apply_tx, encode_tx

ACTION_DOMAIN = b"FLOCKACT1"
ACTION_DEPLOY = 1
DEPLOY_RECEIPT_DOMAIN = b"FLOCKACTDEPLOY1"
ACTION_BLOCK_DOMAIN = b"FLOCKACTBLK1"
ACTION_BLOCK_HASH_DOMAIN = b"FLOCKACTBLKHASH1"

ACTION_CONTRACT_DEPLOY = 2
HASH_SIZE = 32
MAX_ACTION_BYTES = 4096


@dataclass(frozen=True)
class DeployAction:
    program: bytes


@dataclass(frozen=True)
class ActionTxExecution:
    tx: Tx
    raw: bytes
    receipt: ExecutionReceipt
    final_state: UnifiedState
    final_registry_bytes: bytes


@dataclass(frozen=True)
class ActionBlockResult:
    chain_id: int
    height: int
    parent_block_hash: bytes
    pre_registry_root: bytes
    post_registry_root: bytes
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
    final_registry_bytes: bytes
    total_tx_bytes: int
    total_compute: int
    total_state: int
    total_memory: int


def encode_deploy_action(program: bytes) -> bytes:
    decode_program(program)
    if not program:
        raise ValueError("deployment program cannot be empty")
    encoded = (
        ACTION_DOMAIN
        + struct.pack(">B", ACTION_DEPLOY)
        + struct.pack(">I", len(program))
        + program
    )
    if len(encoded) > MAX_ACTION_BYTES:
        raise ValueError("deployment action exceeds transaction payload bound")
    return encoded


def decode_deploy_action(payload: bytes) -> DeployAction:
    fixed = len(ACTION_DOMAIN) + 1 + 4
    if len(payload) < fixed:
        raise ValueError("truncated deployment action")
    if not payload.startswith(ACTION_DOMAIN):
        raise ValueError("wrong action domain")

    at = len(ACTION_DOMAIN)
    kind = payload[at]
    at += 1
    if kind != ACTION_DEPLOY:
        raise ValueError("unsupported action kind")

    program_len = struct.unpack_from(">I", payload, at)[0]
    at += 4
    if program_len == 0:
        raise ValueError("deployment program cannot be empty")
    if len(payload) != at + program_len:
        raise ValueError("wrong deployment action length")

    program = payload[at:]
    decode_program(program)
    if encode_deploy_action(program) != payload:
        raise ValueError("non-canonical deployment action")
    return DeployAction(program)


def is_action_payload(payload: bytes) -> bool:
    return payload.startswith(ACTION_DOMAIN)


def make_deploy_tx(
    *,
    chain_id: int,
    nonce: int,
    sender: bytes,
    amount: int,
    compute_limit: int,
    state_limit: int,
    memory_limit: int,
    program: bytes,
) -> Tx:
    if amount == 0:
        raise ValueError("deployment endowment must be non-zero")
    contract_id = derive_contract_id(sender, nonce, program)
    return Tx(
        chain_id=chain_id,
        nonce=nonce,
        sender=sender,
        recipient=contract_id,
        amount=amount,
        compute_limit=compute_limit,
        state_limit=state_limit,
        memory_limit=memory_limit,
        payload=encode_deploy_action(program),
    )


def _action_receipt_bytes(receipt: ExecutionReceipt) -> bytes:
    if receipt.action in (ACTION_TRANSFER, ACTION_CONTRACT_CALL):
        return _receipt_bytes(receipt)

    if receipt.action != ACTION_CONTRACT_DEPLOY:
        raise ValueError("unknown execution action")

    for value, name in (
        (receipt.tx_hash, "transaction hash"),
        (receipt.pre_state_root, "pre-state root"),
        (receipt.post_state_root, "post-state root"),
        (receipt.detail_hash, "detail hash"),
    ):
        if len(value) != HASH_SIZE:
            raise ValueError(f"{name} must be 32 bytes")

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


def _clone_registry(registry: ContractRegistry) -> ContractRegistry:
    return ContractRegistry.from_bytes(registry.to_bytes())


def _deploy_detail_hash(
    *,
    tx_hash: bytes,
    contract_id: bytes,
    deployment_receipt: bytes,
    pre_registry_root: bytes,
    post_registry_root: bytes,
) -> bytes:
    return hashlib.sha256(
        DEPLOY_RECEIPT_DOMAIN
        + tx_hash
        + contract_id
        + pre_registry_root
        + post_registry_root
        + hashlib.sha256(deployment_receipt).digest()
    ).digest()


def execute_action_transaction(
    state: UnifiedState,
    registry: ContractRegistry,
    tx: Tx,
    *,
    chain_id: int,
) -> ActionTxExecution:
    raw = encode_tx(tx)
    tx_hash = hashlib.sha256(raw).digest()
    pre_root = combined_state_root(state, registry)

    if not is_action_payload(tx.payload):
        legacy = execute_transaction(
            state,
            registry,
            tx,
            chain_id=chain_id,
        )
        return ActionTxExecution(
            tx=tx,
            raw=raw,
            receipt=legacy.receipt,
            final_state=legacy.final_state,
            final_registry_bytes=registry.to_bytes(),
        )

    try:
        action = decode_deploy_action(tx.payload)
    except ValueError:
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_CONTRACT_DEPLOY,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(
                b"FLOCKDEPLOYFAIL1malformed"
            ).digest(),
        )
        return ActionTxExecution(
            tx,
            raw,
            receipt,
            _copy_state(state),
            registry.to_bytes(),
        )

    if tx.chain_id != chain_id:
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_CONTRACT_DEPLOY,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(
                b"FLOCKDEPLOYFAIL1chain_id"
            ).digest(),
        )
        return ActionTxExecution(
            tx,
            raw,
            receipt,
            _copy_state(state),
            registry.to_bytes(),
        )

    expected_contract = derive_contract_id(
        tx.sender,
        tx.nonce,
        action.program,
    )
    if tx.recipient != expected_contract:
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_CONTRACT_DEPLOY,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(
                b"FLOCKDEPLOYFAIL1recipient"
                + expected_contract
            ).digest(),
        )
        return ActionTxExecution(
            tx,
            raw,
            receipt,
            _copy_state(state),
            registry.to_bytes(),
        )

    next_accounts, transfer_ok = apply_tx(state.accounts, tx)
    if not transfer_ok:
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_CONTRACT_DEPLOY,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(
                b"FLOCKDEPLOYFAIL1account_transition"
            ).digest(),
        )
        return ActionTxExecution(
            tx,
            raw,
            receipt,
            _copy_state(state),
            registry.to_bytes(),
        )

    next_registry = _clone_registry(registry)
    pre_registry_root = next_registry.root()
    try:
        deployed = next_registry.deploy(
            tx.sender,
            tx.nonce,
            action.program,
        )
    except ValueError:
        receipt = ExecutionReceipt(
            tx_hash=tx_hash,
            action=ACTION_CONTRACT_DEPLOY,
            success=False,
            pre_state_root=pre_root,
            post_state_root=pre_root,
            detail_hash=hashlib.sha256(
                b"FLOCKDEPLOYFAIL1registry"
            ).digest(),
        )
        return ActionTxExecution(
            tx,
            raw,
            receipt,
            _copy_state(state),
            registry.to_bytes(),
        )

    if deployed.contract_id != tx.recipient:
        raise AssertionError("deployment id diverged from recipient binding")

    final_state = UnifiedState(
        accounts=next_accounts,
        contracts={
            contract_id: dict(slots)
            for contract_id, slots in state.contracts.items()
        },
    )
    post_root = combined_state_root(final_state, next_registry)
    deployment_receipt = encode_deployment_receipt(deployed)
    receipt = ExecutionReceipt(
        tx_hash=tx_hash,
        action=ACTION_CONTRACT_DEPLOY,
        success=True,
        pre_state_root=pre_root,
        post_state_root=post_root,
        detail_hash=_deploy_detail_hash(
            tx_hash=tx_hash,
            contract_id=deployed.contract_id,
            deployment_receipt=deployment_receipt,
            pre_registry_root=pre_registry_root,
            post_registry_root=next_registry.root(),
        ),
    )
    return ActionTxExecution(
        tx=tx,
        raw=raw,
        receipt=receipt,
        final_state=final_state,
        final_registry_bytes=next_registry.to_bytes(),
    )


def _candidate_key(tx: Tx, raw: bytes) -> tuple[bytes, int, bytes, int, bytes]:
    return (
        tx.sender,
        tx.nonce,
        tx.recipient,
        tx.amount,
        hashlib.sha256(raw).digest(),
    )


def _check_hash(value: bytes, name: str) -> None:
    if len(value) != HASH_SIZE:
        raise ValueError(f"{name} must be 32 bytes")


def _action_block_hash(
    *,
    chain_id: int,
    height: int,
    parent_block_hash: bytes,
    pre_registry_root: bytes,
    post_registry_root: bytes,
    pre_state_root: bytes,
    tx_root_value: bytes,
    receipt_root_value: bytes,
    post_state_root: bytes,
    tx_count: int,
) -> bytes:
    for value, name in (
        (parent_block_hash, "parent block hash"),
        (pre_registry_root, "pre-registry root"),
        (post_registry_root, "post-registry root"),
        (pre_state_root, "pre-state root"),
        (tx_root_value, "transaction root"),
        (receipt_root_value, "receipt root"),
        (post_state_root, "post-state root"),
    ):
        _check_hash(value, name)

    if not 0 <= chain_id <= (1 << 32) - 1:
        raise ValueError("chain id outside u32")
    if not 0 <= height <= U64_MAX:
        raise ValueError("height outside u64")
    if not 0 <= tx_count <= (1 << 32) - 1:
        raise ValueError("transaction count outside u32")

    header = b"".join(
        (
            ACTION_BLOCK_DOMAIN,
            struct.pack(">I", chain_id),
            struct.pack(">Q", height),
            parent_block_hash,
            pre_registry_root,
            post_registry_root,
            pre_state_root,
            tx_root_value,
            receipt_root_value,
            post_state_root,
            struct.pack(">I", tx_count),
        )
    )
    return hashlib.sha256(
        ACTION_BLOCK_HASH_DOMAIN + header
    ).digest()


def execute_action_block(
    pre_state: UnifiedState,
    registry: ContractRegistry,
    candidates: list[Tx],
    *,
    chain_id: int,
    height: int,
    parent_block_hash: bytes,
    limits: BlockLimits,
) -> ActionBlockResult:
    _check_hash(parent_block_hash, "parent block hash")

    encoded: list[tuple[Tx, bytes]] = []
    rejected: list[RejectedCandidate] = []

    for tx in candidates:
        try:
            raw = encode_tx(tx)
        except ValueError:
            rejected.append(
                RejectedCandidate(
                    hashlib.sha256(
                        repr(tx).encode("utf-8")
                    ).digest(),
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

    current_state = _copy_state(pre_state)
    current_registry = _clone_registry(registry)
    pre_registry_root = current_registry.root()
    pre_root = combined_state_root(
        current_state,
        current_registry,
    )

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
            rejected.append(
                RejectedCandidate(tx_hash, "chain_id")
            )
            continue

        next_count = len(selected) + 1
        next_bytes = total_tx_bytes + len(raw)
        next_compute = total_compute + tx.compute_limit
        next_state = total_state + tx.state_limit
        next_memory = total_memory + tx.memory_limit

        if next_count > limits.max_txs:
            rejected.append(
                RejectedCandidate(tx_hash, "tx_count")
            )
            continue
        if next_bytes > limits.max_tx_bytes:
            rejected.append(
                RejectedCandidate(tx_hash, "tx_bytes")
            )
            continue
        if next_compute > limits.max_compute:
            rejected.append(
                RejectedCandidate(tx_hash, "compute")
            )
            continue
        if next_state > limits.max_state:
            rejected.append(
                RejectedCandidate(tx_hash, "state")
            )
            continue
        if next_memory > limits.max_memory:
            rejected.append(
                RejectedCandidate(tx_hash, "memory")
            )
            continue

        executed = execute_action_transaction(
            current_state,
            current_registry,
            tx,
            chain_id=chain_id,
        )
        if not executed.receipt.success:
            rejected.append(
                RejectedCandidate(tx_hash, "execution")
            )
            continue

        current_state = executed.final_state
        current_registry = ContractRegistry.from_bytes(
            executed.final_registry_bytes
        )
        selected.append(tx)
        selected_bytes.append(raw)
        receipt_bytes.append(
            _action_receipt_bytes(executed.receipt)
        )
        total_tx_bytes = next_bytes
        total_compute = next_compute
        total_state = next_state
        total_memory = next_memory

    txr = transaction_root(selected_bytes)
    rr = receipts_root(receipt_bytes)
    post_registry_root = current_registry.root()
    post_root = combined_state_root(
        current_state,
        current_registry,
    )
    block_hash = _action_block_hash(
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
        pre_registry_root=pre_registry_root,
        post_registry_root=post_registry_root,
        pre_state_root=pre_root,
        tx_root_value=txr,
        receipt_root_value=rr,
        post_state_root=post_root,
        tx_count=len(selected),
    )

    return ActionBlockResult(
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
        pre_registry_root=pre_registry_root,
        post_registry_root=post_registry_root,
        pre_state_root=pre_root,
        tx_root=txr,
        receipt_root=rr,
        post_state_root=post_root,
        block_hash=block_hash,
        selected=tuple(selected),
        selected_bytes=tuple(selected_bytes),
        receipts=tuple(receipt_bytes),
        rejected=tuple(rejected),
        final_state=current_state,
        final_registry_bytes=current_registry.to_bytes(),
        total_tx_bytes=total_tx_bytes,
        total_compute=total_compute,
        total_state=total_state,
        total_memory=total_memory,
    )
