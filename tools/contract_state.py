from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from tools.flock_vm_state import (
    StateExecutionResult,
    encode_receipt,
    execute_program,
)
from tools.reference_model import Tx, U64_MAX

CONTRACT_STATE_DOMAIN = b"FLOCKCSTATE1"
CONTRACT_RECEIPT_DOMAIN = b"FLOCKCRES1"
STORAGE_KEY_DOMAIN = b"FLOCKSKEY1"
STORAGE_EMPTY_DOMAIN = b"FLOCKSEMPTY1"
STORAGE_LEAF_DOMAIN = b"FLOCKSLEAF1"
STORAGE_NODE_DOMAIN = b"FLOCKSNODE1"

TREE_DEPTH = 256
HASH_SIZE = 32

ContractState = dict[bytes, dict[int, int]]


@dataclass(frozen=True)
class ContractExecution:
    vm_result: StateExecutionResult
    committed: bool
    pre_root: bytes
    post_root: bytes
    final_state: ContractState


def _check_contract_id(contract_id: bytes) -> None:
    if len(contract_id) != 32:
        raise ValueError("contract id must be exactly 32 bytes")


def _check_u64(value: int) -> None:
    if not 0 <= value <= U64_MAX:
        raise ValueError("u64 out of range")


def canonicalize_contract_state(state: ContractState) -> ContractState:
    out: ContractState = {}
    for contract_id, slots in state.items():
        _check_contract_id(contract_id)
        canonical_slots: dict[int, int] = {}
        for slot, value in slots.items():
            _check_u64(slot)
            _check_u64(value)
            if value != 0:
                canonical_slots[slot] = value
        if canonical_slots:
            out[contract_id] = canonical_slots
    return out


def encode_contract_state(state: ContractState) -> bytes:
    canonical = canonicalize_contract_state(state)
    if len(canonical) > (1 << 32) - 1:
        raise ValueError("too many contracts")

    out = bytearray(CONTRACT_STATE_DOMAIN)
    out += struct.pack(">I", len(canonical))

    for contract_id in sorted(canonical):
        slots = canonical[contract_id]
        if len(slots) > (1 << 32) - 1:
            raise ValueError("too many storage slots")

        out += contract_id
        out += struct.pack(">I", len(slots))
        for slot in sorted(slots):
            out += struct.pack(">Q", slot)
            out += struct.pack(">Q", slots[slot])

    return bytes(out)


def decode_contract_state(raw: bytes) -> ContractState:
    if not raw.startswith(CONTRACT_STATE_DOMAIN):
        raise ValueError("wrong contract-state domain")

    at = len(CONTRACT_STATE_DOMAIN)
    if len(raw) < at + 4:
        raise ValueError("truncated contract count")

    contract_count = struct.unpack_from(">I", raw, at)[0]
    at += 4
    state: ContractState = {}
    previous_contract: bytes | None = None

    for _ in range(contract_count):
        if len(raw) < at + 36:
            raise ValueError("truncated contract entry")

        contract_id = raw[at : at + 32]
        at += 32
        slot_count = struct.unpack_from(">I", raw, at)[0]
        at += 4

        if previous_contract is not None and contract_id <= previous_contract:
            raise ValueError("contracts are not in canonical order")
        previous_contract = contract_id

        slots: dict[int, int] = {}
        previous_slot: int | None = None

        for _ in range(slot_count):
            if len(raw) < at + 16:
                raise ValueError("truncated storage slot")

            slot = struct.unpack_from(">Q", raw, at)[0]
            value = struct.unpack_from(">Q", raw, at + 8)[0]
            at += 16

            if value == 0:
                raise ValueError("zero storage values are non-canonical")
            if previous_slot is not None and slot <= previous_slot:
                raise ValueError("storage slots are not in canonical order")

            slots[slot] = value
            previous_slot = slot

        if not slots:
            raise ValueError("empty contract entry is non-canonical")
        state[contract_id] = slots

    if at != len(raw):
        raise ValueError("trailing contract-state bytes")
    if encode_contract_state(state) != raw:
        raise ValueError("non-canonical contract state")
    return state


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


EMPTY = [b""] * (TREE_DEPTH + 1)
EMPTY[TREE_DEPTH] = _h(STORAGE_EMPTY_DOMAIN)
for depth in range(TREE_DEPTH - 1, -1, -1):
    EMPTY[depth] = _h(
        STORAGE_NODE_DOMAIN
        + EMPTY[depth + 1]
        + EMPTY[depth + 1]
    )


def storage_key(contract_id: bytes, slot: int) -> bytes:
    _check_contract_id(contract_id)
    _check_u64(slot)
    return _h(
        STORAGE_KEY_DOMAIN
        + contract_id
        + struct.pack(">Q", slot)
    )


def storage_leaf_hash(contract_id: bytes, slot: int, value: int) -> bytes:
    _check_contract_id(contract_id)
    _check_u64(slot)
    _check_u64(value)
    if value == 0:
        raise ValueError("zero values use the empty leaf")

    return _h(
        STORAGE_LEAF_DOMAIN
        + contract_id
        + struct.pack(">Q", slot)
        + struct.pack(">Q", value)
    )


def contract_state_root(state: ContractState) -> bytes:
    canonical = canonicalize_contract_state(state)
    nodes: dict[int, bytes] = {}

    for contract_id, slots in canonical.items():
        for slot, value in slots.items():
            index = int.from_bytes(storage_key(contract_id, slot), "big")
            if index in nodes:
                raise ValueError("storage-key collision")
            nodes[index] = storage_leaf_hash(contract_id, slot, value)

    if not nodes:
        return EMPTY[0]

    for depth in range(TREE_DEPTH - 1, -1, -1):
        child_empty = EMPTY[depth + 1]
        parents = {index >> 1 for index in nodes}
        nodes = {
            parent: _h(
                STORAGE_NODE_DOMAIN
                + nodes.get(parent << 1, child_empty)
                + nodes.get((parent << 1) | 1, child_empty)
            )
            for parent in parents
        }

    return nodes[0]


def execute_contract_program(
    state: ContractState,
    contract_id: bytes,
    raw_program: bytes,
    *,
    compute_limit: int,
    state_limit: int,
    memory_limit: int,
) -> ContractExecution:
    _check_contract_id(contract_id)

    base = canonicalize_contract_state(state)
    working = {key: dict(slots) for key, slots in base.items()}
    contract_slots = working.setdefault(contract_id, {})

    def storage_read(slot: int) -> int:
        _check_u64(slot)
        return contract_slots.get(slot, 0)

    def storage_write(slot: int, value: int) -> None:
        _check_u64(slot)
        _check_u64(value)
        if value == 0:
            contract_slots.pop(slot, None)
        else:
            contract_slots[slot] = value

    pre_root = contract_state_root(base)
    vm_result = execute_program(
        raw_program,
        compute_limit=compute_limit,
        state_limit=state_limit,
        memory_limit=memory_limit,
        storage_read=storage_read,
        storage_write=storage_write,
    )

    if vm_result.status == "halted":
        final_state = canonicalize_contract_state(working)
        committed = True
    else:
        final_state = base
        committed = False

    post_root = contract_state_root(final_state)
    if not committed and post_root != pre_root:
        raise AssertionError("failed contract execution mutated state")

    return ContractExecution(
        vm_result=vm_result,
        committed=committed,
        pre_root=pre_root,
        post_root=post_root,
        final_state=final_state,
    )


def execute_contract_transaction(
    state: ContractState,
    contract_id: bytes,
    tx: Tx,
) -> ContractExecution:
    return execute_contract_program(
        state,
        contract_id,
        tx.payload,
        compute_limit=tx.compute_limit,
        state_limit=tx.state_limit,
        memory_limit=tx.memory_limit,
    )


def encode_contract_receipt(result: ContractExecution) -> bytes:
    if len(result.pre_root) != HASH_SIZE or len(result.post_root) != HASH_SIZE:
        raise ValueError("contract state roots must be 32 bytes")

    vm_receipt_hash = hashlib.sha256(
        encode_receipt(result.vm_result)
    ).digest()

    return b"".join(
        (
            CONTRACT_RECEIPT_DOMAIN,
            b"\x01" if result.committed else b"\x00",
            result.pre_root,
            result.post_root,
            vm_receipt_hash,
        )
    )
