from __future__ import annotations

import struct

from tools.contract_state import (
    CONTRACT_STATE_DOMAIN,
    contract_state_root,
    decode_contract_state,
    encode_contract_receipt,
    encode_contract_state,
    execute_contract_program,
    execute_contract_transaction,
)
from tools.flock_vm import (
    OP_ADD as V1_ADD,
    OP_HALT as V1_HALT,
    OP_PUSH_U64 as V1_PUSH,
    encode_program as encode_v1,
    execute_program as execute_v1,
)
from tools.flock_vm_state import (
    OP_ADD,
    OP_HALT,
    OP_PUSH_U64,
    OP_REVERT,
    OP_SLOAD_U64,
    OP_SSTORE_U64,
    encode_program,
    execute_program,
)
from tools.reference_model import Tx, U64_MAX

CONTRACT = bytes.fromhex("aa" * 32)
OTHER = bytes.fromhex("bb" * 32)
ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)


def push(value: int) -> bytes:
    return bytes([OP_PUSH_U64]) + struct.pack(">Q", value)


def push_v1(value: int) -> bytes:
    return bytes([V1_PUSH]) + struct.pack(">Q", value)


def sload(slot: int) -> bytes:
    return push(slot) + bytes([OP_SLOAD_U64])


def sstore(slot: int, value: int) -> bytes:
    return push(slot) + push(value) + bytes([OP_SSTORE_U64])


def execute(state, code, *, state_limit=8):
    return execute_contract_program(
        state,
        CONTRACT,
        encode_program(code),
        compute_limit=100,
        state_limit=state_limit,
        memory_limit=64,
    )


def main() -> None:
    v1 = execute_v1(
        encode_v1(push_v1(20) + push_v1(22) + bytes([V1_ADD, V1_HALT])),
        compute_limit=10,
        memory_limit=64,
    )
    v2 = execute_program(
        encode_program(push(20) + push(22) + bytes([OP_ADD, OP_HALT])),
        compute_limit=10,
        state_limit=0,
        memory_limit=64,
    )
    assert v2.status == v1.status
    assert v2.compute_used == v1.compute_used
    assert v2.state_used == 0
    assert v2.pc == v1.pc
    assert v2.stack == v1.stack
    assert v2.memory == v1.memory
    print("PHASE11_VM1_VM2_STORAGE_FREE_CONFORMANCE=GREEN")

    unordered = {
        OTHER: {9: 7, 2: 3},
        CONTRACT: {5: 10, 1: 20, 99: 0},
    }
    raw = encode_contract_state(unordered)
    assert raw.startswith(CONTRACT_STATE_DOMAIN)
    decoded = decode_contract_state(raw)
    assert 99 not in decoded[CONTRACT]
    assert encode_contract_state(decoded) == raw

    reordered = {
        CONTRACT: {1: 20, 5: 10},
        OTHER: {2: 3, 9: 7},
    }
    assert encode_contract_state(reordered) == raw
    assert contract_state_root(reordered) == contract_state_root(unordered)
    print("PHASE11_CANONICAL_CONTRACT_STATE=GREEN")

    empty_root = contract_state_root({})
    committed = execute(
        {},
        sstore(7, 42) + sload(7) + bytes([OP_HALT]),
        state_limit=2,
    )
    assert committed.committed
    assert committed.vm_result.status == "halted"
    assert committed.vm_result.state_used == 2
    assert committed.vm_result.stack == (42,)
    assert committed.final_state == {CONTRACT: {7: 42}}
    assert committed.pre_root == empty_root
    assert committed.post_root != committed.pre_root
    print("PHASE11_PERSISTENT_SLOAD_SSTORE=GREEN")

    read_back = execute(
        committed.final_state,
        sload(7) + bytes([OP_HALT]),
        state_limit=1,
    )
    assert read_back.committed
    assert read_back.vm_result.stack == (42,)
    assert read_back.pre_root == committed.post_root
    assert read_back.post_root == committed.post_root
    print("PHASE11_PERSISTENCE_READBACK=GREEN")

    before = committed.final_state
    before_root = contract_state_root(before)

    reverted = execute(
        before,
        sstore(7, 99) + bytes([OP_REVERT]),
        state_limit=1,
    )
    assert not reverted.committed
    assert reverted.vm_result.status == "reverted"
    assert reverted.final_state == before
    assert reverted.post_root == before_root
    print("PHASE11_REVERT_ROLLBACK=GREEN")

    arithmetic_fail = execute(
        before,
        sstore(8, 5)
        + push(U64_MAX)
        + push(1)
        + bytes([OP_ADD, OP_HALT]),
        state_limit=1,
    )
    assert not arithmetic_fail.committed
    assert arithmetic_fail.vm_result.status == "arithmetic_overflow"
    assert arithmetic_fail.final_state == before
    assert arithmetic_fail.post_root == before_root
    print("PHASE11_FAILURE_ATOMICITY=GREEN")

    state_exhausted = execute(
        before,
        sstore(9, 1) + sload(9) + bytes([OP_HALT]),
        state_limit=1,
    )
    assert not state_exhausted.committed
    assert state_exhausted.vm_result.status == "out_of_state"
    assert state_exhausted.vm_result.state_used == 1
    assert state_exhausted.final_state == before
    assert state_exhausted.post_root == before_root
    print("PHASE11_STATE_BUDGET_ROLLBACK=GREEN")

    deleted = execute(
        before,
        sstore(7, 0) + bytes([OP_HALT]),
        state_limit=1,
    )
    assert deleted.committed
    assert deleted.final_state == {}
    assert deleted.post_root == empty_root
    print("PHASE11_ZERO_DELETE_CANONICAL=GREEN")

    tx = Tx(
        chain_id=1,
        nonce=0,
        sender=ALICE,
        recipient=BOB,
        amount=1,
        compute_limit=100,
        state_limit=2,
        memory_limit=64,
        payload=encode_program(
            sstore(3, 77) + sload(3) + bytes([OP_HALT])
        ),
    )
    tx_result = execute_contract_transaction({}, CONTRACT, tx)
    assert tx_result.committed
    assert tx_result.vm_result.stack == (77,)
    assert tx_result.final_state == {CONTRACT: {3: 77}}
    print("PHASE11_TRANSACTION_STATE_INTEGRATION=GREEN")

    first = execute(
        {},
        sstore(1, 123) + sload(1) + bytes([OP_HALT]),
        state_limit=2,
    )
    second = execute(
        {},
        sstore(1, 123) + sload(1) + bytes([OP_HALT]),
        state_limit=2,
    )
    assert first == second
    assert encode_contract_receipt(first) == encode_contract_receipt(second)
    print("PHASE11_REPEAT_EXECUTION_BYTE_IDENTICAL=GREEN")

    print("FLOCK_PHASE11_VERSIONED_ATOMIC_CONTRACT_STATE=GREEN")


if __name__ == "__main__":
    main()
