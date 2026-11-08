from __future__ import annotations

import struct

from tools.flock_vm import (
    MAX_MEMORY_BYTES,
    MAX_STACK_ITEMS,
    OP_ADD,
    OP_DIV,
    OP_DUP,
    OP_HALT,
    OP_JUMP,
    OP_JUMPI,
    OP_LOAD_U64,
    OP_MUL,
    OP_PUSH_U64,
    OP_STORE_U64,
    OP_SUB,
    PROGRAM_DOMAIN,
    decode_program,
    encode_program,
    encode_receipt,
    execute_program,
    execute_transaction_payload,
)
from tools.reference_model import Tx, U64_MAX

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)


def push(value: int) -> bytes:
    return bytes([OP_PUSH_U64]) + struct.pack(">Q", value)


def jump(target: int) -> bytes:
    return bytes([OP_JUMP]) + struct.pack(">I", target)


def jumpi(target: int) -> bytes:
    return bytes([OP_JUMPI]) + struct.pack(">I", target)


def load(word: int) -> bytes:
    return bytes([OP_LOAD_U64]) + struct.pack(">H", word)


def store(word: int) -> bytes:
    return bytes([OP_STORE_U64]) + struct.pack(">H", word)


def run(code: bytes, *, compute: int = 100, memory: int = 64):
    return execute_program(
        encode_program(code),
        compute_limit=compute,
        memory_limit=memory,
    )


def main() -> None:
    raw = encode_program(push(20) + push(22) + bytes([OP_ADD, OP_HALT]))
    assert raw.startswith(PROGRAM_DOMAIN)
    decoded = decode_program(raw)
    assert encode_program(decoded.code) == raw

    result = execute_program(raw, compute_limit=10, memory_limit=64)
    assert result.status == "halted"
    assert result.stack == (42,)
    assert result.compute_used == 4
    assert encode_receipt(result) == encode_receipt(result)
    print("PHASE10_CODEC_AND_DETERMINISM=GREEN")

    arithmetic = run(
        push(6)
        + push(7)
        + bytes([OP_MUL])
        + push(2)
        + bytes([OP_DIV, OP_HALT])
    )
    assert arithmetic.status == "halted"
    assert arithmetic.stack == (21,)

    overflow = run(push(U64_MAX) + push(1) + bytes([OP_ADD, OP_HALT]))
    assert overflow.status == "arithmetic_overflow"

    underflow = run(push(1) + push(2) + bytes([OP_SUB, OP_HALT]))
    assert underflow.status == "arithmetic_underflow"

    divzero = run(push(7) + push(0) + bytes([OP_DIV, OP_HALT]))
    assert divzero.status == "division_by_zero"
    print("PHASE10_CHECKED_U64_ARITHMETIC=GREEN")

    memory = run(
        push(123456)
        + store(2)
        + load(2)
        + bytes([OP_HALT]),
        memory=32,
    )
    assert memory.status == "halted"
    assert memory.stack == (123456,)

    memory_oob = run(load(8) + bytes([OP_HALT]), memory=32)
    assert memory_oob.status == "memory_oob"
    print("PHASE10_BOUNDED_MEMORY=GREEN")

    infinite = encode_program(jump(0))
    bounded = execute_program(infinite, compute_limit=7, memory_limit=0)
    assert bounded.status == "out_of_compute"
    assert bounded.compute_used == 7
    print("PHASE10_COMPUTE_BOUND=GREEN")

    bad_jump = run(jump(2) + bytes([OP_HALT]))
    assert bad_jump.status == "invalid_jump"

    # PUSH 1; JUMPI -> HALT. Target 14 is the HALT boundary.
    conditional_code = push(1) + jumpi(14) + bytes([OP_HALT])
    conditional = run(conditional_code)
    assert conditional.status == "halted"
    print("PHASE10_CONTROL_FLOW=GREEN")

    code = (push(1) + bytes([OP_DUP])) * (MAX_STACK_ITEMS // 2)
    stack_bound = run(code + bytes([OP_DUP, OP_HALT]), compute=10000)
    assert stack_bound.status == "stack_overflow"
    print("PHASE10_STACK_BOUND=GREEN")

    fallthrough = run(push(1))
    assert fallthrough.status == "fallthrough"

    invalid = execute_program(
        b"not-flockvm",
        compute_limit=10,
        memory_limit=0,
    )
    assert invalid.status == "invalid_program"
    print("PHASE10_FAILURE_SEMANTICS=GREEN")

    tx = Tx(
        chain_id=1,
        nonce=0,
        sender=ALICE,
        recipient=BOB,
        amount=1,
        compute_limit=10,
        state_limit=0,
        memory_limit=64,
        payload=encode_program(push(40) + push(2) + bytes([OP_ADD, OP_HALT])),
    )
    tx_result = execute_transaction_payload(tx)
    assert tx_result.status == "halted"
    assert tx_result.stack == (42,)
    print("PHASE10_TRANSACTION_PAYLOAD_INTEGRATION=GREEN")

    max_mem_program = run(bytes([OP_HALT]), memory=MAX_MEMORY_BYTES)
    assert max_mem_program.status == "halted"

    again = execute_transaction_payload(tx)
    assert again == tx_result
    assert encode_receipt(again) == encode_receipt(tx_result)
    print("PHASE10_REPEAT_EXECUTION_BYTE_IDENTICAL=GREEN")

    print("FLOCK_PHASE10_FLOCKVM_CORE=GREEN")


if __name__ == "__main__":
    main()
