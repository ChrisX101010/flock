from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Callable

from tools.reference_model import U64_MAX

PROGRAM_DOMAIN = b"FLOCKVM2"
RECEIPT_DOMAIN = b"FLOCKVM2RES1"
PROGRAM_VERSION = 2

MAX_CODE_BYTES = 16 * 1024
MAX_STACK_ITEMS = 1024
MAX_MEMORY_BYTES = 64 * 1024

OP_HALT = 0x00
OP_PUSH_U64 = 0x01
OP_ADD = 0x02
OP_SUB = 0x03
OP_MUL = 0x04
OP_DIV = 0x05
OP_MOD = 0x06
OP_EQ = 0x07
OP_LT = 0x08
OP_GT = 0x09
OP_DUP = 0x0A
OP_DROP = 0x0B
OP_SWAP = 0x0C
OP_LOAD_U64 = 0x10
OP_STORE_U64 = 0x11
OP_SLOAD_U64 = 0x12
OP_SSTORE_U64 = 0x13
OP_JUMP = 0x20
OP_JUMPI = 0x21
OP_REVERT = 0x30

IMMEDIATE_LEN = {
    OP_HALT: 0,
    OP_PUSH_U64: 8,
    OP_ADD: 0,
    OP_SUB: 0,
    OP_MUL: 0,
    OP_DIV: 0,
    OP_MOD: 0,
    OP_EQ: 0,
    OP_LT: 0,
    OP_GT: 0,
    OP_DUP: 0,
    OP_DROP: 0,
    OP_SWAP: 0,
    OP_LOAD_U64: 2,
    OP_STORE_U64: 2,
    OP_SLOAD_U64: 0,
    OP_SSTORE_U64: 0,
    OP_JUMP: 4,
    OP_JUMPI: 4,
    OP_REVERT: 0,
}

COMPUTE_COST = {
    OP_HALT: 1,
    OP_PUSH_U64: 1,
    OP_ADD: 1,
    OP_SUB: 1,
    OP_MUL: 3,
    OP_DIV: 3,
    OP_MOD: 3,
    OP_EQ: 1,
    OP_LT: 1,
    OP_GT: 1,
    OP_DUP: 1,
    OP_DROP: 1,
    OP_SWAP: 1,
    OP_LOAD_U64: 2,
    OP_STORE_U64: 2,
    OP_SLOAD_U64: 3,
    OP_SSTORE_U64: 5,
    OP_JUMP: 1,
    OP_JUMPI: 1,
    OP_REVERT: 1,
}

STATUS_CODE = {
    "halted": 0,
    "reverted": 1,
    "out_of_compute": 2,
    "stack_underflow": 3,
    "stack_overflow": 4,
    "arithmetic_overflow": 5,
    "arithmetic_underflow": 6,
    "division_by_zero": 7,
    "memory_oob": 8,
    "invalid_jump": 9,
    "invalid_program": 10,
    "fallthrough": 11,
    "out_of_state": 12,
    "storage_unavailable": 13,
    "invalid_host_state": 14,
}


@dataclass(frozen=True)
class Program:
    version: int
    code: bytes


@dataclass(frozen=True)
class StateExecutionResult:
    status: str
    compute_used: int
    state_used: int
    pc: int
    stack: tuple[int, ...]
    memory: bytes


def encode_program(code: bytes, *, version: int = PROGRAM_VERSION) -> bytes:
    if version != PROGRAM_VERSION:
        raise ValueError("unsupported FlockVM version")
    if len(code) > MAX_CODE_BYTES:
        raise ValueError("program too large")
    return PROGRAM_DOMAIN + struct.pack(">H", version) + struct.pack(">I", len(code)) + code


def decode_program(raw: bytes) -> Program:
    fixed = len(PROGRAM_DOMAIN) + 2 + 4
    if len(raw) < fixed:
        raise ValueError("truncated program")
    if not raw.startswith(PROGRAM_DOMAIN):
        raise ValueError("wrong program domain")

    at = len(PROGRAM_DOMAIN)
    version = struct.unpack_from(">H", raw, at)[0]
    at += 2
    if version != PROGRAM_VERSION:
        raise ValueError("unsupported FlockVM version")

    code_len = struct.unpack_from(">I", raw, at)[0]
    at += 4
    if code_len > MAX_CODE_BYTES:
        raise ValueError("program too large")
    if len(raw) != at + code_len:
        raise ValueError("wrong program length")

    code = raw[at:]
    _instruction_boundaries(code)
    if encode_program(code, version=version) != raw:
        raise ValueError("non-canonical program")
    return Program(version, code)


def _instruction_boundaries(code: bytes) -> frozenset[int]:
    boundaries: set[int] = set()
    at = 0
    while at < len(code):
        boundaries.add(at)
        opcode = code[at]
        imm_len = IMMEDIATE_LEN.get(opcode)
        if imm_len is None:
            raise ValueError("unknown opcode")
        end = at + 1 + imm_len
        if end > len(code):
            raise ValueError("truncated instruction")
        at = end
    return frozenset(boundaries)


def _result(
    status: str,
    compute_used: int,
    state_used: int,
    pc: int,
    stack: list[int],
    memory: bytearray,
) -> StateExecutionResult:
    return StateExecutionResult(
        status,
        compute_used,
        state_used,
        pc,
        tuple(stack),
        bytes(memory),
    )


def execute_program(
    raw_program: bytes,
    *,
    compute_limit: int,
    state_limit: int,
    memory_limit: int,
    storage_read: Callable[[int], int] | None = None,
    storage_write: Callable[[int, int], None] | None = None,
) -> StateExecutionResult:
    if compute_limit < 0 or state_limit < 0:
        raise ValueError("resource limits must be non-negative")
    if memory_limit < 0 or memory_limit > MAX_MEMORY_BYTES:
        raise ValueError("invalid memory limit")
    if memory_limit % 8 != 0:
        raise ValueError("memory limit must be a multiple of 8")

    try:
        program = decode_program(raw_program)
        boundaries = _instruction_boundaries(program.code)
    except ValueError:
        return StateExecutionResult(
            "invalid_program",
            0,
            0,
            0,
            tuple(),
            bytes(memory_limit),
        )

    code = program.code
    memory = bytearray(memory_limit)
    stack: list[int] = []
    pc = 0
    compute_used = 0
    state_used = 0

    def need(count: int) -> bool:
        return len(stack) >= count

    def push(value: int) -> bool:
        if len(stack) >= MAX_STACK_ITEMS:
            return False
        stack.append(value)
        return True

    while True:
        if pc == len(code):
            return _result("fallthrough", compute_used, state_used, pc, stack, memory)
        if pc not in boundaries:
            return _result("invalid_jump", compute_used, state_used, pc, stack, memory)

        opcode = code[pc]
        cost = COMPUTE_COST[opcode]
        if compute_used + cost > compute_limit:
            return _result("out_of_compute", compute_used, state_used, pc, stack, memory)
        compute_used += cost

        imm_len = IMMEDIATE_LEN[opcode]
        next_pc = pc + 1 + imm_len
        imm = code[pc + 1 : next_pc]

        if opcode == OP_HALT:
            return _result("halted", compute_used, state_used, pc, stack, memory)

        if opcode == OP_REVERT:
            return _result("reverted", compute_used, state_used, pc, stack, memory)

        if opcode == OP_PUSH_U64:
            value = struct.unpack(">Q", imm)[0]
            if not push(value):
                return _result("stack_overflow", compute_used, state_used, pc, stack, memory)
            pc = next_pc
            continue

        if opcode == OP_DUP:
            if not need(1):
                return _result("stack_underflow", compute_used, state_used, pc, stack, memory)
            if not push(stack[-1]):
                return _result("stack_overflow", compute_used, state_used, pc, stack, memory)
            pc = next_pc
            continue

        if opcode == OP_DROP:
            if not need(1):
                return _result("stack_underflow", compute_used, state_used, pc, stack, memory)
            stack.pop()
            pc = next_pc
            continue

        if opcode == OP_SWAP:
            if not need(2):
                return _result("stack_underflow", compute_used, state_used, pc, stack, memory)
            stack[-1], stack[-2] = stack[-2], stack[-1]
            pc = next_pc
            continue

        if opcode in (OP_LOAD_U64, OP_STORE_U64):
            word_index = struct.unpack(">H", imm)[0]
            offset = word_index * 8
            if offset + 8 > len(memory):
                return _result("memory_oob", compute_used, state_used, pc, stack, memory)

            if opcode == OP_LOAD_U64:
                value = struct.unpack_from(">Q", memory, offset)[0]
                if not push(value):
                    return _result("stack_overflow", compute_used, state_used, pc, stack, memory)
            else:
                if not need(1):
                    return _result("stack_underflow", compute_used, state_used, pc, stack, memory)
                value = stack.pop()
                struct.pack_into(">Q", memory, offset, value)

            pc = next_pc
            continue

        if opcode in (OP_SLOAD_U64, OP_SSTORE_U64):
            if state_used + 1 > state_limit:
                return _result("out_of_state", compute_used, state_used, pc, stack, memory)

            if opcode == OP_SLOAD_U64:
                if storage_read is None:
                    return _result("storage_unavailable", compute_used, state_used, pc, stack, memory)
                if not need(1):
                    return _result("stack_underflow", compute_used, state_used, pc, stack, memory)
                slot = stack.pop()
                try:
                    value = storage_read(slot)
                except (ValueError, OverflowError):
                    return _result("invalid_host_state", compute_used, state_used, pc, stack, memory)
                if not 0 <= value <= U64_MAX:
                    return _result("invalid_host_state", compute_used, state_used, pc, stack, memory)
                if not push(value):
                    return _result("stack_overflow", compute_used, state_used, pc, stack, memory)
            else:
                if storage_write is None:
                    return _result("storage_unavailable", compute_used, state_used, pc, stack, memory)
                if not need(2):
                    return _result("stack_underflow", compute_used, state_used, pc, stack, memory)
                value = stack.pop()
                slot = stack.pop()
                try:
                    storage_write(slot, value)
                except (ValueError, OverflowError):
                    return _result("invalid_host_state", compute_used, state_used, pc, stack, memory)

            state_used += 1
            pc = next_pc
            continue

        if opcode in (OP_JUMP, OP_JUMPI):
            target = struct.unpack(">I", imm)[0]
            if target not in boundaries:
                return _result("invalid_jump", compute_used, state_used, pc, stack, memory)

            if opcode == OP_JUMP:
                pc = target
                continue

            if not need(1):
                return _result("stack_underflow", compute_used, state_used, pc, stack, memory)
            condition = stack.pop()
            pc = target if condition != 0 else next_pc
            continue

        if opcode in (
            OP_ADD,
            OP_SUB,
            OP_MUL,
            OP_DIV,
            OP_MOD,
            OP_EQ,
            OP_LT,
            OP_GT,
        ):
            if not need(2):
                return _result("stack_underflow", compute_used, state_used, pc, stack, memory)

            rhs = stack.pop()
            lhs = stack.pop()

            if opcode == OP_ADD:
                if lhs > U64_MAX - rhs:
                    return _result("arithmetic_overflow", compute_used, state_used, pc, stack, memory)
                value = lhs + rhs
            elif opcode == OP_SUB:
                if lhs < rhs:
                    return _result("arithmetic_underflow", compute_used, state_used, pc, stack, memory)
                value = lhs - rhs
            elif opcode == OP_MUL:
                if rhs != 0 and lhs > U64_MAX // rhs:
                    return _result("arithmetic_overflow", compute_used, state_used, pc, stack, memory)
                value = lhs * rhs
            elif opcode == OP_DIV:
                if rhs == 0:
                    return _result("division_by_zero", compute_used, state_used, pc, stack, memory)
                value = lhs // rhs
            elif opcode == OP_MOD:
                if rhs == 0:
                    return _result("division_by_zero", compute_used, state_used, pc, stack, memory)
                value = lhs % rhs
            elif opcode == OP_EQ:
                value = 1 if lhs == rhs else 0
            elif opcode == OP_LT:
                value = 1 if lhs < rhs else 0
            else:
                value = 1 if lhs > rhs else 0

            if not push(value):
                return _result("stack_overflow", compute_used, state_used, pc, stack, memory)
            pc = next_pc
            continue

        return _result("invalid_program", compute_used, state_used, pc, stack, memory)


def encode_receipt(result: StateExecutionResult) -> bytes:
    status = STATUS_CODE.get(result.status)
    if status is None:
        raise ValueError("unknown VM status")

    stack_bytes = b"".join(struct.pack(">Q", value) for value in result.stack)
    stack_hash = hashlib.sha256(b"FLOCKVM2STACK1" + stack_bytes).digest()
    memory_hash = hashlib.sha256(b"FLOCKVM2MEM1" + result.memory).digest()

    return b"".join(
        (
            RECEIPT_DOMAIN,
            struct.pack(">B", status),
            struct.pack(">Q", result.compute_used),
            struct.pack(">Q", result.state_used),
            struct.pack(">I", result.pc),
            struct.pack(">I", len(result.stack)),
            stack_hash,
            memory_hash,
        )
    )
