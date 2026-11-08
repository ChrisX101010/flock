from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from tools.reference_model import Tx, U64_MAX

PROGRAM_DOMAIN = b"FLOCKVM1"
RECEIPT_DOMAIN = b"FLOCKVMRES1"
PROGRAM_VERSION = 1

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
}


@dataclass(frozen=True)
class Program:
    version: int
    code: bytes


@dataclass(frozen=True)
class ExecutionResult:
    status: str
    compute_used: int
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

    program = Program(version, raw[at:])
    if encode_program(program.code, version=program.version) != raw:
        raise ValueError("non-canonical program")
    _instruction_boundaries(program.code)
    return program


def _instruction_boundaries(code: bytes) -> frozenset[int]:
    boundaries: set[int] = set()
    at = 0
    while at < len(code):
        boundaries.add(at)
        opcode = code[at]
        imm = IMMEDIATE_LEN.get(opcode)
        if imm is None:
            raise ValueError("unknown opcode")
        end = at + 1 + imm
        if end > len(code):
            raise ValueError("truncated instruction")
        at = end
    return frozenset(boundaries)


def _failure(
    status: str,
    compute_used: int,
    pc: int,
    stack: list[int],
    memory: bytearray,
) -> ExecutionResult:
    return ExecutionResult(status, compute_used, pc, tuple(stack), bytes(memory))


def execute_program(
    raw_program: bytes,
    *,
    compute_limit: int,
    memory_limit: int,
) -> ExecutionResult:
    if compute_limit < 0:
        raise ValueError("compute limit must be non-negative")
    if memory_limit < 0 or memory_limit > MAX_MEMORY_BYTES:
        raise ValueError("invalid memory limit")
    if memory_limit % 8 != 0:
        raise ValueError("memory limit must be a multiple of 8")

    try:
        program = decode_program(raw_program)
        boundaries = _instruction_boundaries(program.code)
    except ValueError:
        return ExecutionResult("invalid_program", 0, 0, tuple(), bytes(memory_limit))

    code = program.code
    memory = bytearray(memory_limit)
    stack: list[int] = []
    pc = 0
    compute_used = 0

    def need(n: int) -> bool:
        return len(stack) >= n

    def push(value: int) -> bool:
        if len(stack) >= MAX_STACK_ITEMS:
            return False
        stack.append(value)
        return True

    while True:
        if pc == len(code):
            return _failure("fallthrough", compute_used, pc, stack, memory)
        if pc not in boundaries:
            return _failure("invalid_jump", compute_used, pc, stack, memory)

        opcode = code[pc]
        cost = COMPUTE_COST[opcode]
        if compute_used + cost > compute_limit:
            return _failure("out_of_compute", compute_used, pc, stack, memory)
        compute_used += cost

        imm_len = IMMEDIATE_LEN[opcode]
        next_pc = pc + 1 + imm_len
        imm = code[pc + 1 : next_pc]

        if opcode == OP_HALT:
            return ExecutionResult("halted", compute_used, pc, tuple(stack), bytes(memory))

        if opcode == OP_REVERT:
            return _failure("reverted", compute_used, pc, stack, memory)

        if opcode == OP_PUSH_U64:
            value = struct.unpack(">Q", imm)[0]
            if not push(value):
                return _failure("stack_overflow", compute_used, pc, stack, memory)
            pc = next_pc
            continue

        if opcode == OP_DUP:
            if not need(1):
                return _failure("stack_underflow", compute_used, pc, stack, memory)
            if not push(stack[-1]):
                return _failure("stack_overflow", compute_used, pc, stack, memory)
            pc = next_pc
            continue

        if opcode == OP_DROP:
            if not need(1):
                return _failure("stack_underflow", compute_used, pc, stack, memory)
            stack.pop()
            pc = next_pc
            continue

        if opcode == OP_SWAP:
            if not need(2):
                return _failure("stack_underflow", compute_used, pc, stack, memory)
            stack[-1], stack[-2] = stack[-2], stack[-1]
            pc = next_pc
            continue

        if opcode in (OP_LOAD_U64, OP_STORE_U64):
            word_index = struct.unpack(">H", imm)[0]
            offset = word_index * 8
            if offset + 8 > len(memory):
                return _failure("memory_oob", compute_used, pc, stack, memory)

            if opcode == OP_LOAD_U64:
                value = struct.unpack_from(">Q", memory, offset)[0]
                if not push(value):
                    return _failure("stack_overflow", compute_used, pc, stack, memory)
            else:
                if not need(1):
                    return _failure("stack_underflow", compute_used, pc, stack, memory)
                value = stack.pop()
                struct.pack_into(">Q", memory, offset, value)

            pc = next_pc
            continue

        if opcode in (OP_JUMP, OP_JUMPI):
            target = struct.unpack(">I", imm)[0]
            if target not in boundaries:
                return _failure("invalid_jump", compute_used, pc, stack, memory)

            if opcode == OP_JUMP:
                pc = target
                continue

            if not need(1):
                return _failure("stack_underflow", compute_used, pc, stack, memory)
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
                return _failure("stack_underflow", compute_used, pc, stack, memory)

            rhs = stack.pop()
            lhs = stack.pop()

            if opcode == OP_ADD:
                if lhs > U64_MAX - rhs:
                    return _failure("arithmetic_overflow", compute_used, pc, stack, memory)
                value = lhs + rhs
            elif opcode == OP_SUB:
                if lhs < rhs:
                    return _failure("arithmetic_underflow", compute_used, pc, stack, memory)
                value = lhs - rhs
            elif opcode == OP_MUL:
                if rhs != 0 and lhs > U64_MAX // rhs:
                    return _failure("arithmetic_overflow", compute_used, pc, stack, memory)
                value = lhs * rhs
            elif opcode == OP_DIV:
                if rhs == 0:
                    return _failure("division_by_zero", compute_used, pc, stack, memory)
                value = lhs // rhs
            elif opcode == OP_MOD:
                if rhs == 0:
                    return _failure("division_by_zero", compute_used, pc, stack, memory)
                value = lhs % rhs
            elif opcode == OP_EQ:
                value = 1 if lhs == rhs else 0
            elif opcode == OP_LT:
                value = 1 if lhs < rhs else 0
            else:
                value = 1 if lhs > rhs else 0

            if not push(value):
                return _failure("stack_overflow", compute_used, pc, stack, memory)
            pc = next_pc
            continue

        return _failure("invalid_program", compute_used, pc, stack, memory)


def execute_transaction_payload(tx: Tx) -> ExecutionResult:
    return execute_program(
        tx.payload,
        compute_limit=tx.compute_limit,
        memory_limit=tx.memory_limit,
    )


def encode_receipt(result: ExecutionResult) -> bytes:
    status_code = STATUS_CODE.get(result.status)
    if status_code is None:
        raise ValueError("unknown VM status")

    stack_bytes = b"".join(struct.pack(">Q", value) for value in result.stack)
    stack_hash = hashlib.sha256(b"FLOCKVMSTACK1" + stack_bytes).digest()
    memory_hash = hashlib.sha256(b"FLOCKVMMEM1" + result.memory).digest()

    return b"".join(
        (
            RECEIPT_DOMAIN,
            struct.pack(">B", status_code),
            struct.pack(">Q", result.compute_used),
            struct.pack(">I", result.pc),
            struct.pack(">I", len(result.stack)),
            stack_hash,
            memory_hash,
        )
    )
