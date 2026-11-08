# Flock Phase 10 — FlockVM deterministic bounded core

Phase 10 introduces the first executable FlockVM core.

This phase is deliberately small. It proves deterministic, resource-bounded
program execution before persistent contract storage, contract deployment,
cross-contract calls, fees, or consensus integration are added.

## Program envelope

    FLOCKVM1
    version:u16
    code_length:u32
    code:[code_length]u8

Version 1 programs are bounded to 16 KiB of bytecode.

## Numeric model

FlockVM v1 uses unsigned 64-bit integers only.

Arithmetic is checked:

- addition and multiplication overflow fail;
- subtraction underflow fails;
- division/modulo by zero fail;
- arithmetic never wraps.

No floating point exists in consensus execution.

## Stack and memory

The operand stack is bounded to 1024 u64 values.

Linear memory is explicit, zero-initialized, and bounded by the transaction's
memory limit up to 64 KiB in Phase 10. Memory access uses 8-byte words and
out-of-bounds access fails deterministically.

## Compute accounting

Each opcode has a fixed Phase 10 compute cost.

The VM checks the compute budget before each instruction. Infinite loops and
other non-terminating programs therefore stop deterministically with
`out_of_compute`.

## Control flow

Jumps are absolute bytecode offsets and may target only validated instruction
boundaries.

Malformed programs and invalid jump targets fail deterministically.

## Host boundary

Phase 10 has no ambient filesystem, network, wall clock, process, locale,
floating-point, or randomness access.

It also has no persistent contract storage yet. Persistent storage and atomic
state integration are a later phase and must preserve Phase 0/2/3 state
commitment invariants.

## Transaction payload

A canonical FlockVM program may be carried in the existing transaction payload
and executed using the transaction's explicit compute and memory limits.

Phase 10 does not yet make payload execution part of the canonical transfer
state transition. That integration is intentionally deferred until persistent
contract-state semantics are specified and independently tested.

## Receipt

The reference implementation emits a canonical receipt commitment containing:

- deterministic status code;
- compute consumed;
- final program counter;
- final stack length;
- stack hash; and
- memory hash.

Identical program bytes and limits must produce byte-identical receipts.
