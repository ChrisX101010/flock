# Flock Phase 11 — Versioned atomic contract state

Phase 11 adds deterministic persistent contract storage without changing the
already-published FlockVM v1 semantics.

Storage-aware programs use the versioned `FLOCKVM2` envelope. Storage-free VM2
programs are differentially tested against VM1 for equivalent arithmetic and
memory behavior.

## Storage model

Phase 11 intentionally starts with:

    contract_id: 32 bytes
    slot:        u64
    value:       u64

Zero is the canonical empty value. Writing zero deletes a slot.

This narrow model proves persistence, authenticated roots, bounded state I/O,
and rollback before a wider public contract ABI is introduced.

## Canonical encoding

    FLOCKCSTATE1
    contract_count:u32

For each non-empty contract, sorted lexicographically by contract id:

    contract_id:32
    slot_count:u32

For each non-zero slot, sorted numerically:

    slot:u64
    value:u64

Empty contract entries and explicit zero values are non-canonical.

## Authenticated storage root

Each non-zero `(contract, slot, value)` is placed in a 256-level sparse Merkle
tree. Tree indexes, leaves, empty leaves, and internal nodes are all
domain-separated.

## FlockVM2 state operations

VM2 preserves the VM1 storage-free instruction semantics and adds:

- `SLOAD_U64`: pop slot, push current value;
- `SSTORE_U64`: pop value, then slot, write into the transaction overlay.

Each state access consumes one state-I/O unit and a fixed compute cost. If the
next access exceeds `state_limit`, execution fails before the access.

## Atomic overlay

Contract execution never mutates input state directly. Writes land in a
transaction-local overlay and commit only when execution ends with `HALT`.

`REVERT`, compute exhaustion, state exhaustion, arithmetic failure, malformed
programs, and all other VM errors discard the overlay. Failed execution must
produce a post-state root identical to the pre-state root.

## Receipt

The contract receipt commits to:

- committed / rolled-back status;
- pre-state root;
- post-state root; and
- hash of the complete VM2 execution receipt, which includes compute and state
  resource usage.

## Explicitly out of scope

Phase 11 does not yet add contract deployment, deterministic contract
addresses, cross-contract calls, events, fees/rent, 256-bit dynamic mapping
keys, code upgrades, consensus integration, validator execution, or DEX logic.
