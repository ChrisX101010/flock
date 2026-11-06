# Flock Phase 4 — Persistent Chain Store and Reference Tooling

Phase 4 makes the deterministic commitments from Phases 0–3 durable and
independently verifiable after process restart.

It does **not** add P2P networking, consensus, leader election, token economics,
EVM execution, or real-value operation.

## Canonical persisted block record

A persisted block record is:

    FLOCKREC1
    header_length      u32
    header             canonical Phase 3 header (185 bytes)
    tx_count           u32
    repeated:
      tx_length        u32
      tx_bytes
    receipt_count      u32
    repeated:
      receipt_length   u32
      receipt_bytes
    state_length       u32
    post_state_bytes   canonical FLOCKSTATE1 bytes
    record_hash        32 bytes

`record_hash` is:

    SHA256("FLOCKRECORDHASH1" || all preceding record bytes)

The Phase 3 block hash remains the blockchain identity. The record hash only
protects the persistence envelope.

A record is valid only when:

- the header is canonical and its Phase 3 block hash recomputes;
- the transaction count equals the header count;
- `transaction_root(tx_bytes)` equals the header transaction root;
- there is exactly one receipt per transaction;
- each receipt is canonical `FLOCKRCPT1`, has its correct index, and commits
  the SHA-256 of its corresponding transaction;
- `receipts_root(receipts)` equals the header receipt root;
- the persisted state is canonical `FLOCKSTATE1`;
- the authenticated root of that state equals the header post-state root; and
- the record hash matches.

## Persistent chain store

The reference store is an immutable block directory plus an atomic `HEAD`.

For every appended block it verifies:

1. the record itself;
2. genesis is height 0 with the zero parent;
3. every later height is exactly previous height + 1;
4. `parent_block_hash` equals the previous block hash; and
5. `pre_state_root` equals the previous block's `post_state_root`.

Block files are immutable. `HEAD` is updated by write + fsync + atomic rename.

## Reference tool

`python3 -m tools.flock_tool` is the canonical Phase 4 inspection surface:

- `verify-record FILE`
- `verify-store DIR`
- `inspect-store DIR`

This tool is a reference implementation and conformance surface, not a
proprietary lock-in mechanism. Other implementations may interoperate by
matching the public canonical formats and invariants.

FlockVM remains the native VM (`FLVM`). EVM compatibility, if added later,
must remain a separate compatibility layer.
