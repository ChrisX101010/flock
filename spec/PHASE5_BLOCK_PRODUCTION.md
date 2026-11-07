# Flock Phase 5 — Deterministic block production

Phase 5 adds a deterministic reference block producer on top of the
Phase 0–4 transaction, authenticated-state, block-commitment and persistence
layers.

It does **not** add networking, leader election, fork choice, consensus,
economic incentives, EVM execution or real-value operation.

## Determinism contract

Given the same:

- parent state,
- parent block hash and height,
- chain id,
- candidate transaction **set**, and
- block limits,

the producer emits the same selected transaction sequence, receipts, block
header, block hash and persisted record bytes, regardless of candidate input
order.

Candidates are canonically ordered by:

    sender || nonce || recipient || amount || SHA256(canonical_tx_bytes)

Exact duplicate canonical transaction bytes are considered one candidate.

## Admission

The producer scans the canonical candidate order once.

A candidate is skipped when:

- its chain id differs from the block chain id;
- its canonical encoding is invalid;
- adding it would exceed any block-level declared-resource limit; or
- applying it to the state produced by earlier admitted transactions fails.

The reference producer uses declared transaction limits as conservative block
budgets. It never executes a transaction whose declarations would make the
block exceed:

- maximum transaction count;
- maximum total canonical transaction bytes;
- maximum total declared compute;
- maximum total declared state;
- maximum total declared memory.

A skipped candidate does not consume block budget and does not change state.

## Relationship to consensus

This is a deterministic **proposal construction policy**, not fork choice or
consensus. A validator verifies the canonical block and state commitments from
Phases 2–4. Future consensus work decides which valid proposal becomes
canonical.

The native VM remains FlockVM (`FLVM`). EVM support, if implemented later,
remains a separate compatibility layer.
