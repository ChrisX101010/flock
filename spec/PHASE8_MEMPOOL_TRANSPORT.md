# Flock Phase 8 — Bounded mempool transport and admission

Phase 8 adds a bounded in-memory transaction pool and the smallest network
surface required to submit one canonical transaction over an already
established Phase 6 peer session.

It does **not** add transaction gossip, replacement-by-fee, eviction policy,
fees, signatures/accounts, validator membership, consensus, fork choice or
economics.

## Canonical transaction decode

Phase 8 adds the strict inverse of the existing `FLOCKTX1` encoder.

A received transaction is accepted as canonical only when:

- the transaction domain is exact;
- all fixed-width fields are present;
- the payload length is within the Phase 0 maximum;
- there are no truncated or trailing bytes; and
- re-encoding the parsed transaction produces byte-identical input.

## Transaction message

One network submission is:

    FLOCKTXMSG1
    tx_length:u32
    tx_bytes:[tx_length]u8

The Phase 6 frame still wraps this payload. Both the outer frame and inner
transaction length are bounded before admission.

Phase 8 deliberately sends one transaction per message. Batch transport and
gossip are out of scope.

## Mempool admission

Admission is stateless and fail-closed. It checks:

1. canonical transaction encoding;
2. expected chain id;
3. non-zero transfer amount;
4. sender and recipient are distinct;
5. configured per-transaction compute/state/memory ceilings;
6. exact canonical duplicate rejection;
7. maximum entry count; and
8. maximum total stored transaction bytes.

A rejected transaction does not mutate the pool.

The pool has no implicit eviction policy. When capacity is exhausted, new
transactions are rejected.

## State-dependent validity

Mempool admission does **not** claim that a transaction is executable against
the committed state.

Nonce, balance and state-transition validity remain the responsibility of the
deterministic Phase 5 producer. This allows multiple sequential nonces from one
sender to coexist in the pool while keeping block construction deterministic.

## Peer boundary

Transaction transport is permitted only after a Phase 6 session is
`ESTABLISHED`, and the remote hello must advertise the same chain id.

Malformed input, pre-handshake input and oversized frames cannot mutate the
mempool.

## Explicitly out of scope

Later phases may add peer-to-peer gossip, signatures/account authentication,
fee policy, eviction/replacement rules and consensus integration. Those
mechanisms must not be inferred from Phase 8.
