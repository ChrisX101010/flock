# Flock Phase 9 — Authenticated transaction admission

Phase 9 authenticates canonical Phase 0/8 transactions before they enter the
mempool.

It adds Ed25519 signatures, deterministic account derivation from public keys,
strict signed-envelope encoding, sender/public-key binding, and a bounded
pending-nonce conflict gate.

It does **not** add fees, validator identity, consensus signatures, multisig,
key rotation, wallets, replacement-by-fee, transaction gossip, or full
state-dependent mempool execution.

## Account derivation

An account id is derived from the raw 32-byte Ed25519 public key:

    SHA256("FLOCKADDR1" || public_key)

The transaction's existing 32-byte `sender` field must equal this value.

## Signature

The signed message is:

    "FLOCKSIG1" || canonical_tx_bytes

The signature algorithm is Ed25519.

The signature authenticates the exact canonical transaction bytes, including
chain id, nonce, sender, recipient, amount, resource limits, and payload.

## Signed transaction envelope

The canonical envelope is:

    FLOCKSIGNEDTX1
    public_key:32
    signature:64
    tx_length:u32
    tx_bytes:[tx_length]u8

`tx_bytes` must itself be a canonical `FLOCKTX1` transaction.

Truncated input, trailing bytes, invalid key/signature lengths, oversized
transactions, non-canonical transactions, sender/key mismatches, and invalid
signatures are rejected before mempool mutation.

## Pending nonce conflict gate

The authenticated mempool permits sequential pending nonces for one sender, but
only one transaction per exact `(sender, nonce)` pair.

A second transaction with the same sender and nonce but different canonical
bytes is rejected as `nonce_conflict`.

This is a mempool conflict/replay guard, not a claim that the nonce is currently
executable against committed state. Final nonce and balance validity remain the
deterministic Phase 5 producer's responsibility.

## Failure atomicity

Authentication and nonce-conflict failures do not mutate mempool entry count,
mempool byte usage, transaction hashes, or pending nonce indexes.

Removing a transaction also removes its pending nonce index.

## Transport boundary

Signed transaction transport is allowed only over an already established Phase
6 peer session with a matching chain id. The outer Phase 6 frame remains
bounded.

## Explicitly out of scope

Later phases may add gossip, peer scoring, fees, replacement policy, wallet/key
management, validator authentication, consensus signatures, and persistent
mempool state.
