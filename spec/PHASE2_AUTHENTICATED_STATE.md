# Flock Phase 2 — Authenticated Sparse State

Phase 2 authenticates the canonical Phase 1 account state with a fixed-depth
256-bit sparse Merkle tree.

This phase selects SHA-256 for the Phase 2 state-root construction. It is a
standard cryptographic primitive; Flock does not define a new hash primitive.

## Keys

An account key is the existing 32-byte Phase 0/1 account identifier, interpreted
as a 256-bit big-endian path.

Bit 255 is traversed first. A zero bit selects the left child and a one bit the
right child.

## Account value

The authenticated value is:

- nonce: u64 big-endian
- balance: u64 big-endian

## Domain-separated hashing

Let `H` be SHA-256.

Empty leaf:

    H("FLOCKEMPTY1")

Account leaf:

    H("FLOCKLEAF1" || address[32] || nonce_be_u64 || balance_be_u64)

Internal node:

    H("FLOCKNODE1" || left_hash[32] || right_hash[32])

The empty hash at depth 256 is the empty-leaf hash. Empty hashes for depths
255 through 0 are recursively:

    empty[d] = H("FLOCKNODE1" || empty[d+1] || empty[d+1])

The state root is the depth-0 hash.

## Properties required by conformance

- input account insertion order cannot affect the root
- changing nonce or balance changes the root
- adding or removing an account changes the root
- membership proofs reconstruct the exact root
- non-membership proofs use the empty leaf and reconstruct the exact root
- two independent implementations must produce the same root
- parsing Goose's canonical Phase 1 state bytes must produce the same root
