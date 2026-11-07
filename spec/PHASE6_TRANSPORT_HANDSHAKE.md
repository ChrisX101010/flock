# Flock Phase 6 — Bounded transport and deterministic handshake

Phase 6 adds the smallest network boundary required for two Flock nodes to
establish that they speak the same protocol and refer to the same chain.

It does **not** add block synchronization, gossip, mempool transport, peer
identity, signatures, validator membership, fork choice, consensus, economics
or real-value operation.

## Canonical hello

A hello is exactly:

    FLOCKHELLO1
    protocol_version:u32
    chain_id:u32
    genesis_block_hash:[32]u8
    tip_height:u64
    tip_block_hash:[32]u8

Integers use network byte order. Hashes are raw fixed-width bytes. The current
protocol version is `1`.

The chain identity is `(chain_id, genesis_block_hash)`. The advertised tip is
only peer information for later synchronization work; receiving it never
changes local chain state.

## Framing

Every transport payload is wrapped in:

    FLOCKFRM1
    payload_length:u32
    payload:[payload_length]u8

A receiver checks the frame domain and declared length **before** reading the
payload. The implementation has an explicit maximum frame size and never
allocates a peer-declared payload larger than that bound.

A complete frame decoder rejects truncated and trailing bytes.

## Handshake admission

A peer becomes established only after a canonical hello is parsed and all of
the following match local expectations:

- supported protocol version;
- chain id;
- genesis block hash.

Malformed/truncated/trailing hello bytes, wrong domains and wrong hash widths
are rejected.

Timeout, EOF, parse failure or admission failure closes the session state. No
chain-store mutation is part of the handshake.

## State machine

The reference session has three states:

    PRE_HANDSHAKE -> ESTABLISHED
    PRE_HANDSHAKE -> CLOSED
    ESTABLISHED   -> CLOSED

Calling the handshake outside `PRE_HANDSHAKE` is rejected.

## Store integration

`hello_from_store()` derives genesis and tip information only from a verified
Phase 4 `ChainStore` chain. An empty store is not a network identity and is
rejected. Every record in the verified chain must use the requested chain id.

## Explicitly out of scope

Phase 7 adds block synchronization. Phase 8 adds bounded mempool transport and
admission. Signatures/accounts, validators and consensus remain later phases.
