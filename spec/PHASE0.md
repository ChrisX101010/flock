# Flock Phase 0 Canonical Model

Phase 0 intentionally does not finalize signature scheme, consensus hash,
consensus algorithm, fee market, or token economics.

## Account identifier
Exactly 32 opaque bytes.

## Transaction encoding v1
All integers are unsigned big-endian.

FLOCKTX1        8 bytes
chain_id        u32
nonce           u64
sender          32 bytes
recipient       32 bytes
amount          u64
compute_limit   u64
state_limit     u64
memory_limit    u64
payload_length  u32
payload         payload_length bytes

Maximum payload: 4096 bytes.

## Account state
nonce u64
balance u64

## Transfer validity
A transfer is valid iff amount > 0, sender != recipient, sender exists,
transaction nonce equals sender nonce, sender has sufficient balance,
payload <= 4096 bytes, recipient balance does not overflow u64, and sender
nonce increment does not overflow u64.

Failure leaves consensus state byte-identical.

## Canonical state encoding
All integers are unsigned big-endian.

FLOCKSTATE1     11 bytes
account_count   u32

Accounts follow in lexicographic order by their 32-byte identifier:
address         32 bytes
nonce           u64
balance         u64

The SHA-256 emitted by Phase 0 tooling is only a conformance fingerprint,
not yet the selected Flock consensus hash.
