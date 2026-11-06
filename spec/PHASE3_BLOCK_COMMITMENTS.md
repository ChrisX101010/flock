# Flock Phase 3 — Block Commitments

Phase 3 commits an ordered transaction sequence and its deterministic state
transition into a canonical block header. It does not introduce networking,
leader election, finality, token economics, or real-value use.

All integers below are unsigned big-endian integers. All hashes are SHA-256.
Every domain string is literal ASCII and is part of the committed bytes.

## Ordered list commitments

Transaction and receipt lists use the same tree shape but distinct domains.

For item `i`:

    item_hash = H(ITEM_DOMAIN || i_u32 || item_length_u32 || item_bytes)

Leaves are paired from left to right:

    node = H(NODE_DOMAIN || left_hash || right_hash)

If a level has an odd number of hashes, its missing right child is:

    pad = H(PAD_DOMAIN || level_u32 || missing_index_u32)

where level 0 is the leaf level and `missing_index` is the zero-based child
index that would have occupied the missing slot.

The final list commitment binds the item count:

    root = H(ROOT_DOMAIN || count_u32 || tree_hash)

For an empty list:

    tree_hash = H(EMPTY_DOMAIN)

Transaction domains:

- `FLOCKTXITEM1`
- `FLOCKTXNODE1`
- `FLOCKTXPAD1`
- `FLOCKTXEMPTY1`
- `FLOCKTXROOT1`

Receipt domains:

- `FLOCKRCPTITEM1`
- `FLOCKRCPTNODE1`
- `FLOCKRCPTPAD1`
- `FLOCKRCPTEMPTY1`
- `FLOCKRCPTROOT1`

Transaction item bytes are the canonical `FLOCKTX1` bytes from Phase 0/1.

## Receipt

Phase 3 uses a minimal deterministic transfer receipt:

    FLOCKRCPT1
    tx_index          u32
    tx_sha256         32 bytes
    success           u8 (0 or 1)
    post_state_root   32 bytes

There is exactly one receipt for each ordered transaction, including an invalid
transaction. An invalid transaction leaves state unchanged and therefore its
receipt commits the unchanged state root.

This receipt version is specific to the Phase 1 transfer transition. A future
FlockVM receipt format must use a new domain/version rather than reinterpret
`FLOCKRCPT1`.

## Block transition

Given a pre-state and ordered transactions:

1. Compute the Phase 2 authenticated `pre_state_root`.
2. Process transactions in order.
3. A transaction whose `chain_id` differs from the block `chain_id` is invalid.
4. Otherwise apply the Phase 1 transition.
5. Invalid transactions are atomic and leave state byte-equivalent.
6. After every attempt, compute the authenticated state root and emit one
   receipt.
7. The final root is `post_state_root`.
8. Commit the canonical transaction bytes and receipt bytes into their ordered
   roots.

## Canonical block header

    FLOCKBLK1          9 bytes
    chain_id           u32
    height             u64
    parent_block_hash  32 bytes
    pre_state_root     32 bytes
    tx_root            32 bytes
    receipt_root       32 bytes
    post_state_root    32 bytes
    tx_count           u32

The header is exactly 185 bytes.

The canonical block hash is:

    H("FLOCKBLOCKHASH1" || canonical_header_bytes)

The zero parent hash is valid for the Phase 3 genesis test vector.

## Phase 3 conformance gates

Phase 3 is GREEN only when:

- two independent block-oracle implementations produce byte-identical headers
  and block hashes;
- the ordered transaction root changes when transaction order changes;
- receipts include invalid transactions and invalid transitions are atomic;
- empty-block pre/post roots are equal;
- parent hash and height changes alter the block hash;
- the canonical Goose Phase 1 transaction bytes feed the transaction root;
- the canonical Goose Phase 1 state bytes equal the one-transaction post-state;
- repeated construction is byte-identical;
- CI runs the vector after Phase 1 and Phase 2 conformance.
