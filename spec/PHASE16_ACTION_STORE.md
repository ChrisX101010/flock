# Flock Phase 16 — Registry-changing action store

Phase 16 persists the Phase 15 action-block format, including legitimate
contract-registry transitions caused by authenticated deployment transactions.

It is a new versioned store rather than a mutation of the Phase 14 format.

## Record commitments

`FLOCKACTREC1` commits to:

- chain id and height;
- parent action-block hash;
- pre-registry root;
- post-registry root;
- unified pre-state root;
- ordered transaction root;
- ordered execution-receipt root;
- unified post-state root;
- action-block hash;
- canonical selected transaction bytes;
- ordered receipt bytes;
- canonical account state;
- canonical contract storage; and
- canonical post-block contract registry.

The record ends in a domain-separated SHA-256 record hash.

## Registry-changing continuity

Unlike Phase 14, the registry root is allowed to change.

For every adjacent committed block:

    next.pre_registry_root == previous.post_registry_root
    next.pre_state_root    == previous.post_state_root
    next.parent_hash       == previous.block_hash

This permits any number of authenticated deployment transitions while
preventing a node from silently switching to a different code registry.

## Parse verification

Each record independently recomputes and verifies:

- transaction root;
- receipt root;
- post-registry root from persisted registry bytes;
- unified post-state root from account/contract/registry state;
- action-block hash; and
- outer record hash.

## Restart recovery

Recovery verifies the entire chain from genesis through ACTION_HEAD and returns
the exact unified state plus the post-block contract registry needed for the
next Phase 15 action block.

The test suite proves:

- recovery immediately after deploy+call;
- a block with no registry change;
- a later second deployment that changes the registry again;
- rejection of stale-registry continuity;
- duplicate rejection;
- tamper detection; and
- continued execution after restart.

## Explicitly out of scope

Phase 16 does not yet add consensus/finality, validator voting, block gossip,
snapshots/pruning, fees, RPC, indexer, wallet, faucet, or DEX.

The next major gate is network consensus over these deterministic persisted
state transitions.
