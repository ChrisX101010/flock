# Flock Phase 14 — Versioned execution store and restart recovery

Phase 14 persists the Phase 13 unified execution block and enough canonical
state to restart a node without replaying from an external service.

It intentionally introduces a new execution-record format instead of changing
the older Phase 4 account-only persistence format.

## Execution record

A `FLOCKEXECREC1` record commits to:

- chain id;
- height;
- parent execution-block hash;
- contract registry root;
- unified pre-state root;
- ordered transaction root;
- ordered execution-receipt root;
- unified post-state root;
- Phase 13 execution-block hash;
- selected canonical transaction bytes;
- ordered execution receipts;
- canonical account-state bytes;
- canonical contract-state bytes; and
- canonical immutable contract-registry bytes.

The record ends with a domain-separated SHA-256 record hash.

## Parse-time verification

A record is accepted only if all independent commitments recompute:

- transaction root;
- receipt root;
- contract registry root;
- unified post-state root;
- execution-block hash; and
- outer record hash.

The persisted account state, contract state, and code registry therefore cannot
be replaced independently without detection.

## Durable append

The execution store writes block files through a temporary file, flushes and
fsyncs the file, atomically renames it, fsyncs the block directory, then
atomically updates and fsyncs `EXECUTION_HEAD`.

Duplicate blocks, wrong heights, wrong parents, and state-root discontinuities
are rejected before HEAD mutation.

## Restart recovery

Recovery verifies every committed execution block from genesis through HEAD and
returns:

- verified tip height;
- verified tip block hash;
- reconstructed unified account/contract state; and
- reconstructed immutable contract registry.

The recovered values can be passed directly into the Phase 13 executor to
produce the next block.

## Registry transition rule

Phase 14 requires the contract registry root to remain constant across adjacent
records. Contract deployment as an authenticated state transition is not yet in
the execution block format and remains a later phase.

## Explicitly out of scope

Phase 14 does not yet add:

- deployment transactions;
- consensus/finality;
- validator signatures;
- snapshots/pruning;
- RPC;
- indexer;
- wallet;
- faucet;
- fees;
- DEX.

Those remain subsequent gated phases.
