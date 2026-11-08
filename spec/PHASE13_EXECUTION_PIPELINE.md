# Flock Phase 13 — Unified authenticated execution pipeline

Phase 13 joins the previously isolated authenticated mempool, account transfer,
contract-call, FlockVM, receipt, and state-commitment layers into one
deterministic execution pipeline.

## Unified state

The execution state contains:

- account nonce/balance state from Phase 0/2;
- contract storage state from Phase 11; and
- the immutable contract code registry from Phase 12.

The combined execution root is domain-separated over:

    account_state_root
    contract_storage_root
    contract_registry_root

This is the first Flock root that commits to all execution-relevant state.

## Dispatch

A canonical transaction is dispatched deterministically:

- if the recipient is not a deployed contract, it is a normal account transfer;
- if the recipient is a deployed contract, it is an atomic value-transfer plus
  deployed-code call.

## Contract-call atomicity

For a contract call, account value transfer and contract execution are one
transactional operation.

The account transfer is committed only if the contract VM execution also
commits.

REVERT, state exhaustion, compute exhaustion, invalid execution, or any other
contract failure rolls back:

- sender nonce;
- sender balance;
- recipient/contract balance; and
- contract storage.

The combined post-state root is therefore identical to the pre-state root on a
failed call.

## Block execution

Candidate transactions are:

1. canonically encoded;
2. deduplicated;
3. sorted by sender, nonce, recipient, amount, and transaction hash;
4. bounded by block transaction/resource limits; and
5. executed sequentially against the evolving unified state.

Only successfully executed transactions enter the Phase 13 execution block.

This preserves the existing Phase 5 policy that state-invalid candidates are
not included in a produced block. Fee-paying failed execution is deliberately
deferred until fee economics are specified.

## Authenticated mempool integration

Phase 13 tests the full path from Ed25519-authenticated Phase 9 mempool
admission into deterministic unified block execution.

The block executor does not trust mempool arrival order.

## Execution block commitment

The Phase 13 execution-block hash commits to:

- chain id;
- height;
- parent block hash;
- registry root;
- unified pre-state root;
- ordered transaction root;
- ordered execution receipt root;
- unified post-state root; and
- selected transaction count.

Persistence of this versioned execution block format is the next phase.

## Explicitly out of scope

Phase 13 does not yet add:

- versioned execution-block disk persistence;
- deployment as a signed transaction action;
- calldata or events;
- fees;
- consensus/finality;
- validator membership;
- RPC;
- indexer;
- token faucet;
- DEX.

Those are subsequent gated phases.
