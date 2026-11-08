# Flock Phase 12 — Deterministic contract deployment and calls

Phase 12 introduces immutable contract code registration and deterministic
execution of deployed code against the Phase 11 atomic contract-state layer.

## Deterministic contract id

A contract id is:

    SHA256(
      "FLOCKCONTRACT1"
      || deployer
      || deploy_nonce:u64
      || SHA256("FLOCKCODE1" || canonical_program)
    )

This binds the address to deployer identity, deployment nonce and exact
canonical code bytes.

## Immutable code registry

The registry stores:

- contract id;
- deployer;
- deployment nonce;
- code hash; and
- canonical FlockVM2 program bytes.

The registry has a canonical sorted encoding and a domain-separated registry
root. Re-deployment of the same derived contract id is rejected without
mutation.

Phase 12 deliberately has no code-update path.

## Calls

A contract call is bound to an existing canonical transaction whose recipient
must equal the contract id.

The transaction contributes the explicit compute, state-I/O and memory limits.
The registered program is executed against the Phase 11 transaction-local
storage overlay.

A successful HALT commits contract state. Any VM or resource failure leaves the
contract-state root unchanged.

Transaction value transfer and call-data semantics are not yet integrated into
contract execution; those are part of the later unified execution pipeline.

## Receipts

Deployment receipts commit to:

- contract id;
- code hash; and
- resulting registry root.

Call receipts commit to:

- contract id;
- canonical transaction hash;
- deployed code hash;
- contract execution receipt hash; and
- post-state root.

## Explicitly out of scope

Phase 12 does not yet add:

- constructor execution;
- call data opcodes;
- events/logs;
- cross-contract calls;
- contract code upgrades;
- account-value transfer into contracts;
- fee charging;
- block-level execution integration;
- consensus or validator logic.
