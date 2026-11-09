# Flock Phase 15 — Authenticated on-chain contract deployment

Phase 15 turns contract deployment from a local registry operation into a
canonical signed transaction action.

It preserves the existing canonical `FLOCKTX1` transaction and Phase 9 Ed25519
signature format.

## Action envelope

Deployment is encoded inside the existing transaction payload:

    FLOCKACT1
    action_kind:u8 = 1
    program_length:u32
    FLOCKVM2 program bytes

Malformed or unknown payloads beginning with `FLOCKACT1` fail closed and are
never reinterpreted as ordinary transfers.

## Deterministic recipient binding

The deployment transaction recipient must equal the existing Phase 12
deterministic contract id:

    derive_contract_id(sender, nonce, program)

This binds the signed transaction to the exact deployed code, deployer, and
deployment nonce before execution.

## Native endowment

Deployment requires a non-zero `amount`.

The canonical Phase 0 account transition transfers that amount from the
deployer to the deterministic contract address and increments the deployer's
nonce.

The registry update and native-value transfer are atomic: both commit, or
neither commits.

This deliberately preserves Phase 8/9 mempool rules, including non-zero
transaction amount, rather than adding a special zero-value admission bypass.

## Registry transition

Successful deployment changes the immutable contract registry root. Phase 15
therefore introduces a versioned action-block commitment with distinct
pre-registry and post-registry roots.

The unified pre/post state roots also commit to their corresponding registry
roots, so code deployment changes the execution state commitment even before
the contract has storage.

## Same-block deployment and call

Canonical sender/nonce ordering permits deployment at nonce N and a call to the
newly deployed contract at nonce N+1 inside one block.

Mempool arrival order does not determine execution order.

## Authentication

Phase 15 tests deployment through the Phase 9 authenticated mempool. Deployment
therefore inherits Ed25519 signature verification, sender/public-key binding,
canonical transaction signing, `(sender, nonce)` conflict protection, and
chain-id admission.

## Explicitly out of scope

Phase 15 does not yet add constructor execution, calldata, event logs,
upgradeable code, deployment fees/rent, consensus/finality, validator
membership, RPC/indexer/wallet/faucet, or DEX.

Persistence of registry-changing action blocks is the next storage-format gate.
