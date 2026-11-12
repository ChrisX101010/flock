# Flock Architecture — v0.1.0-devnet

This document summarizes the implemented architecture at the Phase 19 devnet
milestone. It is descriptive, not a production-security claim.

## Layer map

### 1. Deterministic ledger foundation — Phases 1–5

These phases establish the reproducible state-transition base:

- canonical/reference execution and independent conformance;
- authenticated state;
- block commitments;
- durable chain persistence and tooling;
- deterministic block production.

The central invariant is that identical protocol inputs produce byte-identical
consensus outputs.

### 2. Bounded networking and admission — Phases 6–9

The network-facing foundation adds:

- bounded transport framing and handshake;
- sequential bounded block synchronization;
- bounded mempool transport;
- authenticated transaction admission.

These layers are kept separate from consensus authority.

### 3. FlockVM and durable action execution — Phases 10–16

FlockVM provides deterministic bounded execution without ambient filesystem,
network, wall-clock, or nondeterministic randomness dependencies.

The stack then adds:

- versioned atomic contract state;
- deterministic deployment and calls;
- authenticated execution pipeline;
- restart-safe execution storage;
- authenticated deployment actions;
- durable registry-changing action records.

The Phase 16 `ActionStore` is the persisted block/action identity consumed by
the consensus layers.

### 4. Deterministic BFT safety core — Phase 17

Phase 17 adds:

- canonical validator sets;
- deterministic proposer selection;
- Ed25519 domain-separated PREVOTE/PRECOMMIT votes;
- >2/3 voting-power quorum certificates;
- equivocation detection;
- lock/relock safety;
- matching PREVOTE + PRECOMMIT QC finality.

This layer defines safety/finality semantics independently from peer transport.

### 5. Multi-process recovery gate — Phase 18

Four validator processes run independently with:

- separate validator keys;
- separate ActionStores;
- durable consensus WALs;
- bounded TCP loopback RPC.

The gate covers minority no-quorum behavior, three-of-four finality, process
kill/restart, partition healing/catch-up, and all-node restart recovery.

The integration coordinator still carries consensus messages in this phase.

### 6. Peer-to-peer pacemaker — Phase 19

Phase 19 removes the coordinator from the consensus message path.

Validators directly exchange and verify:

- proposals;
- PREVOTE/PRECOMMIT votes;
- quorum certificates;
- signed round-change records;
- authenticated round-change quorum certificates.

A local timeout alone cannot advance the round. More than two thirds of voting
power must authenticate the target round. This permits 3/4 missing-proposer
recovery while a 2/4 minority cannot advance the view or finalize.

The scheduled proposer also votes for its own valid proposal, preserving
liveness when only three of four validators are live.

## Data and authority flow

```text
client transaction
      |
      v
authenticated admission
      |
      v
deterministic execution / state transition
      |
      v
persisted action record
      |
      v
scheduled proposer + signed proposal
      |
      v
peer verification
      |
      v
PREVOTE aggregation
      |
      v
PREVOTE QC -> lock
      |
      v
PRECOMMIT aggregation
      |
      v
PRECOMMIT QC -> finality
```

Round progression is a separate authenticated path:

```text
local timeout
   |
   v
signed FLOCKROUND19 record
   |
   v
>2/3 round-change voting power
   |
   v
FLOCKROUNDQC19
   |
   v
advance round -> next scheduled proposer
```

## Persistence boundaries

Consensus safety evidence is restart-aware:

- execution/action identity remains in the existing durable action store;
- Phase 18 persists consensus anti-equivocation evidence;
- Phase 19 persists round-scoped proposals, local votes, observed QCs,
  round-change records, and the highest authenticated round.

On restart, signatures and certificates are re-verified before reconstructing
lock/finality state.

## Explicit non-goals of v0.1.0-devnet

This milestone does not provide or claim:

- production-ready BFT consensus;
- authenticated transport identity;
- persistent peer discovery;
- robust retransmission/anti-entropy;
- peer scoring/backpressure;
- adaptive timeout policy;
- multi-height production operation;
- validator-set changes;
- Byzantine evidence/slashing propagation;
- TLS/Noise transport;
- WAN deployment validation;
- long-running chaos/soak evidence;
- public testnet readiness;
- external security audit.

The release intentionally freezes here so later work can be evaluated against a
stable, reproducible devnet baseline.
