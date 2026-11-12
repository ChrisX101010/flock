# Flock v0.1.0-devnet

`v0.1.0-devnet` freezes the first end-to-end Flock research/devnet milestone.

## Included

The release integrates Phase 1 through Phase 19, including:

- deterministic reference/conformance execution;
- authenticated state and block commitments;
- durable persistence and deterministic block production;
- bounded transport, block synchronization and authenticated mempool admission;
- FlockVM deterministic bounded execution;
- versioned contract state, deployment/call execution and durable action store;
- canonical validator sets and deterministic proposer selection;
- signed PREVOTE/PRECOMMIT records;
- deterministic quorum certificates and local lock/finality rules;
- four-validator independent-process devnet recovery;
- peer-to-peer proposal, vote and QC propagation;
- authenticated quorum-based view change;
- missing-proposer recovery with three of four validators;
- restart recovery of consensus/view-change evidence;
- minority inability to advance view or finalize.

## Release evidence

Phase 17, Phase 18 and Phase 19 were independently validated before merge.
The Phase 19 gate was repeated during final validation, and the merged Phase
17–19 stack passed `Flock CI` on `master`.

The release tag must point to a later docs-only release commit whose parentage
contains the validated Phase 19 master commit
`ffb04cafa6ad347def9c8d038b8ec64323f9ed39`, with its own successful `Flock CI`
run.

## Scope

This is a **devnet/research release**. It is not:

- production blockchain software;
- a public-testnet launch;
- externally audited consensus;
- a security guarantee;
- suitable for real-value assets.

Known deliberate gaps are documented in
[ARCHITECTURE.md](ARCHITECTURE.md) and the Phase 19 design notes.

## Freeze policy

After this release:

1. no Phase 20 feature work is added to the release line;
2. fixes must be narrowly scoped and regression-tested;
3. new protocol work begins from a separately reviewed post-release milestone;
4. `v0.1.0-devnet` remains a stable evidence point for later comparisons.
