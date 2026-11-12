# Flock Phase 17 — Deterministic BFT finality core

Phase 17 adds a deterministic, authenticated BFT safety/finality layer over the
Phase 16 persisted action-block format. It is additive: FLOCKVM1/FLOCKVM2,
action-block execution, and Phase 16 persistence formats are unchanged.

## Validator set

`FLOCKVALSET1` canonically sorts Ed25519 public keys and commits each key plus
its positive u64 voting power. The validator-set root is SHA-256 over this
canonical representation.

Quorum requires strictly more than two thirds of total voting power:

    quorum = floor(2 * total_power / 3) + 1

Duplicate validator keys are rejected and duplicate votes never add voting
power.

## Deterministic proposer

For a fixed validator set, height, and round, the proposer is selected by a
canonical round-robin schedule over the sorted validator set:

    index = (height + round) mod validator_count

A proposal signs the Phase 16 action block hash plus its parent, pre/post state
roots, pre/post registry roots, chain id, height, round, and validator-set root.
The verifier requires the scheduled proposer and exact action-record binding.

## Authenticated votes

Ed25519 votes are domain separated by `FLOCKVOTE1` and commit to:

- chain id;
- height;
- round;
- step (`PREVOTE` or `PRECOMMIT`);
- action-block hash; and
- validator-set root.

`VoteBook` rejects conflicting votes from one validator at the same
chain/height/round/step as equivocation. Replays of the exact same vote are
idempotent and do not add power.

## Quorum certificates

A quorum certificate contains canonical, public-key-sorted votes that all bind
to one chain/height/round/step/block/validator-set decision. Every signature is
verified and total unique voting power must meet the >2/3 threshold.

The certificate has deterministic `FLOCKQC1` bytes and a domain-separated
certificate hash.

## Locking and finality

The Phase 17 local consensus state machine implements a deliberately small
Tendermint-style safety core:

1. a valid PREVOTE QC locks the node on that block at the QC round;
2. an older conflicting QC cannot break a newer lock;
3. a higher-round PREVOTE QC may move the lock to its certified block;
4. a PRECOMMIT QC finalizes only when the node has observed a matching PREVOTE
   QC for the same round and block; and
5. a finalized consensus instance cannot finalize a different block.

Finalized block identity is checked back against the Phase 16 persisted action
record.

## What the tests prove

- canonical validator-set root independent of input order;
- deterministic proposer selection and exact action-record proposal binding;
- deterministic Ed25519 vote records and quorum-certificate bytes;
- three-of-four equal-power validators reach quorum while two-of-four do not;
- duplicate validators/votes cannot inflate power;
- equivocation is detected;
- conflicting precommit certificates cannot bypass the local lock;
- matching PREVOTE + PRECOMMIT quorum finalizes the action block; and
- a higher-round PREVOTE QC can deterministically move the lock.

## Explicitly out of scope

Phase 17 is not a production-ready distributed consensus implementation. It
intentionally does not yet provide peer gossip, proposal/vote networking,
timeouts, pacemaker/failure detection, validator-set changes, slashing,
evidence propagation, WAL/restart persistence for consensus state, dynamic
membership, network partitions, or production security claims.

Phase 18 is the multi-process devnet gate: independent nodes, real transport,
kill/restart tests, and partition/recovery tests around this deterministic
safety core.
