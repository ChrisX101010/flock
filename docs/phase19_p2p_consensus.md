# Flock Phase 19 — peer-to-peer consensus and authenticated view change

Phase 19 removes the Phase 18 test coordinator from the consensus message path.

Validators now exchange proposals, votes, quorum certificates, and signed
round-change records directly over bounded TCP frames. Each process validates,
persists, aggregates, and advances consensus locally.

This remains a controlled devnet gate, not a production BFT implementation.

## New consensus-network responsibilities

Every validator process now owns:

- direct peer addresses;
- proposal reception and verification;
- PREVOTE/PRECOMMIT reception and signature verification;
- local vote aggregation by round, step, and block;
- local quorum-certificate construction;
- QC propagation;
- durable round-scoped anti-equivocation records;
- a local pacemaker timer; and
- authenticated quorum-based round progression.

The integration test only starts/stops processes and observes status. It does
not carry proposals, collect votes, build QCs, or deliver certificates.

## Authenticated round change

A local timeout does not unilaterally advance consensus.

A validator signs `FLOCKROUND19`, binding:

- chain id;
- height;
- target round; and
- validator-set root.

The signed record also contains the validator public key. Once a node has
strictly more than two thirds of voting power, it canonicalizes those signed
records into a hash-protected `FLOCKROUNDQC19` certificate and propagates that
certificate before any proposal for the new round. Every peer independently
verifies the certificate before advancing its local pacemaker.

This means two of four equal-power validators can time out forever without
changing the round, while three of four can recover from a missing proposer.

## Autonomous round operation

The scheduled proposer for a round signs the existing Phase 16 action record
and broadcasts it directly to peers.

Each peer independently verifies the proposer schedule, signature, block
commitments, and validator-set root before signing a PREVOTE.

Nodes locally aggregate PREVOTEs. Once quorum exists they build and broadcast a
PREVOTE QC, lock through the Phase 17 state machine, sign PRECOMMIT, and
broadcast that vote.

Nodes then locally aggregate PRECOMMITs. A quorum becomes a PRECOMMIT QC and
finalizes only through the Phase 17 safety rules.

## Durable evidence

`P2P_CONSENSUS_WAL` is canonical, hash-protected, and atomically replaced. It
contains round-scoped proposals, this validator's signed votes, observed QCs,
round-change records, and the highest authenticated round.

After restart the node re-verifies signatures/QCs and reconstructs its Phase 17
lock/finality state from those records.

## What the gate proves

The Phase 19 integration test proves:

1. four independent processes finalize round 0 without a coordinator carrying
   consensus messages;
2. if the round-0 proposer is absent, the remaining 3/4 validators produce an
   authenticated round-change quorum;
3. the scheduled round-1 proposer then drives consensus to finality;
4. the view-change/finality evidence survives process restart; and
5. a 2/4 minority cannot advance the round and cannot finalize.

## Deliberate limits

Phase 19 still does not claim production consensus. It lacks:

- authenticated peer identity at the transport layer;
- persistent peer discovery;
- retransmission/anti-entropy beyond later messages;
- backpressure and peer scoring;
- deterministic timeout adaptation;
- multi-height block production loop;
- validator-set changes;
- Byzantine evidence/slashing propagation;
- TLS/Noise;
- multi-host WAN tests;
- long-duration chaos/soak testing.

The next gate should focus on multi-height operation, retransmission/anti-
entropy, crash points around every durable transition, and adversarial message
scheduling rather than adding application features.
