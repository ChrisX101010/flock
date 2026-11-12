# Flock Phase 18 — Multi-process devnet gate

Phase 18 integrates the Phase 16 durable action-block store, Phase 17
deterministic BFT finality core, and Phase 6 bounded frame transport across
independent OS processes.

It is a devnet correctness gate, not a production consensus implementation.

## What is exercised

Four validator processes each own:

- one Ed25519 validator key;
- an independent ActionStore;
- an independently persisted consensus WAL; and
- a TCP loopback RPC listener using Flock's bounded frame codec.

The test performs a real process/network sequence:

1. the scheduled proposer signs the Phase 16 action record from its own process;
2. two validators alone cannot form a quorum;
3. three validators produce a PREVOTE QC;
4. those validators lock and sign PRECOMMITs;
5. one validator is killed and restarted before finality and recovers its lock
   plus signed vote from disk;
6. three validators finalize from the PREVOTE/PRECOMMIT QCs;
7. the fourth validator, which was process-down during consensus, restarts and
   catches up by independently verifying the action record, proposal and QCs;
8. all four nodes are killed/restarted and recover the same finalized block.

## Durable safety evidence

CONSENSUS_WAL is versioned, hash-protected and atomically replaced. It stores
the node's signed proposal/votes and observed quorum certificates. This keeps
anti-equivocation evidence across process restarts.

The action block itself remains in the Phase 16 ActionStore; Phase 18 does not
invent a second state persistence format.

## Deliberate limits

Phase 18 does not claim production BFT consensus. The integration-test
coordinator collects messages and delivers certificates. There is no peer
discovery, gossip fanout, pacemaker/timeouts, dynamic membership, slashing,
encrypted transport, NAT traversal, remote key management, or multi-height
production loop.

The next gate should replace the test coordinator with peer-to-peer
proposal/vote propagation and deterministic timeout/round progression while
retaining the same signed wire records and durable anti-equivocation state.
