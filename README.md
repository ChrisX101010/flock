# Flock

Flock is an experimental blockchain systems project focused on deterministic
execution, explicit resource bounds, authenticated state, reproducibility, and
the Goose programming language.

The current `v0.1.0-devnet` milestone integrates the deterministic execution
stack with a four-validator multi-process devnet and a peer-to-peer BFT
pacemaker/view-change prototype.

> **Status:** research/devnet software. Flock is **not** production-ready,
> audited, or suitable for real-value deployment.

## Current milestone

The repository currently contains Phase 1 through Phase 19:

- deterministic reference execution and authenticated state;
- persistence, block production, bounded transport, block synchronization, and
  authenticated mempool admission;
- FlockVM deterministic bounded execution and versioned contract/action state;
- deterministic Ed25519 BFT votes, quorum certificates, locking and finality;
- four independent validator processes with durable consensus recovery;
- direct peer-to-peer proposal/vote/QC propagation;
- authenticated quorum-based round change and missing-proposer recovery.

Every phase is exercised by `Flock CI` on pull requests and on `master`.

## Architecture

The implemented stack is intentionally layered:

```text
transactions
    |
    v
authenticated mempool
    |
    v
deterministic block/action pipeline
    |
    v
FlockVM + versioned state
    |
    v
ActionStore / durable execution records
    |
    v
signed proposal
    |
    v
PREVOTE -> QC -> lock -> PRECOMMIT -> QC -> finality
    |
    v
P2P propagation + authenticated round-change pacemaker
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the phase/layer map and
[docs/INVARIANTS.md](docs/INVARIANTS.md) for core deterministic consensus
invariants.

## Quick verification

The consensus/devnet milestone can be checked locally with:

```bash
python3 -m py_compile \
  tools/consensus.py \
  tools/consensus_wire.py \
  tools/devnet.py \
  tools/p2p_consensus.py \
  tests/phase17_consensus_finality.py \
  tests/phase18_multiprocess_devnet.py \
  tests/phase19_p2p_consensus.py

PYTHONPATH=. python3 tests/phase17_consensus_finality.py
PYTHONPATH=. python3 tests/phase18_multiprocess_devnet.py
PYTHONPATH=. python3 tests/phase19_p2p_consensus.py
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for prerequisites and validation
details.

## Execution environments

- **FlockVM (FLVM):** Flock's native deterministic bounded execution
  environment.
- **EVM compatibility:** a separate future compatibility boundary, not the
  definition of Flock's native VM.

FlockVM is not an EVM or SVM clone.

## Safety and scope

The Phase 19 devnet deliberately does **not** claim production BFT consensus.
Not yet implemented or proven include authenticated transport identity,
persistent peer discovery, robust retransmission/anti-entropy, adaptive
timeouts, validator-set changes, slashing/evidence propagation, TLS/Noise,
multi-host WAN operation, long-duration chaos/soak testing, public testnet
operation, or security audit readiness.

The `v0.1.0-devnet` release therefore freezes the current research milestone
instead of extending it with more features.

## Release

Release notes: [docs/RELEASE_v0.1.0-devnet.md](docs/RELEASE_v0.1.0-devnet.md)

License: see [LICENSE](LICENSE).
