# Flock v0.1.0-devnet Quickstart

Flock is research/devnet software. These commands validate the current
deterministic BFT/devnet milestone; they do not create a production network.

## Prerequisites

For the Phase 17–19 Python validation path:

- Linux or WSL2;
- Python 3;
- Python `cryptography` support;
- Git.

On Ubuntu, the CI-equivalent package is:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-cryptography git
```

## Clone

```bash
git clone https://github.com/ChrisX101010/flock.git
cd flock
git checkout v0.1.0-devnet
```

Before the release tag exists, use `master` instead of the final checkout line.

## Verify syntax

```bash
python3 -m py_compile \
  tools/consensus.py \
  tools/consensus_wire.py \
  tools/devnet.py \
  tools/p2p_consensus.py \
  tests/phase17_consensus_finality.py \
  tests/phase18_multiprocess_devnet.py \
  tests/phase19_p2p_consensus.py
```

## Phase 17 — deterministic BFT finality

```bash
PYTHONPATH=. python3 tests/phase17_consensus_finality.py
```

The final marker is:

```text
FLOCK_PHASE17_DETERMINISTIC_BFT_FINALITY=GREEN
```

## Phase 18 — multi-process devnet

```bash
PYTHONPATH=. python3 tests/phase18_multiprocess_devnet.py
```

The final marker is:

```text
FLOCK_PHASE18_MULTIPROCESS_DEVNET=GREEN
```

## Phase 19 — P2P consensus and pacemaker

```bash
PYTHONPATH=. python3 tests/phase19_p2p_consensus.py
```

Expected milestone markers include:

```text
PHASE19_AUTONOMOUS_ROUND0_FINALITY=GREEN
PHASE19_ROUND_CHANGE_QC_PROPAGATION=GREEN
PHASE19_SIGNED_VIEW_CHANGE=GREEN
PHASE19_THREE_LIVE_PROPOSER_QUORUM=GREEN
PHASE19_MISSING_PROPOSER_RECOVERY=GREEN
PHASE19_VIEW_CHANGE_RESTART_RECOVERY=GREEN
PHASE19_MINORITY_CANNOT_VIEW_CHANGE=GREEN
PHASE19_MINORITY_CANNOT_FINALIZE=GREEN
FLOCK_PHASE19_P2P_PACEMAKER=GREEN
```

`PHASE19_ROUND0_OPTIONAL_PROPOSAL_CACHE_MISS` may also be printed. It is
diagnostic: finalized nodes are required to retain the matching PREVOTE and
PRECOMMIT QCs; every follower retaining the original proposal in an optional
local proposal cache is not a finality invariant.

## Full repository CI

The authoritative repository gate is `.github/workflows/ci.yml`. It validates
Phases 1–19 and builds a pinned Goose compiler before the Goose conformance
checks.

For `v0.1.0-devnet`, release readiness requires a successful `Flock CI` run on
the exact tagged `master` commit.
