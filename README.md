# Flock

Flock is an experimental blockchain systems project centered on deterministic
execution, explicit resource bounds, authenticated state, reproducibility,
and the Goose programming language.

## Execution environments

- FlockVM (FLVM) — Flock's native deterministic execution environment.
- EVM compatibility — a separate compatibility layer, not Flock's native VM.

FlockVM is not an EVM or SVM clone.

## Development order

1. Canonical consensus encoding
2. Deterministic state transition
3. Independent conformance implementation
4. Authenticated state
5. Persistence
6. Block production
7. P2P networking
8. Consensus
9. FlockVM execution
10. Multi-node Docker devnet
11. EVM compatibility
12. Adversarial and fuzz testing
13. Public testnet
14. Security gate
15. Real-value experiments only after those gates
