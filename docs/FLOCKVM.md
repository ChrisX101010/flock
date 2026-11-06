# FlockVM

FlockVM is Flock's native execution environment.

## Goals

- deterministic execution
- bounded execution
- explicit host interface
- deterministic state access
- deterministic failure semantics
- no ambient network or filesystem access
- no wall-clock dependency
- no nondeterministic randomness
- explicit compute, state-I/O and memory accounting
- small attack surface

EVM support remains a compatibility boundary and does not define FlockVM semantics.
A conventional unrestricted heap is not a design requirement.
