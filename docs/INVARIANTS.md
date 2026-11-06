# Flock Consensus Invariants

For identical protocol version, genesis state, transaction ordering and block
metadata, every conforming node must produce byte-identical results.

Consensus execution must not depend on:

- wall-clock time
- locale
- filesystem ordering
- thread scheduling
- process identifiers
- nondeterministic randomness
- floating-point behavior

Invalid transactions are atomic and must leave consensus state unchanged.
Consensus monetary and resource values use fixed-width unsigned integers.
Overflow and underflow are consensus errors and never wrap.
Every consensus object is versioned or domain-separated.
