from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.authenticated_state import (  # noqa: E402
    make_proof,
    parse_canonical_state,
    state_root,
    verify_proof,
)
from tools.authenticated_state_alt import state_root_alt  # noqa: E402


if len(sys.argv) != 2:
    raise SystemExit("usage: phase2_authenticated_state.py STATE.bin")

state_bytes = Path(sys.argv[1]).read_bytes()
state = parse_canonical_state(state_bytes)

root_a = state_root(state)
root_b = state_root_alt(state)

assert root_a == root_b
assert len(root_a) == 32

# Empty-state behavior is part of the consensus vector.
assert state_root({}) == state_root_alt({})

# Dict insertion order cannot affect an authenticated map.
reversed_state = dict(reversed(list(state.items())))
assert state_root(reversed_state) == root_a
assert state_root_alt(reversed_state) == root_a

for address, value in state.items():
    proof = make_proof(state, address)
    assert len(proof) == 256
    assert verify_proof(address, value, proof, root_a)

missing = bytes.fromhex("33" * 32)
assert missing not in state

missing_proof = make_proof(state, missing)
assert verify_proof(missing, None, missing_proof, root_a)

first = next(iter(state))
nonce, balance = state[first]

mutated = dict(state)
mutated[first] = (nonce, balance + 1)
assert state_root(mutated) != root_a

removed = dict(state)
del removed[first]
assert state_root(removed) != root_a

added = dict(state)
added[missing] = (0, 1)
assert state_root(added) != root_a

print(f"STATE_ACCOUNTS={len(state)}")
print(f"FLOCK_STATE_ROOT={root_a.hex()}")
print("EMPTY_STATE_ROOT_A_EQUALS_B=GREEN")
print("SPARSE_ROOT_A_EQUALS_B=GREEN")
print("INSERTION_ORDER_INVARIANT=GREEN")
print("MEMBERSHIP_PROOFS=GREEN")
print("NON_MEMBERSHIP_PROOF=GREEN")
print("STATE_MUTATION_CHANGES_ROOT=GREEN")
print("FLOCK_PHASE2_AUTH_STATE=GREEN")
