from pathlib import Path

from reference_model import Tx, apply_tx, encode_state, encode_tx

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)

tx = Tx(
    chain_id=1,
    nonce=0,
    sender=ALICE,
    recipient=BOB,
    amount=125,
    compute_limit=100_000,
    state_limit=64,
    memory_limit=1_048_576,
    payload=b"phase0",
)

genesis = {
    ALICE: (0, 1000),
    BOB: (0, 0),
}

final_state, ok = apply_tx(genesis, tx)
assert ok

invalid = Tx(
    chain_id=1,
    nonce=99,
    sender=ALICE,
    recipient=BOB,
    amount=1,
    compute_limit=1,
    state_limit=1,
    memory_limit=1,
    payload=b"",
)

invalid_state, invalid_ok = apply_tx(genesis, invalid)
assert not invalid_ok

dist = Path("dist")
dist.mkdir(exist_ok=True)

(dist / "python_tx.bin").write_bytes(encode_tx(tx))
(dist / "python_state.bin").write_bytes(encode_state(final_state))
(dist / "python_invalid_state.bin").write_bytes(encode_state(invalid_state))

print("PYTHON_PHASE1_EXPECTED=GREEN")
