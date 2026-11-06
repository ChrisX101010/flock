from reference_model import Tx, apply_tx, encode_state, encode_tx, fingerprint as fa
from reference_model_alt import encode_transaction, fingerprint as fb, state_bytes, transition

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)

tx_a = Tx(1, 0, ALICE, BOB, 125, 100000, 64, 1048576, b"phase0")
tx_b = {"chain_id":1,"nonce":0,"sender":ALICE,"recipient":BOB,"amount":125,
        "compute_limit":100000,"state_limit":64,"memory_limit":1048576,"payload":b"phase0"}

gen_a = {ALICE:(0,1000), BOB:(0,0)}
gen_b = {ALICE:{"nonce":0,"balance":1000}, BOB:{"nonce":0,"balance":0}}

enc_a = encode_tx(tx_a)
enc_b = encode_transaction(tx_b)
assert enc_a == enc_b

st_a, ok_a = apply_tx(gen_a, tx_a)
st_b, ok_b = transition(gen_b, tx_b)
assert ok_a and ok_b
assert st_a[ALICE] == (1,875)
assert st_a[BOB] == (0,125)
assert encode_state(st_a) == state_bytes(st_b)
assert fa(st_a) == fb(st_b)

bad_a = Tx(1, 99, ALICE, BOB, 1, 1, 1, 1)
bad_b = {"chain_id":1,"nonce":99,"sender":ALICE,"recipient":BOB,"amount":1,
         "compute_limit":1,"state_limit":1,"memory_limit":1,"payload":b""}
ua, oka = apply_tx(gen_a, bad_a)
ub, okb = transition(gen_b, bad_b)
assert not oka and not okb
assert encode_state(ua) == encode_state(gen_a)
assert state_bytes(ub) == state_bytes(gen_b)

print("CANONICAL_TX_BYTES=" + enc_a.hex())
print("FINAL_STATE_BYTES=" + encode_state(st_a).hex())
print("REFERENCE_SHA256=" + fa(st_a))
print("INVALID_TX_ATOMICITY=GREEN")
print("TWO_REFERENCE_IMPLEMENTATIONS=BYTE_IDENTICAL")
print("FLOCK_PHASE0_ORACLE=GREEN")
