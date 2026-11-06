import std;
import binary;
import os;

let MAX_PAYLOAD = 4096;
let U64_MAX: u64 = 18446744073709551615;

struct Account {
    address: u8[32],
    nonce:   u64,
    balance: u64,
}

struct Tx {
    chain_id:      u32,
    nonce:         u64,
    sender:        u8[32],
    recipient:     u8[32],
    amount:        u64,
    compute_limit: u64,
    state_limit:   u64,
    memory_limit:  u64,
}

fn same_bytes(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len {
        if a[i] != b[i] { return false; }
    }
    return true;
}

fn bytes_less(a: const u8[:], b: const u8[:]) -> bool {
    let n = if a.len < b.len { a.len } else { b.len };
    for i in n {
        if a[i] < b[i] { return true; }
        if a[i] > b[i] { return false; }
    }
    return a.len < b.len;
}

fn encode_tx(tx: Tx, payload: const u8[:], out: u8[>..]&) {
    assert(payload.len <= MAX_PAYLOAD);

    out.append("FLOCKTX1");
    binary::write_u32be(out, tx.chain_id);
    binary::write_u64be(out, tx.nonce);
    out.append(tx.sender);
    out.append(tx.recipient);
    binary::write_u64be(out, tx.amount);
    binary::write_u64be(out, tx.compute_limit);
    binary::write_u64be(out, tx.state_limit);
    binary::write_u64be(out, tx.memory_limit);
    binary::write_u32be(out, payload.len as u32);
    out.append(payload);
}

fn encode_account(a: Account, out: u8[>..]&) {
    out.append(a.address);
    binary::write_u64be(out, a.nonce);
    binary::write_u64be(out, a.balance);
}

fn encode_state(a: Account, b: Account, out: u8[>..]&) {
    assert(!same_bytes(a.address, b.address));

    out.append("FLOCKSTATE1");
    binary::write_u32be(out, 2);

    if bytes_less(a.address, b.address) {
        encode_account(a, out);
        encode_account(b, out);
    } else {
        encode_account(b, out);
        encode_account(a, out);
    }
}

fn apply_tx(
    sender:    Account&,
    recipient: Account&,
    tx:        Tx,
    payload:   const u8[:],
) -> bool {
    if payload.len > MAX_PAYLOAD { return false; }
    if tx.amount == 0 { return false; }

    if !same_bytes(sender.address, tx.sender) { return false; }
    if !same_bytes(recipient.address, tx.recipient) { return false; }
    if same_bytes(tx.sender, tx.recipient) { return false; }

    if sender.nonce == U64_MAX { return false; }
    if sender.nonce != tx.nonce { return false; }
    if sender.balance < tx.amount { return false; }

    if recipient.balance > U64_MAX - tx.amount { return false; }

    sender.balance -= tx.amount;
    sender.nonce += 1;
    recipient.balance += tx.amount;

    return true;
}

fn main() {
    let alice_id: u8[32] = [0x11; 32];
    let bob_id:   u8[32] = [0x22; 32];

    let tx = Tx {
        chain_id:      1,
        nonce:         0,
        sender:        alice_id,
        recipient:     bob_id,
        amount:        125,
        compute_limit: 100000,
        state_limit:   64,
        memory_limit:  1048576,
    };

    var tx_bytes: u8[>..] = [];
    encode_tx(tx, "phase0", tx_bytes);

    var alice = Account {
        address: alice_id,
        nonce:   0,
        balance: 1000,
    };

    var bob = Account {
        address: bob_id,
        nonce:   0,
        balance: 0,
    };

    assert(apply_tx(alice, bob, tx, "phase0"));
    assert(alice.nonce == 1);
    assert(alice.balance == 875);
    assert(bob.nonce == 0);
    assert(bob.balance == 125);

    var final_state: u8[>..] = [];
    encode_state(alice, bob, final_state);

    // Build the same genesis in reverse argument order to prove canonical
    // state serialization is independent of caller order.
    var reversed_state: u8[>..] = [];
    encode_state(bob, alice, reversed_state);
    assert(same_bytes(final_state, reversed_state));

    // Invalid nonce: state must remain byte-identical.
    var invalid_alice = Account {
        address: alice_id,
        nonce:   0,
        balance: 1000,
    };

    var invalid_bob = Account {
        address: bob_id,
        nonce:   0,
        balance: 0,
    };

    var before_invalid: u8[>..] = [];
    encode_state(invalid_alice, invalid_bob, before_invalid);

    let invalid_tx = Tx {
        chain_id:      1,
        nonce:         99,
        sender:        alice_id,
        recipient:     bob_id,
        amount:        1,
        compute_limit: 1,
        state_limit:   1,
        memory_limit:  1,
    };

    assert(!apply_tx(invalid_alice, invalid_bob, invalid_tx, ""));

    var after_invalid: u8[>..] = [];
    encode_state(invalid_alice, invalid_bob, after_invalid);

    assert(same_bytes(before_invalid, after_invalid));

    assert(write_file("dist/goose_tx.bin", tx_bytes));
    assert(write_file("dist/goose_state.bin", final_state));
    assert(write_file("dist/goose_invalid_state.bin", after_invalid));

    print("GOOSE_TX_ENCODING=GREEN");
    print("GOOSE_STATE_TRANSITION=GREEN");
    print("GOOSE_CANONICAL_STATE_ORDER=GREEN");
    print("GOOSE_INVALID_TX_ATOMICITY=GREEN");
    print("FLOCK_GOOSE_PHASE1=GREEN");
}
