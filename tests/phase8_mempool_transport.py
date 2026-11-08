from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import socket
import struct

from tools.block_producer import BlockLimits, produce_block
from tools.mempool import (
    MAX_CANONICAL_TX,
    TX_MESSAGE_DOMAIN,
    TX_MESSAGE_FIXED,
    Mempool,
    MempoolLimits,
    decode_tx_message,
    encode_tx_message,
    receive_transaction,
    send_transaction,
)
from tools.reference_model import MAX_PAYLOAD, Tx, decode_tx, encode_tx
from tools.transport import (
    FRAME_DOMAIN,
    PROTOCOL_VERSION,
    Hello,
    PeerSession,
    PeerState,
)

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)
CAROL = bytes.fromhex("33" * 32)
GENESIS = bytes.fromhex("44" * 32)
TIP = bytes.fromhex("55" * 32)
ZERO = bytes(32)


def must_fail(fn, exc=ValueError) -> None:
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"{exc.__name__} was not raised")


def tx(
    *,
    chain_id: int = 1,
    nonce: int = 0,
    sender: bytes = ALICE,
    recipient: bytes = BOB,
    amount: int = 10,
    compute: int = 100,
    state: int = 10,
    memory: int = 1000,
    payload: bytes = b"phase8",
) -> Tx:
    return Tx(
        chain_id=chain_id,
        nonce=nonce,
        sender=sender,
        recipient=recipient,
        amount=amount,
        compute_limit=compute,
        state_limit=state,
        memory_limit=memory,
        payload=payload,
    )


def established(chain_id: int = 1) -> PeerSession:
    return PeerSession(
        state=PeerState.ESTABLISHED,
        remote_hello=Hello(
            PROTOCOL_VERSION,
            chain_id,
            GENESIS,
            0,
            TIP,
        ),
    )


def main() -> None:
    canonical = tx(payload=b"x" * MAX_PAYLOAD)
    raw = encode_tx(canonical)
    assert len(raw) == MAX_CANONICAL_TX
    assert decode_tx(raw) == canonical
    assert encode_tx(decode_tx(raw)) == raw

    must_fail(lambda: decode_tx(raw[:-1]))
    must_fail(lambda: decode_tx(raw + b"x"))
    must_fail(lambda: decode_tx(b"X" + raw[1:]))

    bad_payload_len = bytearray(raw)
    struct.pack_into(">I", bad_payload_len, len(raw) - MAX_PAYLOAD - 4, MAX_PAYLOAD + 1)
    must_fail(lambda: decode_tx(bytes(bad_payload_len)))
    print("PHASE8_CANONICAL_TX_DECODE=GREEN")

    msg = encode_tx_message(raw)
    assert msg.startswith(TX_MESSAGE_DOMAIN)
    assert decode_tx_message(msg) == raw
    must_fail(lambda: decode_tx_message(msg[:-1]))
    must_fail(lambda: decode_tx_message(msg + b"x"))
    must_fail(lambda: decode_tx_message(b"X" + msg[1:]))
    must_fail(lambda: encode_tx_message(b""))
    must_fail(
        lambda: encode_tx_message(
            raw,
            max_tx_bytes=len(raw) - 1,
        )
    )
    print("PHASE8_TX_MESSAGE_BOUNDS=GREEN")

    limits = MempoolLimits(
        max_entries=4,
        max_total_bytes=4 * MAX_CANONICAL_TX,
        max_tx_bytes=MAX_CANONICAL_TX,
        max_compute_per_tx=1000,
        max_state_per_tx=100,
        max_memory_per_tx=10000,
    )
    pool = Mempool(limits)

    good = tx()
    good_raw = encode_tx(good)
    accepted = pool.admit_raw(good_raw, chain_id=1)
    assert accepted.accepted and accepted.reason == "accepted"
    before = (len(pool), pool.total_bytes, pool.hashes())

    duplicate = pool.admit_raw(good_raw, chain_id=1)
    assert not duplicate.accepted and duplicate.reason == "duplicate"
    assert (len(pool), pool.total_bytes, pool.hashes()) == before

    wrong_chain = pool.admit_tx(tx(chain_id=2), chain_id=1)
    assert not wrong_chain.accepted and wrong_chain.reason == "chain_id"

    zero_amount = pool.admit_tx(tx(amount=0), chain_id=1)
    assert not zero_amount.accepted and zero_amount.reason == "zero_amount"

    self_transfer = pool.admit_tx(tx(recipient=ALICE), chain_id=1)
    assert not self_transfer.accepted and self_transfer.reason == "self_transfer"

    too_compute = pool.admit_tx(tx(nonce=1, compute=1001), chain_id=1)
    assert not too_compute.accepted and too_compute.reason == "compute"

    malformed = pool.admit_raw(b"not-a-canonical-tx", chain_id=1)
    assert not malformed.accepted and malformed.reason == "encoding"

    assert (len(pool), pool.total_bytes, pool.hashes()) == before
    print("PHASE8_STATELESS_ADMISSION=GREEN")
    print("PHASE8_REJECTION_NO_MUTATION=GREEN")

    one = encode_tx(tx())
    cap_count = Mempool(
        MempoolLimits(
            max_entries=1,
            max_total_bytes=2 * len(one),
            max_tx_bytes=MAX_CANONICAL_TX,
        )
    )
    assert cap_count.admit_raw(one, chain_id=1).accepted
    rejected = cap_count.admit_tx(tx(sender=BOB, recipient=CAROL), chain_id=1)
    assert not rejected.accepted and rejected.reason == "entry_capacity"

    cap_bytes = Mempool(
        MempoolLimits(
            max_entries=4,
            max_total_bytes=len(one),
            max_tx_bytes=MAX_CANONICAL_TX,
        )
    )
    assert cap_bytes.admit_raw(one, chain_id=1).accepted
    rejected = cap_bytes.admit_tx(tx(sender=BOB, recipient=CAROL), chain_id=1)
    assert not rejected.accepted and rejected.reason == "byte_capacity"
    print("PHASE8_MEMPOOL_CAPACITY=GREEN")

    transport_pool = Mempool(limits)
    left, right = socket.socketpair()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                receive_transaction,
                right,
                established(),
                transport_pool,
                chain_id=1,
            )
            send_transaction(
                left,
                established(),
                good_raw,
                chain_id=1,
            )
            result = future.result(timeout=5)
        assert result.accepted
        assert len(transport_pool) == 1
    finally:
        left.close()
        right.close()
    print("PHASE8_ESTABLISHED_TRANSPORT=GREEN")

    left, right = socket.socketpair()
    try:
        must_fail(
            lambda: receive_transaction(
                right,
                PeerSession(),
                Mempool(limits),
                chain_id=1,
            ),
            RuntimeError,
        )
    finally:
        left.close()
        right.close()
    print("PHASE8_PREHANDSHAKE_REJECTED=GREEN")

    malformed_pool = Mempool(limits)
    before = (len(malformed_pool), malformed_pool.total_bytes)
    left, right = socket.socketpair()
    try:
        bad = encode_tx_message(b"not-a-canonical-tx")
        left.sendall(
            FRAME_DOMAIN
            + struct.pack(">I", len(bad))
            + bad
        )
        result = receive_transaction(
            right,
            established(),
            malformed_pool,
            chain_id=1,
        )
        assert not result.accepted and result.reason == "encoding"
    finally:
        left.close()
        right.close()
    assert (len(malformed_pool), malformed_pool.total_bytes) == before
    print("PHASE8_MALFORMED_TX_NO_MUTATION=GREEN")

    oversize_pool = Mempool(
        MempoolLimits(
            max_entries=4,
            max_total_bytes=4 * MAX_CANONICAL_TX,
            max_tx_bytes=len(good_raw),
        )
    )
    before = (len(oversize_pool), oversize_pool.total_bytes)
    left, right = socket.socketpair()
    try:
        declared = TX_MESSAGE_FIXED + len(good_raw) + 1
        left.sendall(FRAME_DOMAIN + struct.pack(">I", declared))
        must_fail(
            lambda: receive_transaction(
                right,
                established(),
                oversize_pool,
                chain_id=1,
            )
        )
    finally:
        left.close()
        right.close()
    assert (len(oversize_pool), oversize_pool.total_bytes) == before
    print("PHASE8_OVERSIZE_FRAME_REJECTED_BEFORE_PAYLOAD=GREEN")

    producer_pool = Mempool(
        MempoolLimits(
            max_entries=8,
            max_total_bytes=8 * MAX_CANONICAL_TX,
            max_tx_bytes=MAX_CANONICAL_TX,
        )
    )
    assert producer_pool.admit_tx(tx(nonce=1, amount=25), chain_id=1).accepted
    assert producer_pool.admit_tx(tx(nonce=0, amount=50), chain_id=1).accepted

    state = {ALICE: (0, 1000), BOB: (0, 0)}
    produced = produce_block(
        state,
        list(producer_pool.transactions()),
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=BlockLimits(
            max_txs=8,
            max_tx_bytes=8 * MAX_CANONICAL_TX,
            max_compute=10000,
            max_state=1000,
            max_memory=100000,
        ),
    )
    assert [item.nonce for item in produced.selected] == [0, 1]
    assert produced.commitment.final_state[ALICE] == (2, 925)
    assert produced.commitment.final_state[BOB] == (0, 75)
    print("PHASE8_PHASE5_PRODUCER_INTEGRATION=GREEN")

    hashes = producer_pool.hashes()
    removed = producer_pool.remove(hashes[:1])
    assert removed == 1 and len(producer_pool) == 1
    removed = producer_pool.remove(hashes)
    assert removed == 1 and len(producer_pool) == 0 and producer_pool.total_bytes == 0
    print("PHASE8_EXPLICIT_REMOVAL=GREEN")

    print("FLOCK_PHASE8_MEMPOOL_TRANSPORT_ADMISSION=GREEN")


if __name__ == "__main__":
    main()
