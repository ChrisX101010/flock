from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import socket

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.authenticated_mempool import (
    MAX_SIGNED_TX,
    SIGNED_TX_DOMAIN,
    AuthenticatedMempool,
    SignedTx,
    address_from_public_key,
    decode_signed_tx,
    encode_signed_tx,
    public_key_bytes,
    receive_signed_transaction,
    send_signed_transaction,
    sign_tx,
    verify_signed_tx,
)
from tools.block_producer import BlockLimits, produce_block
from tools.mempool import MempoolLimits
from tools.reference_model import Tx
from tools.transport import PROTOCOL_VERSION, Hello, PeerSession, PeerState

BOB = bytes.fromhex("22" * 32)
GENESIS = bytes.fromhex("44" * 32)
TIP = bytes.fromhex("55" * 32)
ZERO = bytes(32)


def must_fail(fn, exc=ValueError) -> None:
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"{exc.__name__} was not raised")


def key(byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([byte]) * 32)


ALICE_KEY = key(1)
MALLORY_KEY = key(2)
ALICE_PUB = public_key_bytes(ALICE_KEY.public_key())
MALLORY_PUB = public_key_bytes(MALLORY_KEY.public_key())
ALICE = address_from_public_key(ALICE_PUB)
MALLORY = address_from_public_key(MALLORY_PUB)


def tx(
    *,
    nonce: int = 0,
    sender: bytes = ALICE,
    recipient: bytes = BOB,
    amount: int = 10,
    chain_id: int = 1,
    payload: bytes = b"phase9",
) -> Tx:
    return Tx(
        chain_id=chain_id,
        nonce=nonce,
        sender=sender,
        recipient=recipient,
        amount=amount,
        compute_limit=100,
        state_limit=10,
        memory_limit=1000,
        payload=payload,
    )


def established(chain_id: int = 1) -> PeerSession:
    return PeerSession(
        state=PeerState.ESTABLISHED,
        remote_hello=Hello(PROTOCOL_VERSION, chain_id, GENESIS, 0, TIP),
    )


def main() -> None:
    assert len(ALICE) == 32
    assert ALICE != ALICE_PUB
    assert ALICE != MALLORY

    signed = sign_tx(tx(), ALICE_KEY)
    encoded = encode_signed_tx(signed)
    decoded = decode_signed_tx(encoded)

    assert encoded.startswith(SIGNED_TX_DOMAIN)
    assert decoded == signed
    assert verify_signed_tx(decoded) == tx()
    assert encode_signed_tx(decoded) == encoded
    assert len(encoded) <= MAX_SIGNED_TX
    print("PHASE9_SIGNED_ENVELOPE=GREEN")

    must_fail(lambda: decode_signed_tx(encoded[:-1]))
    must_fail(lambda: decode_signed_tx(encoded + b"x"))
    must_fail(lambda: decode_signed_tx(b"X" + encoded[1:]))

    tampered_tx = bytearray(signed.tx_bytes)
    tampered_tx[-1] ^= 1
    must_fail(
        lambda: verify_signed_tx(
            SignedTx(signed.public_key, signed.signature, bytes(tampered_tx))
        )
    )

    tampered_sig = bytearray(signed.signature)
    tampered_sig[0] ^= 1
    must_fail(
        lambda: verify_signed_tx(
            SignedTx(signed.public_key, bytes(tampered_sig), signed.tx_bytes)
        )
    )

    wrong_key_envelope = SignedTx(
        MALLORY_PUB,
        MALLORY_KEY.sign(b"FLOCKSIG1" + signed.tx_bytes),
        signed.tx_bytes,
    )
    must_fail(lambda: verify_signed_tx(wrong_key_envelope))
    print("PHASE9_AUTHENTICATION_FAILURES=GREEN")

    limits = MempoolLimits(
        max_entries=8,
        max_total_bytes=8 * 8192,
        max_compute_per_tx=1000,
        max_state_per_tx=100,
        max_memory_per_tx=10000,
    )
    pool = AuthenticatedMempool(limits)

    accepted = pool.admit_signed(signed, chain_id=1)
    assert accepted.accepted and accepted.reason == "accepted"
    before = (len(pool), pool.total_bytes, pool.hashes())

    duplicate = pool.admit_signed(signed, chain_id=1)
    assert not duplicate.accepted and duplicate.reason == "duplicate"
    assert (len(pool), pool.total_bytes, pool.hashes()) == before

    conflict_tx = tx(recipient=MALLORY, amount=11)
    conflict_signed = sign_tx(conflict_tx, ALICE_KEY)
    conflict = pool.admit_signed(conflict_signed, chain_id=1)
    assert not conflict.accepted and conflict.reason == "nonce_conflict"
    assert (len(pool), pool.total_bytes, pool.hashes()) == before

    sequential = pool.admit_signed(sign_tx(tx(nonce=1), ALICE_KEY), chain_id=1)
    assert sequential.accepted
    assert len(pool) == 2
    print("PHASE9_NONCE_CONFLICT_GATE=GREEN")

    wrong_chain = pool.admit_signed(
        sign_tx(tx(nonce=2, chain_id=2), ALICE_KEY),
        chain_id=1,
    )
    assert not wrong_chain.accepted and wrong_chain.reason == "chain_id"

    before_bad = (len(pool), pool.total_bytes, pool.hashes())
    bad_sig = SignedTx(
        signed.public_key,
        bytes([signed.signature[0] ^ 1]) + signed.signature[1:],
        signed.tx_bytes,
    )
    rejected = pool.admit_signed(bad_sig, chain_id=1)
    assert not rejected.accepted
    assert (len(pool), pool.total_bytes, pool.hashes()) == before_bad
    print("PHASE9_AUTH_REJECTION_NO_MUTATION=GREEN")

    transport_pool = AuthenticatedMempool(limits)
    transport_signed = encode_signed_tx(sign_tx(tx(), ALICE_KEY))

    left, right = socket.socketpair()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                receive_signed_transaction,
                right,
                established(),
                transport_pool,
                chain_id=1,
            )
            send_signed_transaction(
                left,
                established(),
                transport_signed,
                chain_id=1,
            )
            result = future.result(timeout=5)
        assert result.accepted
        assert len(transport_pool) == 1
    finally:
        left.close()
        right.close()
    print("PHASE9_AUTHENTICATED_TRANSPORT=GREEN")

    left, right = socket.socketpair()
    try:
        must_fail(
            lambda: receive_signed_transaction(
                right,
                PeerSession(),
                AuthenticatedMempool(limits),
                chain_id=1,
            ),
            RuntimeError,
        )
    finally:
        left.close()
        right.close()
    print("PHASE9_PREHANDSHAKE_REJECTED=GREEN")

    producer_pool = AuthenticatedMempool(limits)
    assert producer_pool.admit_signed(
        sign_tx(tx(nonce=1, amount=25), ALICE_KEY), chain_id=1
    ).accepted
    assert producer_pool.admit_signed(
        sign_tx(tx(nonce=0, amount=50), ALICE_KEY), chain_id=1
    ).accepted

    state = {ALICE: (0, 1000), BOB: (0, 0)}
    produced = produce_block(
        state,
        list(producer_pool.transactions()),
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=BlockLimits(
            max_txs=8,
            max_tx_bytes=8 * 8192,
            max_compute=10000,
            max_state=1000,
            max_memory=100000,
        ),
    )
    assert [item.nonce for item in produced.selected] == [0, 1]
    assert produced.commitment.final_state[ALICE] == (2, 925)
    assert produced.commitment.final_state[BOB] == (0, 75)
    print("PHASE9_PHASE5_PRODUCER_INTEGRATION=GREEN")

    assert producer_pool.remove(producer_pool.hashes()) == 2
    assert len(producer_pool) == 0
    assert producer_pool.total_bytes == 0
    print("PHASE9_NONCE_INDEX_REMOVAL=GREEN")

    print("FLOCK_PHASE9_AUTHENTICATED_TRANSACTION_ADMISSION=GREEN")


if __name__ == "__main__":
    main()
