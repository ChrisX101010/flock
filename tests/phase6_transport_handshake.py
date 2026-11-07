from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import socket
import struct

from tools.transport import (
    FRAME_DOMAIN,
    FRAME_HEADER_LEN,
    HELLO_DOMAIN,
    HELLO_LEN,
    PROTOCOL_VERSION,
    Hello,
    PeerSession,
    PeerState,
    decode_frame,
    decode_hello,
    encode_frame,
    encode_hello,
    hello_from_store,
    recv_frame,
    validate_hello,
)

GENESIS = bytes.fromhex("11" * 32)
GENESIS_OTHER = bytes.fromhex("22" * 32)
TIP_A = bytes.fromhex("aa" * 32)
TIP_B = bytes.fromhex("bb" * 32)


def must_fail(fn, exc=ValueError) -> None:
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"{exc.__name__} was not raised")


def hello(*, chain_id: int = 7, genesis: bytes = GENESIS, height: int = 3, tip: bytes = TIP_A) -> Hello:
    return Hello(PROTOCOL_VERSION, chain_id, genesis, height, tip)


@dataclass(frozen=True)
class FakeFields:
    chain_id: int
    height: int


@dataclass(frozen=True)
class FakeRecord:
    fields: FakeFields
    block_hash: bytes


class FakeStore:
    def __init__(self, records):
        self.records = list(records)

    def verify_chain(self):
        return list(self.records)


def main() -> None:
    local = hello()
    raw = encode_hello(local)

    assert len(raw) == HELLO_LEN
    assert raw.startswith(HELLO_DOMAIN)
    assert encode_hello(local) == raw
    assert decode_hello(raw) == local
    validate_hello(
        local,
        expected_chain_id=7,
        expected_genesis_block_hash=GENESIS,
    )
    print(f"PHASE6_HELLO_LEN={HELLO_LEN}")
    print("CANONICAL_HELLO_CODEC=GREEN")

    must_fail(lambda: decode_hello(raw[:-1]))
    must_fail(lambda: decode_hello(raw + b"x"))
    must_fail(lambda: decode_hello(b"X" + raw[1:]))

    wrong_version = bytearray(raw)
    struct.pack_into(">I", wrong_version, len(HELLO_DOMAIN), PROTOCOL_VERSION + 1)
    must_fail(
        lambda: validate_hello(
            decode_hello(bytes(wrong_version)),
            expected_chain_id=7,
            expected_genesis_block_hash=GENESIS,
        )
    )
    must_fail(
        lambda: validate_hello(
            hello(chain_id=8),
            expected_chain_id=7,
            expected_genesis_block_hash=GENESIS,
        )
    )
    must_fail(
        lambda: validate_hello(
            hello(genesis=GENESIS_OTHER),
            expected_chain_id=7,
            expected_genesis_block_hash=GENESIS,
        )
    )
    print("HELLO_ADMISSION_REJECTIONS=GREEN")

    frame = encode_frame(raw, max_payload=HELLO_LEN)
    assert len(frame) == FRAME_HEADER_LEN + HELLO_LEN
    assert decode_frame(frame, max_payload=HELLO_LEN) == raw
    must_fail(lambda: decode_frame(frame[:-1], max_payload=HELLO_LEN))
    must_fail(lambda: decode_frame(frame + b"x", max_payload=HELLO_LEN))
    must_fail(lambda: decode_frame(b"X" + frame[1:], max_payload=HELLO_LEN))
    must_fail(lambda: encode_frame(raw + b"x", max_payload=HELLO_LEN))

    oversize_header = FRAME_DOMAIN + struct.pack(">I", HELLO_LEN + 1)
    must_fail(lambda: decode_frame(oversize_header, max_payload=HELLO_LEN))
    print("BOUNDED_FRAME_CODEC=GREEN")

    # Streaming receiver must reject a peer-controlled oversize length before
    # attempting to read or allocate the declared payload.
    left, right = socket.socketpair()
    try:
        left.sendall(oversize_header)
        must_fail(lambda: recv_frame(right, max_payload=HELLO_LEN))
    finally:
        left.close()
        right.close()
    print("OVERSIZE_STREAM_FRAME_REJECTED=GREEN")

    # EOF in the middle of a declared payload is a transport failure.
    left, right = socket.socketpair()
    try:
        partial = FRAME_DOMAIN + struct.pack(">I", HELLO_LEN) + raw[:5]
        left.sendall(partial)
        left.shutdown(socket.SHUT_WR)
        must_fail(lambda: recv_frame(right, max_payload=HELLO_LEN), EOFError)
    finally:
        left.close()
        right.close()
    print("TRUNCATED_STREAM_FRAME_REJECTED=GREEN")

    # Two loopback peers can establish concurrently. Their tip advertisements
    # may differ; chain identity is chain id + genesis hash, not the tip.
    a_sock, b_sock = socket.socketpair()
    a = PeerSession()
    b = PeerSession()
    a_local = hello(height=10, tip=TIP_A)
    b_local = hello(height=12, tip=TIP_B)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            fa = pool.submit(
                a.handshake,
                a_sock,
                a_local,
                expected_chain_id=7,
                expected_genesis_block_hash=GENESIS,
            )
            fb = pool.submit(
                b.handshake,
                b_sock,
                b_local,
                expected_chain_id=7,
                expected_genesis_block_hash=GENESIS,
            )
            a_remote = fa.result(timeout=5)
            b_remote = fb.result(timeout=5)
    finally:
        a_sock.close()
        b_sock.close()

    assert a.state is PeerState.ESTABLISHED
    assert b.state is PeerState.ESTABLISHED
    assert a_remote == b_local
    assert b_remote == a_local
    assert a.remote_hello == b_local
    assert b.remote_hello == a_local
    print("LOOPBACK_HANDSHAKE=GREEN")
    print("REMOTE_TIP_IS_ADVERTISEMENT_ONLY=GREEN")

    # Admission failure transitions the local session to CLOSED and never to
    # ESTABLISHED.
    left, right = socket.socketpair()
    bad = PeerSession()
    try:
        right.sendall(encode_frame(encode_hello(hello(chain_id=99)), max_payload=HELLO_LEN))
        # The local handshake sends first, so drain its hello concurrently.
        with ThreadPoolExecutor(max_workers=1) as pool:
            drain = pool.submit(recv_frame, right, max_payload=HELLO_LEN)
            must_fail(
                lambda: bad.handshake(
                    left,
                    local,
                    expected_chain_id=7,
                    expected_genesis_block_hash=GENESIS,
                )
            )
            assert decode_hello(drain.result(timeout=5)) == local
    finally:
        left.close()
        right.close()
    assert bad.state is PeerState.CLOSED
    assert bad.remote_hello is None
    print("FAILED_HANDSHAKE_CLOSES_SESSION=GREEN")

    # Store integration consumes only verified chain metadata.
    store = FakeStore(
        [
            FakeRecord(FakeFields(7, 0), GENESIS),
            FakeRecord(FakeFields(7, 1), TIP_A),
            FakeRecord(FakeFields(7, 2), TIP_B),
        ]
    )
    derived = hello_from_store(store, chain_id=7)
    assert derived == Hello(PROTOCOL_VERSION, 7, GENESIS, 2, TIP_B)
    must_fail(lambda: hello_from_store(FakeStore([]), chain_id=7))
    must_fail(
        lambda: hello_from_store(
            FakeStore(
                [
                    FakeRecord(FakeFields(7, 0), GENESIS),
                    FakeRecord(FakeFields(8, 1), TIP_A),
                ]
            ),
            chain_id=7,
        )
    )
    print("CHAINSTORE_METADATA_INTEGRATION=GREEN")

    # The state machine is explicit and cannot handshake twice.
    must_fail(
        lambda: a.handshake(
            socket.socketpair()[0],
            a_local,
            expected_chain_id=7,
            expected_genesis_block_hash=GENESIS,
        ),
        RuntimeError,
    )
    a.close()
    b.close()
    assert a.state is PeerState.CLOSED and b.state is PeerState.CLOSED
    print("PEER_STATE_MACHINE=GREEN")

    print("FLOCK_PHASE6_TRANSPORT_HANDSHAKE=GREEN")


if __name__ == "__main__":
    main()
