from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import struct
import tempfile

from tools.block_commitment import build_block_commitment
from tools.block_sync import (
    BLOCK_REQUEST_DOMAIN,
    BLOCK_RESPONSE_DOMAIN,
    DEFAULT_MAX_RECORD,
    REQUEST_LEN,
    RESPONSE_FIXED_LEN,
    decode_block_request,
    decode_block_response,
    encode_block_request,
    encode_block_response,
    request_block,
    serve_block_requests,
    sync_next_block,
    sync_to_advertised_tip,
)
from tools.chain_store import ChainStore, encode_persisted_block
from tools.reference_model import Tx
from tools.transport import (
    PROTOCOL_VERSION,
    Hello,
    PeerSession,
    PeerState,
    recv_frame,
    send_frame,
)

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)
ZERO = bytes(32)


def must_fail(fn, exc=ValueError) -> None:
    try:
        fn()
    except exc:
        return
    raise AssertionError(f"{exc.__name__} was not raised")


def tx(nonce: int, amount: int) -> Tx:
    return Tx(
        chain_id=1,
        nonce=nonce,
        sender=ALICE,
        recipient=BOB,
        amount=amount,
        compute_limit=100000,
        state_limit=64,
        memory_limit=1048576,
        payload=b"phase7",
    )


def make_records() -> list[bytes]:
    state0 = {ALICE: (0, 1000), BOB: (0, 0)}

    block0 = build_block_commitment(
        state0,
        [tx(0, 100)],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
    )
    block1 = build_block_commitment(
        block0.final_state,
        [],
        chain_id=1,
        height=1,
        parent_block_hash=block0.block_hash,
    )
    block2 = build_block_commitment(
        block1.final_state,
        [tx(1, 50)],
        chain_id=1,
        height=2,
        parent_block_hash=block1.block_hash,
    )
    block3 = build_block_commitment(
        block2.final_state,
        [],
        chain_id=1,
        height=3,
        parent_block_hash=block2.block_hash,
    )

    return [
        encode_persisted_block(block0),
        encode_persisted_block(block1),
        encode_persisted_block(block2),
        encode_persisted_block(block3),
    ]


def make_store(root: Path, records: list[bytes]) -> ChainStore:
    store = ChainStore(root)
    for raw in records:
        store.append(raw)
    return store


def established_for(remote: ChainStore) -> PeerSession:
    chain = remote.verify_chain()
    return PeerSession(
        state=PeerState.ESTABLISHED,
        remote_hello=Hello(
            PROTOCOL_VERSION,
            1,
            chain[0].block_hash,
            chain[-1].fields.height,
            chain[-1].block_hash,
        ),
    )


def snapshot(store: ChainStore) -> tuple[bytes | None, tuple[str, ...], bytes | None]:
    tip = store.tip()
    head = store.head_path.read_bytes() if store.head_path.exists() else None
    files = tuple(sorted(path.name for path in store.blocks.glob("*.flock")))
    return (tip.block_hash if tip else None, files, head)


def main() -> None:
    records = make_records()

    request = encode_block_request(7)
    assert len(request) == REQUEST_LEN
    assert request.startswith(BLOCK_REQUEST_DOMAIN)
    assert decode_block_request(request) == 7
    assert encode_block_request(7) == request
    must_fail(lambda: decode_block_request(request[:-1]))
    must_fail(lambda: decode_block_request(request + b"x"))
    must_fail(lambda: decode_block_request(b"X" + request[1:]))
    print("PHASE7_REQUEST_CODEC=GREEN")

    found = encode_block_response(
        1,
        records[1],
        max_record_size=len(records[1]),
    )
    parsed = decode_block_response(
        found,
        max_record_size=len(records[1]),
    )
    assert found.startswith(BLOCK_RESPONSE_DOMAIN)
    assert parsed.height == 1
    assert parsed.record == records[1]

    missing = encode_block_response(99, None)
    parsed_missing = decode_block_response(missing)
    assert parsed_missing.height == 99 and parsed_missing.record is None

    must_fail(
        lambda: encode_block_response(
            1,
            records[1],
            max_record_size=len(records[1]) - 1,
        )
    )
    oversize = (
        BLOCK_RESPONSE_DOMAIN
        + bytes((1,))
        + struct.pack(">Q", 1)
        + struct.pack(">I", 11)
    )
    must_fail(lambda: decode_block_response(oversize, max_record_size=10))
    must_fail(lambda: decode_block_response(found + b"x"))
    bad_status = bytearray(missing)
    bad_status[len(BLOCK_RESPONSE_DOMAIN)] = 9
    must_fail(lambda: decode_block_response(bytes(bad_status)))
    print("PHASE7_RESPONSE_BOUNDS=GREEN")

    with tempfile.TemporaryDirectory(prefix="flock-phase7-") as td:
        root = Path(td)

        remote1 = make_store(root / "remote1", records[:2])
        local1 = make_store(root / "local1", records[:1])
        left, right = socket.socketpair()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                server = pool.submit(serve_block_requests, right, remote1, 1)
                count = sync_to_advertised_tip(
                    left,
                    established_for(remote1),
                    local1,
                    chain_id=1,
                    max_blocks=1,
                )
                served = server.result(timeout=5)
            assert count == 1
            assert len(served) == 1 and served[0].height == 1
            assert local1.tip().block_hash == remote1.tip().block_hash
        finally:
            left.close()
            right.close()
        print("PHASE7_ONE_BLOCK_EXTENSION=GREEN")

        remote3 = make_store(root / "remote3", records)
        local3 = make_store(root / "local3", records[:1])
        left, right = socket.socketpair()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                server = pool.submit(serve_block_requests, right, remote3, 3)
                count = sync_to_advertised_tip(
                    left,
                    established_for(remote3),
                    local3,
                    chain_id=1,
                    max_blocks=8,
                )
                served = server.result(timeout=5)
            assert count == 3
            assert [item.height for item in served] == [1, 2, 3]
            assert [r.block_hash for r in local3.verify_chain()] == [
                r.block_hash for r in remote3.verify_chain()
            ]
        finally:
            left.close()
            right.close()
        print("PHASE7_SEQUENTIAL_EXTENSION=GREEN")

        left, right = socket.socketpair()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                server = pool.submit(serve_block_requests, right, remote1, 1)
                got = request_block(left, 99)
                served = server.result(timeout=5)
            assert got is None
            assert served[0].height == 99 and served[0].record is None
        finally:
            left.close()
            right.close()
        print("PHASE7_NOT_FOUND=GREEN")

        wrong_height_store = make_store(root / "wrong-height", records[:1])
        before = snapshot(wrong_height_store)
        left, right = socket.socketpair()

        def wrong_height_server() -> None:
            raw = recv_frame(right, max_payload=REQUEST_LEN)
            requested = decode_block_request(raw)
            payload = encode_block_response(
                requested + 1,
                records[1],
                max_record_size=DEFAULT_MAX_RECORD,
            )
            send_frame(
                right,
                payload,
                max_payload=RESPONSE_FIXED_LEN + DEFAULT_MAX_RECORD,
            )

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                server = pool.submit(wrong_height_server)
                must_fail(
                    lambda: sync_next_block(
                        left,
                        established_for(remote1),
                        wrong_height_store,
                        chain_id=1,
                    )
                )
                server.result(timeout=5)
        finally:
            left.close()
            right.close()

        assert snapshot(wrong_height_store) == before
        print("PHASE7_WRONG_HEIGHT_NO_MUTATION=GREEN")

        corrupt_store = make_store(root / "corrupt-record", records[:1])
        before = snapshot(corrupt_store)
        corrupt = bytearray(records[1])
        corrupt[len(corrupt) // 2] ^= 0x01
        left, right = socket.socketpair()

        def corrupt_server() -> None:
            raw = recv_frame(right, max_payload=REQUEST_LEN)
            requested = decode_block_request(raw)
            payload = encode_block_response(
                requested,
                bytes(corrupt),
                max_record_size=DEFAULT_MAX_RECORD,
            )
            send_frame(
                right,
                payload,
                max_payload=RESPONSE_FIXED_LEN + DEFAULT_MAX_RECORD,
            )

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                server = pool.submit(corrupt_server)
                must_fail(
                    lambda: sync_next_block(
                        left,
                        established_for(remote1),
                        corrupt_store,
                        chain_id=1,
                    )
                )
                server.result(timeout=5)
        finally:
            left.close()
            right.close()

        assert snapshot(corrupt_store) == before
        print("PHASE7_CORRUPT_RECORD_NO_MUTATION=GREEN")

        mismatch_store = make_store(root / "tip-mismatch", records[:1])
        before = snapshot(mismatch_store)
        real_remote = established_for(remote1)
        real_remote.remote_hello = Hello(
            PROTOCOL_VERSION,
            1,
            real_remote.remote_hello.genesis_block_hash,
            1,
            bytes.fromhex("ff" * 32),
        )
        left, right = socket.socketpair()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                server = pool.submit(serve_block_requests, right, remote1, 1)
                must_fail(
                    lambda: sync_next_block(
                        left,
                        real_remote,
                        mismatch_store,
                        chain_id=1,
                    )
                )
                server.result(timeout=5)
        finally:
            left.close()
            right.close()

        assert snapshot(mismatch_store) == before
        print("PHASE7_ADVERTISED_TIP_NO_MUTATION=GREEN")

    print("FLOCK_PHASE7_BLOCK_SYNC=GREEN")


if __name__ == "__main__":
    main()
