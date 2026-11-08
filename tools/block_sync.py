from __future__ import annotations

from dataclasses import dataclass
import socket
import struct

from tools.chain_store import ChainStore, PersistedBlock, parse_persisted_block
from tools.transport import PeerSession, PeerState, recv_frame, send_frame

BLOCK_REQUEST_DOMAIN = b"FLOCKGETBLK1"
BLOCK_RESPONSE_DOMAIN = b"FLOCKBLK1"

BLOCK_STATUS_NOT_FOUND = 0
BLOCK_STATUS_FOUND = 1

U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1

REQUEST_LEN = len(BLOCK_REQUEST_DOMAIN) + 8
RESPONSE_FIXED_LEN = len(BLOCK_RESPONSE_DOMAIN) + 1 + 8 + 4
DEFAULT_MAX_RECORD = 1024 * 1024
DEFAULT_MAX_BLOCKS = 64


def _u32(value: int) -> bytes:
    if not 0 <= value <= U32_MAX:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    if not 0 <= value <= U64_MAX:
        raise ValueError("u64 out of range")
    return struct.pack(">Q", value)


@dataclass(frozen=True)
class BlockResponse:
    height: int
    record: bytes | None


def encode_block_request(height: int) -> bytes:
    return BLOCK_REQUEST_DOMAIN + _u64(height)


def decode_block_request(raw: bytes) -> int:
    if len(raw) != REQUEST_LEN:
        raise ValueError("wrong block-request length")
    if not raw.startswith(BLOCK_REQUEST_DOMAIN):
        raise ValueError("wrong block-request domain")
    return struct.unpack_from(">Q", raw, len(BLOCK_REQUEST_DOMAIN))[0]


def encode_block_response(
    height: int,
    record: bytes | None,
    *,
    max_record_size: int = DEFAULT_MAX_RECORD,
) -> bytes:
    if not 0 <= max_record_size <= U32_MAX:
        raise ValueError("invalid maximum record size")

    if record is None:
        status = BLOCK_STATUS_NOT_FOUND
        payload = b""
    else:
        if len(record) == 0:
            raise ValueError("found response cannot contain an empty record")
        if len(record) > max_record_size:
            raise ValueError("block record exceeds limit")
        status = BLOCK_STATUS_FOUND
        payload = record

    return b"".join(
        (
            BLOCK_RESPONSE_DOMAIN,
            bytes((status,)),
            _u64(height),
            _u32(len(payload)),
            payload,
        )
    )


def decode_block_response(
    raw: bytes,
    *,
    max_record_size: int = DEFAULT_MAX_RECORD,
) -> BlockResponse:
    if not 0 <= max_record_size <= U32_MAX:
        raise ValueError("invalid maximum record size")
    if len(raw) < RESPONSE_FIXED_LEN:
        raise ValueError("truncated block response")
    if not raw.startswith(BLOCK_RESPONSE_DOMAIN):
        raise ValueError("wrong block-response domain")

    at = len(BLOCK_RESPONSE_DOMAIN)
    status = raw[at]
    at += 1

    height = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    size = struct.unpack_from(">I", raw, at)[0]
    at += 4

    if size > max_record_size:
        raise ValueError("block record exceeds limit")
    if len(raw) != at + size:
        raise ValueError("wrong block-response payload length")

    payload = raw[at:]
    if status == BLOCK_STATUS_NOT_FOUND:
        if size != 0:
            raise ValueError("not-found response carries a record")
        return BlockResponse(height, None)

    if status == BLOCK_STATUS_FOUND:
        if size == 0:
            raise ValueError("found response has no record")
        return BlockResponse(height, payload)

    raise ValueError("unknown block-response status")


def serve_block_request(
    sock: socket.socket,
    store: ChainStore,
    *,
    max_record_size: int = DEFAULT_MAX_RECORD,
) -> BlockResponse:
    request = recv_frame(sock, max_payload=REQUEST_LEN)
    height = decode_block_request(request)

    chain = store.verify_chain()
    record = chain[height].raw if height < len(chain) else None

    response = BlockResponse(height, record)
    payload = encode_block_response(
        height,
        record,
        max_record_size=max_record_size,
    )
    send_frame(
        sock,
        payload,
        max_payload=RESPONSE_FIXED_LEN + max_record_size,
    )
    return response


def serve_block_requests(
    sock: socket.socket,
    store: ChainStore,
    count: int,
    *,
    max_record_size: int = DEFAULT_MAX_RECORD,
) -> tuple[BlockResponse, ...]:
    if count < 0:
        raise ValueError("request count must be non-negative")

    served = []
    for _ in range(count):
        served.append(
            serve_block_request(
                sock,
                store,
                max_record_size=max_record_size,
            )
        )
    return tuple(served)


def request_block(
    sock: socket.socket,
    height: int,
    *,
    max_record_size: int = DEFAULT_MAX_RECORD,
) -> bytes | None:
    send_frame(
        sock,
        encode_block_request(height),
        max_payload=REQUEST_LEN,
    )
    payload = recv_frame(
        sock,
        max_payload=RESPONSE_FIXED_LEN + max_record_size,
    )
    response = decode_block_response(
        payload,
        max_record_size=max_record_size,
    )
    if response.height != height:
        raise ValueError("peer responded for a different height")
    return response.record


def _checked_local_chain(store: ChainStore, *, chain_id: int) -> list[PersistedBlock]:
    chain = store.verify_chain()
    if not chain:
        raise ValueError("block sync requires a non-empty local chain")
    for record in chain:
        if record.fields.chain_id != chain_id:
            raise ValueError("local chain contains a different chain id")
    return chain


def sync_next_block(
    sock: socket.socket,
    session: PeerSession,
    store: ChainStore,
    *,
    chain_id: int,
    max_record_size: int = DEFAULT_MAX_RECORD,
) -> PersistedBlock | None:
    if session.state is not PeerState.ESTABLISHED or session.remote_hello is None:
        raise RuntimeError("block sync requires an established peer session")

    remote = session.remote_hello
    if remote.chain_id != chain_id:
        raise ValueError("remote hello has a different chain id")

    chain = _checked_local_chain(store, chain_id=chain_id)
    local_genesis = chain[0]
    local_tip = chain[-1]

    if remote.genesis_block_hash != local_genesis.block_hash:
        raise ValueError("remote hello has a different genesis block hash")

    if remote.tip_height < local_tip.fields.height:
        return None

    if remote.tip_height == local_tip.fields.height:
        if remote.tip_block_hash != local_tip.block_hash:
            raise ValueError("same-height peer tip diverges; fork choice is out of scope")
        return None

    requested_height = local_tip.fields.height + 1
    raw = request_block(
        sock,
        requested_height,
        max_record_size=max_record_size,
    )
    if raw is None:
        raise ValueError("peer advertised an extension but returned not found")

    parsed = parse_persisted_block(raw)
    if parsed.fields.height != requested_height:
        raise ValueError("returned record height does not match request")
    if parsed.fields.chain_id != chain_id:
        raise ValueError("returned record has a different chain id")

    if requested_height == remote.tip_height:
        if parsed.block_hash != remote.tip_block_hash:
            raise ValueError("returned terminal block does not match advertised tip")

    return store.append(raw)


def sync_to_advertised_tip(
    sock: socket.socket,
    session: PeerSession,
    store: ChainStore,
    *,
    chain_id: int,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_record_size: int = DEFAULT_MAX_RECORD,
) -> int:
    if max_blocks <= 0:
        raise ValueError("max_blocks must be positive")

    appended = 0
    for _ in range(max_blocks):
        record = sync_next_block(
            sock,
            session,
            store,
            chain_id=chain_id,
            max_record_size=max_record_size,
        )
        if record is None:
            break
        appended += 1

    return appended
