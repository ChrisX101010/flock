from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import socket
import struct

HELLO_DOMAIN = b"FLOCKHELLO1"
FRAME_DOMAIN = b"FLOCKFRM1"
PROTOCOL_VERSION = 1
HASH_SIZE = 32
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1

HELLO_LEN = len(HELLO_DOMAIN) + 4 + 4 + HASH_SIZE + 8 + HASH_SIZE
FRAME_HEADER_LEN = len(FRAME_DOMAIN) + 4
DEFAULT_MAX_FRAME = 64 * 1024


def _u32(value: int) -> bytes:
    if not 0 <= value <= U32_MAX:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    if not 0 <= value <= U64_MAX:
        raise ValueError("u64 out of range")
    return struct.pack(">Q", value)


@dataclass(frozen=True)
class Hello:
    protocol_version: int
    chain_id: int
    genesis_block_hash: bytes
    tip_height: int
    tip_block_hash: bytes


class PeerState(Enum):
    PRE_HANDSHAKE = "pre_handshake"
    ESTABLISHED = "established"
    CLOSED = "closed"


def encode_hello(hello: Hello) -> bytes:
    if len(hello.genesis_block_hash) != HASH_SIZE:
        raise ValueError("genesis block hash must be 32 bytes")
    if len(hello.tip_block_hash) != HASH_SIZE:
        raise ValueError("tip block hash must be 32 bytes")

    raw = b"".join(
        (
            HELLO_DOMAIN,
            _u32(hello.protocol_version),
            _u32(hello.chain_id),
            hello.genesis_block_hash,
            _u64(hello.tip_height),
            hello.tip_block_hash,
        )
    )
    if len(raw) != HELLO_LEN:
        raise AssertionError("canonical hello width changed")
    return raw


def decode_hello(raw: bytes) -> Hello:
    if len(raw) != HELLO_LEN:
        raise ValueError("wrong hello length")
    if not raw.startswith(HELLO_DOMAIN):
        raise ValueError("wrong hello domain")

    at = len(HELLO_DOMAIN)
    protocol_version = struct.unpack_from(">I", raw, at)[0]
    at += 4
    chain_id = struct.unpack_from(">I", raw, at)[0]
    at += 4
    genesis = raw[at:at + HASH_SIZE]
    at += HASH_SIZE
    tip_height = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    tip = raw[at:at + HASH_SIZE]
    at += HASH_SIZE

    if at != len(raw):
        raise AssertionError("hello parser width changed")

    return Hello(protocol_version, chain_id, genesis, tip_height, tip)


def validate_hello(
    hello: Hello,
    *,
    expected_chain_id: int,
    expected_genesis_block_hash: bytes,
    expected_protocol_version: int = PROTOCOL_VERSION,
) -> None:
    if len(expected_genesis_block_hash) != HASH_SIZE:
        raise ValueError("expected genesis block hash must be 32 bytes")
    if hello.protocol_version != expected_protocol_version:
        raise ValueError("unsupported protocol version")
    if hello.chain_id != expected_chain_id:
        raise ValueError("wrong chain id")
    if hello.genesis_block_hash != expected_genesis_block_hash:
        raise ValueError("wrong genesis block hash")


def encode_frame(payload: bytes, *, max_payload: int = DEFAULT_MAX_FRAME) -> bytes:
    if max_payload < 0 or max_payload > U32_MAX:
        raise ValueError("invalid maximum frame size")
    if len(payload) > max_payload:
        raise ValueError("frame payload exceeds limit")
    return FRAME_DOMAIN + _u32(len(payload)) + payload


def decode_frame(raw: bytes, *, max_payload: int = DEFAULT_MAX_FRAME) -> bytes:
    if max_payload < 0 or max_payload > U32_MAX:
        raise ValueError("invalid maximum frame size")
    if len(raw) < FRAME_HEADER_LEN:
        raise ValueError("truncated frame header")
    if not raw.startswith(FRAME_DOMAIN):
        raise ValueError("wrong frame domain")

    size = struct.unpack_from(">I", raw, len(FRAME_DOMAIN))[0]
    if size > max_payload:
        raise ValueError("frame payload exceeds limit")

    expected = FRAME_HEADER_LEN + size
    if len(raw) < expected:
        raise ValueError("truncated frame payload")
    if len(raw) > expected:
        raise ValueError("trailing frame bytes")
    return raw[FRAME_HEADER_LEN:]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    if size < 0:
        raise ValueError("negative receive size")
    out = bytearray()
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            raise EOFError("unexpected EOF")
        out += chunk
    return bytes(out)


def send_frame(
    sock: socket.socket,
    payload: bytes,
    *,
    max_payload: int = DEFAULT_MAX_FRAME,
) -> None:
    sock.sendall(encode_frame(payload, max_payload=max_payload))


def recv_frame(
    sock: socket.socket,
    *,
    max_payload: int = DEFAULT_MAX_FRAME,
) -> bytes:
    if max_payload < 0 or max_payload > U32_MAX:
        raise ValueError("invalid maximum frame size")

    header = recv_exact(sock, FRAME_HEADER_LEN)
    if not header.startswith(FRAME_DOMAIN):
        raise ValueError("wrong frame domain")

    size = struct.unpack_from(">I", header, len(FRAME_DOMAIN))[0]
    if size > max_payload:
        raise ValueError("frame payload exceeds limit")

    return recv_exact(sock, size)


def hello_from_store(store, *, chain_id: int) -> Hello:
    chain = store.verify_chain()
    if not chain:
        raise ValueError("cannot advertise an empty chain")

    for record in chain:
        if record.fields.chain_id != chain_id:
            raise ValueError("verified chain contains a different chain id")

    genesis = chain[0]
    tip = chain[-1]
    return Hello(
        protocol_version=PROTOCOL_VERSION,
        chain_id=chain_id,
        genesis_block_hash=genesis.block_hash,
        tip_height=tip.fields.height,
        tip_block_hash=tip.block_hash,
    )


@dataclass
class PeerSession:
    state: PeerState = PeerState.PRE_HANDSHAKE
    remote_hello: Hello | None = None

    def handshake(
        self,
        sock: socket.socket,
        local_hello: Hello,
        *,
        expected_chain_id: int,
        expected_genesis_block_hash: bytes,
        timeout: float = 2.0,
    ) -> Hello:
        if self.state is not PeerState.PRE_HANDSHAKE:
            raise RuntimeError("handshake requires PRE_HANDSHAKE state")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        old_timeout = sock.gettimeout()
        try:
            sock.settimeout(timeout)
            send_frame(sock, encode_hello(local_hello), max_payload=HELLO_LEN)
            remote = decode_hello(recv_frame(sock, max_payload=HELLO_LEN))
            validate_hello(
                remote,
                expected_chain_id=expected_chain_id,
                expected_genesis_block_hash=expected_genesis_block_hash,
            )
        except Exception:
            self.state = PeerState.CLOSED
            raise
        finally:
            sock.settimeout(old_timeout)

        self.remote_hello = remote
        self.state = PeerState.ESTABLISHED
        return remote

    def close(self) -> None:
        self.state = PeerState.CLOSED
