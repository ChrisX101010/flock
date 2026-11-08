from __future__ import annotations

from dataclasses import dataclass
import hashlib
import socket
import struct

from tools.reference_model import MAX_PAYLOAD, TX_FIXED_LEN, U64_MAX, Tx, decode_tx, encode_tx
from tools.transport import PeerSession, PeerState, recv_frame, send_frame

TX_MESSAGE_DOMAIN = b"FLOCKTXMSG1"
CANONICAL_TX_FIXED = TX_FIXED_LEN
MAX_CANONICAL_TX = CANONICAL_TX_FIXED + MAX_PAYLOAD
TX_MESSAGE_FIXED = len(TX_MESSAGE_DOMAIN) + 4


@dataclass(frozen=True)
class MempoolLimits:
    max_entries: int = 1024
    max_total_bytes: int = 4 * 1024 * 1024
    max_tx_bytes: int = MAX_CANONICAL_TX
    max_compute_per_tx: int = U64_MAX
    max_state_per_tx: int = U64_MAX
    max_memory_per_tx: int = U64_MAX

    def __post_init__(self) -> None:
        for name, value in (
            ("max_entries", self.max_entries),
            ("max_total_bytes", self.max_total_bytes),
            ("max_tx_bytes", self.max_tx_bytes),
            ("max_compute_per_tx", self.max_compute_per_tx),
            ("max_state_per_tx", self.max_state_per_tx),
            ("max_memory_per_tx", self.max_memory_per_tx),
        ):
            if value < 0:
                raise ValueError(f"{name} must be non-negative")

        if self.max_tx_bytes > MAX_CANONICAL_TX:
            raise ValueError("max_tx_bytes exceeds canonical transaction maximum")


@dataclass(frozen=True)
class Admission:
    accepted: bool
    reason: str
    tx_hash: bytes


class Mempool:
    def __init__(self, limits: MempoolLimits | None = None):
        self.limits = limits or MempoolLimits()
        self._entries: dict[bytes, tuple[Tx, bytes]] = {}
        self._total_bytes = 0

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    def hashes(self) -> tuple[bytes, ...]:
        return tuple(sorted(self._entries))

    def transactions(self) -> tuple[Tx, ...]:
        return tuple(self._entries[h][0] for h in sorted(self._entries))

    def raw_transactions(self) -> tuple[bytes, ...]:
        return tuple(self._entries[h][1] for h in sorted(self._entries))

    def admit_tx(self, tx: Tx, *, chain_id: int) -> Admission:
        try:
            raw = encode_tx(tx)
        except ValueError:
            digest = hashlib.sha256(repr(tx).encode("utf-8")).digest()
            return Admission(False, "encoding", digest)
        return self.admit_raw(raw, chain_id=chain_id)

    def admit_raw(self, raw: bytes, *, chain_id: int) -> Admission:
        digest = hashlib.sha256(raw).digest()

        if len(raw) > self.limits.max_tx_bytes:
            return Admission(False, "tx_bytes", digest)

        try:
            tx = decode_tx(raw)
        except ValueError:
            return Admission(False, "encoding", digest)

        if tx.chain_id != chain_id:
            return Admission(False, "chain_id", digest)
        if tx.amount == 0:
            return Admission(False, "zero_amount", digest)
        if tx.sender == tx.recipient:
            return Admission(False, "self_transfer", digest)
        if tx.compute_limit > self.limits.max_compute_per_tx:
            return Admission(False, "compute", digest)
        if tx.state_limit > self.limits.max_state_per_tx:
            return Admission(False, "state", digest)
        if tx.memory_limit > self.limits.max_memory_per_tx:
            return Admission(False, "memory", digest)

        if digest in self._entries:
            return Admission(False, "duplicate", digest)

        if len(self._entries) >= self.limits.max_entries:
            return Admission(False, "entry_capacity", digest)
        if self._total_bytes + len(raw) > self.limits.max_total_bytes:
            return Admission(False, "byte_capacity", digest)

        self._entries[digest] = (tx, raw)
        self._total_bytes += len(raw)
        return Admission(True, "accepted", digest)

    def remove(self, tx_hashes) -> int:
        removed = 0
        for tx_hash in tx_hashes:
            item = self._entries.pop(tx_hash, None)
            if item is not None:
                self._total_bytes -= len(item[1])
                removed += 1
        return removed


def encode_tx_message(
    raw: bytes,
    *,
    max_tx_bytes: int = MAX_CANONICAL_TX,
) -> bytes:
    if not 0 <= max_tx_bytes <= MAX_CANONICAL_TX:
        raise ValueError("invalid maximum transaction size")
    if not raw:
        raise ValueError("transaction message cannot be empty")
    if len(raw) > max_tx_bytes:
        raise ValueError("transaction message exceeds limit")
    return TX_MESSAGE_DOMAIN + struct.pack(">I", len(raw)) + raw


def decode_tx_message(
    payload: bytes,
    *,
    max_tx_bytes: int = MAX_CANONICAL_TX,
) -> bytes:
    if not 0 <= max_tx_bytes <= MAX_CANONICAL_TX:
        raise ValueError("invalid maximum transaction size")
    if len(payload) < TX_MESSAGE_FIXED:
        raise ValueError("truncated transaction message")
    if not payload.startswith(TX_MESSAGE_DOMAIN):
        raise ValueError("wrong transaction-message domain")

    size = struct.unpack_from(">I", payload, len(TX_MESSAGE_DOMAIN))[0]
    if size == 0:
        raise ValueError("transaction message cannot be empty")
    if size > max_tx_bytes:
        raise ValueError("transaction message exceeds limit")
    if len(payload) != TX_MESSAGE_FIXED + size:
        raise ValueError("wrong transaction-message payload length")
    return payload[TX_MESSAGE_FIXED:]


def _require_established(session: PeerSession, *, chain_id: int) -> None:
    if session.state is not PeerState.ESTABLISHED or session.remote_hello is None:
        raise RuntimeError("mempool transport requires an established peer session")
    if session.remote_hello.chain_id != chain_id:
        raise ValueError("remote hello has a different chain id")


def send_transaction(
    sock: socket.socket,
    session: PeerSession,
    raw: bytes,
    *,
    chain_id: int,
    max_tx_bytes: int = MAX_CANONICAL_TX,
) -> None:
    _require_established(session, chain_id=chain_id)
    payload = encode_tx_message(raw, max_tx_bytes=max_tx_bytes)
    send_frame(
        sock,
        payload,
        max_payload=TX_MESSAGE_FIXED + max_tx_bytes,
    )


def receive_transaction(
    sock: socket.socket,
    session: PeerSession,
    mempool: Mempool,
    *,
    chain_id: int,
) -> Admission:
    _require_established(session, chain_id=chain_id)
    payload = recv_frame(
        sock,
        max_payload=TX_MESSAGE_FIXED + mempool.limits.max_tx_bytes,
    )
    raw = decode_tx_message(
        payload,
        max_tx_bytes=mempool.limits.max_tx_bytes,
    )
    return mempool.admit_raw(raw, chain_id=chain_id)
