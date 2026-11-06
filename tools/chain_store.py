from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
import tempfile

from tools.authenticated_state import parse_canonical_state, state_root
from tools.block_commitment import (
    BLOCK_DOMAIN,
    RECEIPT_DOMAIN,
    BlockCommitment,
    canonical_block_hash,
    receipts_root,
    transaction_root,
)
from tools.reference_model import encode_state

RECORD_DOMAIN = b"FLOCKREC1"
RECORD_HASH_DOMAIN = b"FLOCKRECORDHASH1"
HEADER_LEN = 185
HASH_SIZE = 32
ZERO_HASH = bytes(HASH_SIZE)
U32_MAX = (1 << 32) - 1


def _u32(value: int) -> bytes:
    if not 0 <= value <= U32_MAX:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


def _take_u32(data: bytes, at: int) -> tuple[int, int]:
    if len(data) < at + 4:
        raise ValueError("truncated u32")
    return struct.unpack_from(">I", data, at)[0], at + 4


def _take_blob(data: bytes, at: int) -> tuple[bytes, int]:
    size, at = _take_u32(data, at)
    end = at + size
    if end > len(data):
        raise ValueError("truncated blob")
    return data[at:end], end


@dataclass(frozen=True)
class HeaderFields:
    chain_id: int
    height: int
    parent_block_hash: bytes
    pre_state_root: bytes
    tx_root: bytes
    receipt_root: bytes
    post_state_root: bytes
    tx_count: int


@dataclass(frozen=True)
class PersistedBlock:
    raw: bytes
    header: bytes
    block_hash: bytes
    record_hash: bytes
    fields: HeaderFields
    tx_bytes: tuple[bytes, ...]
    receipts: tuple[bytes, ...]
    post_state_bytes: bytes


def parse_header(header: bytes) -> HeaderFields:
    if len(header) != HEADER_LEN or not header.startswith(BLOCK_DOMAIN):
        raise ValueError("not a canonical Phase 3 block header")

    at = len(BLOCK_DOMAIN)
    chain_id = struct.unpack_from(">I", header, at)[0]
    at += 4
    height = struct.unpack_from(">Q", header, at)[0]
    at += 8
    parent = header[at:at + 32]
    at += 32
    pre = header[at:at + 32]
    at += 32
    txr = header[at:at + 32]
    at += 32
    rr = header[at:at + 32]
    at += 32
    post = header[at:at + 32]
    at += 32
    count = struct.unpack_from(">I", header, at)[0]
    at += 4

    if at != HEADER_LEN:
        raise AssertionError("header parser width changed")

    return HeaderFields(chain_id, height, parent, pre, txr, rr, post, count)


def encode_persisted_block(commitment: BlockCommitment) -> bytes:
    state_bytes = encode_state(commitment.final_state)
    body = bytearray(RECORD_DOMAIN)
    body += _u32(len(commitment.header))
    body += commitment.header
    body += _u32(len(commitment.tx_bytes))

    for tx in commitment.tx_bytes:
        body += _u32(len(tx))
        body += tx

    body += _u32(len(commitment.receipts))
    for receipt in commitment.receipts:
        body += _u32(len(receipt))
        body += receipt

    body += _u32(len(state_bytes))
    body += state_bytes

    record_hash = hashlib.sha256(RECORD_HASH_DOMAIN + body).digest()
    return bytes(body) + record_hash


def parse_persisted_block(data: bytes) -> PersistedBlock:
    if not data.startswith(RECORD_DOMAIN):
        raise ValueError("wrong persisted-record domain")
    if len(data) < len(RECORD_DOMAIN) + 4 + HEADER_LEN + HASH_SIZE:
        raise ValueError("truncated persisted block")

    payload, stored_hash = data[:-HASH_SIZE], data[-HASH_SIZE:]
    expected_hash = hashlib.sha256(RECORD_HASH_DOMAIN + payload).digest()
    if stored_hash != expected_hash:
        raise ValueError("persisted-record hash mismatch")

    at = len(RECORD_DOMAIN)
    header_len, at = _take_u32(payload, at)
    if header_len != HEADER_LEN or len(payload) < at + header_len:
        raise ValueError("wrong or truncated block header")
    header = payload[at:at + header_len]
    at += header_len

    fields = parse_header(header)
    block_hash = canonical_block_hash(header)

    tx_count, at = _take_u32(payload, at)
    txs: list[bytes] = []
    for _ in range(tx_count):
        blob, at = _take_blob(payload, at)
        txs.append(blob)

    receipt_count, at = _take_u32(payload, at)
    receipts: list[bytes] = []
    for _ in range(receipt_count):
        blob, at = _take_blob(payload, at)
        receipts.append(blob)

    state_bytes, at = _take_blob(payload, at)
    if at != len(payload):
        raise ValueError("trailing persisted-record bytes")

    if tx_count != fields.tx_count:
        raise ValueError("transaction count does not match header")
    if receipt_count != tx_count:
        raise ValueError("receipt count does not match transaction count")
    if transaction_root(txs) != fields.tx_root:
        raise ValueError("transaction root mismatch")
    if receipts_root(receipts) != fields.receipt_root:
        raise ValueError("receipt root mismatch")

    for index, (tx, receipt) in enumerate(zip(txs, receipts, strict=True)):
        if len(receipt) != len(RECEIPT_DOMAIN) + 4 + 32 + 1 + 32:
            raise ValueError("wrong receipt length")
        if not receipt.startswith(RECEIPT_DOMAIN):
            raise ValueError("wrong receipt domain")
        rat = len(RECEIPT_DOMAIN)
        got_index = struct.unpack_from(">I", receipt, rat)[0]
        rat += 4
        got_tx_hash = receipt[rat:rat + 32]
        if got_index != index:
            raise ValueError("receipt index mismatch")
        if got_tx_hash != hashlib.sha256(tx).digest():
            raise ValueError("receipt transaction hash mismatch")

    state = parse_canonical_state(state_bytes)
    if state_root(state) != fields.post_state_root:
        raise ValueError("persisted post-state root mismatch")

    return PersistedBlock(
        raw=data,
        header=header,
        block_hash=block_hash,
        record_hash=stored_hash,
        fields=fields,
        tx_bytes=tuple(txs),
        receipts=tuple(receipts),
        post_state_bytes=state_bytes,
    )


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class ChainStore:
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.blocks = self.root / "blocks"
        self.head_path = self.root / "HEAD"
        self.blocks.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _name(height: int, block_hash: bytes) -> str:
        return f"{height:020d}-{block_hash.hex()}.flock"

    def _head(self) -> tuple[int, bytes] | None:
        if not self.head_path.exists():
            return None
        parts = self.head_path.read_text(encoding="ascii").strip().split()
        if len(parts) != 2:
            raise ValueError("malformed HEAD")
        height = int(parts[0])
        block_hash = bytes.fromhex(parts[1])
        if len(block_hash) != HASH_SIZE:
            raise ValueError("malformed HEAD hash")
        return height, block_hash

    def _record_path(self, height: int, block_hash: bytes) -> Path:
        return self.blocks / self._name(height, block_hash)

    def read(self, height: int, block_hash: bytes) -> PersistedBlock:
        return parse_persisted_block(self._record_path(height, block_hash).read_bytes())

    def tip(self) -> PersistedBlock | None:
        head = self._head()
        if head is None:
            return None
        return self.read(*head)

    def append(self, record_bytes: bytes) -> PersistedBlock:
        record = parse_persisted_block(record_bytes)
        head = self._head()

        if head is None:
            if record.fields.height != 0:
                raise ValueError("genesis height must be zero")
            if record.fields.parent_block_hash != ZERO_HASH:
                raise ValueError("genesis parent must be zero")
        else:
            previous = self.read(*head)
            if record.fields.height != previous.fields.height + 1:
                raise ValueError("height is not contiguous")
            if record.fields.parent_block_hash != previous.block_hash:
                raise ValueError("parent block hash mismatch")
            if record.fields.pre_state_root != previous.fields.post_state_root:
                raise ValueError("pre-state root does not continue previous post-state")

        target = self._record_path(record.fields.height, record.block_hash)
        if target.exists():
            raise ValueError("block already exists")

        fd, tmp_name = tempfile.mkstemp(prefix=".block-", dir=self.blocks)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(record_bytes)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, target)
            _fsync_dir(self.blocks)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

        head_text = f"{record.fields.height} {record.block_hash.hex()}\n".encode("ascii")
        fd, tmp_name = tempfile.mkstemp(prefix=".HEAD-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(head_text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.head_path)
            _fsync_dir(self.root)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

        return record

    def verify_chain(self) -> list[PersistedBlock]:
        head = self._head()
        if head is None:
            return []

        head_height, head_hash = head
        by_height: dict[int, list[Path]] = {}

        for path in self.blocks.glob("*.flock"):
            try:
                height = int(path.name.split("-", 1)[0])
            except ValueError:
                raise ValueError(f"malformed block filename: {path.name}")
            if height <= head_height:
                by_height.setdefault(height, []).append(path)

        chain: list[PersistedBlock] = []
        previous: PersistedBlock | None = None

        for height in range(head_height + 1):
            paths = by_height.get(height, [])
            if len(paths) != 1:
                raise ValueError(f"expected exactly one committed block at height {height}")
            record = parse_persisted_block(paths[0].read_bytes())
            if record.fields.height != height:
                raise ValueError("filename/header height mismatch")

            if previous is None:
                if height != 0 or record.fields.parent_block_hash != ZERO_HASH:
                    raise ValueError("invalid genesis")
            else:
                if record.fields.parent_block_hash != previous.block_hash:
                    raise ValueError("chain parent mismatch")
                if record.fields.pre_state_root != previous.fields.post_state_root:
                    raise ValueError("chain state-root discontinuity")

            chain.append(record)
            previous = record

        if not chain or chain[-1].block_hash != head_hash:
            raise ValueError("HEAD does not match verified tip")

        return chain
