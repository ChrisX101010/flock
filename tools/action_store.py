from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
import tempfile

from tools.authenticated_state import parse_canonical_state
from tools.block_commitment import receipts_root, transaction_root
from tools.contract_runtime import ContractRegistry
from tools.contract_state import decode_contract_state, encode_contract_state
from tools.deployment_actions import ActionBlockResult, _action_block_hash
from tools.execution_pipeline import UnifiedState, combined_state_root
from tools.reference_model import encode_state

RECORD_DOMAIN = b"FLOCKACTREC1"
RECORD_HASH_DOMAIN = b"FLOCKACTRECHASH1"
HASH_SIZE = 32
ZERO_HASH = bytes(HASH_SIZE)


@dataclass(frozen=True)
class PersistedActionBlock:
    raw: bytes
    record_hash: bytes
    chain_id: int
    height: int
    parent_block_hash: bytes
    pre_registry_root: bytes
    post_registry_root: bytes
    pre_state_root: bytes
    tx_root: bytes
    receipt_root: bytes
    post_state_root: bytes
    block_hash: bytes
    tx_bytes: tuple[bytes, ...]
    receipts: tuple[bytes, ...]
    accounts_bytes: bytes
    contracts_bytes: bytes
    registry_bytes: bytes
    final_state: UnifiedState
    registry: ContractRegistry


def _u32(value: int) -> bytes:
    if not 0 <= value <= (1 << 32) - 1:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    if not 0 <= value <= (1 << 64) - 1:
        raise ValueError("u64 out of range")
    return struct.pack(">Q", value)


def _take_u32(data: bytes, at: int) -> tuple[int, int]:
    if len(data) < at + 4:
        raise ValueError("truncated u32")
    return struct.unpack_from(">I", data, at)[0], at + 4


def _take_u64(data: bytes, at: int) -> tuple[int, int]:
    if len(data) < at + 8:
        raise ValueError("truncated u64")
    return struct.unpack_from(">Q", data, at)[0], at + 8


def _take_hash(data: bytes, at: int) -> tuple[bytes, int]:
    if len(data) < at + HASH_SIZE:
        raise ValueError("truncated hash")
    return data[at:at + HASH_SIZE], at + HASH_SIZE


def _blob(value: bytes) -> bytes:
    return _u32(len(value)) + value


def _take_blob(data: bytes, at: int) -> tuple[bytes, int]:
    size, at = _take_u32(data, at)
    end = at + size
    if end > len(data):
        raise ValueError("truncated blob")
    return data[at:end], end


def encode_action_record(
    block: ActionBlockResult,
) -> bytes:
    registry = ContractRegistry.from_bytes(block.final_registry_bytes)

    if registry.root() != block.post_registry_root:
        raise ValueError("post-registry root does not match action block")
    if combined_state_root(block.final_state, registry) != block.post_state_root:
        raise ValueError("final state does not match action block")

    accounts_bytes = encode_state(block.final_state.accounts)
    contracts_bytes = encode_contract_state(block.final_state.contracts)
    registry_bytes = block.final_registry_bytes

    body = bytearray(RECORD_DOMAIN)
    body += _u32(block.chain_id)
    body += _u64(block.height)
    body += block.parent_block_hash
    body += block.pre_registry_root
    body += block.post_registry_root
    body += block.pre_state_root
    body += block.tx_root
    body += block.receipt_root
    body += block.post_state_root
    body += block.block_hash

    body += _u32(len(block.selected_bytes))
    for raw in block.selected_bytes:
        body += _blob(raw)

    body += _u32(len(block.receipts))
    for receipt in block.receipts:
        body += _blob(receipt)

    body += _blob(accounts_bytes)
    body += _blob(contracts_bytes)
    body += _blob(registry_bytes)

    record_hash = hashlib.sha256(RECORD_HASH_DOMAIN + body).digest()
    return bytes(body) + record_hash


def parse_action_record(data: bytes) -> PersistedActionBlock:
    if not data.startswith(RECORD_DOMAIN):
        raise ValueError("wrong action-record domain")
    if len(data) < len(RECORD_DOMAIN) + HASH_SIZE:
        raise ValueError("truncated action record")

    payload, stored_record_hash = data[:-HASH_SIZE], data[-HASH_SIZE:]
    expected_record_hash = hashlib.sha256(
        RECORD_HASH_DOMAIN + payload
    ).digest()
    if stored_record_hash != expected_record_hash:
        raise ValueError("action-record hash mismatch")

    at = len(RECORD_DOMAIN)
    chain_id, at = _take_u32(payload, at)
    height, at = _take_u64(payload, at)
    parent_block_hash, at = _take_hash(payload, at)
    pre_registry_root, at = _take_hash(payload, at)
    post_registry_root, at = _take_hash(payload, at)
    pre_state_root, at = _take_hash(payload, at)
    tx_root_value, at = _take_hash(payload, at)
    receipt_root_value, at = _take_hash(payload, at)
    post_state_root, at = _take_hash(payload, at)
    stored_block_hash, at = _take_hash(payload, at)

    tx_count, at = _take_u32(payload, at)
    txs: list[bytes] = []
    for _ in range(tx_count):
        raw, at = _take_blob(payload, at)
        txs.append(raw)

    receipt_count, at = _take_u32(payload, at)
    receipts: list[bytes] = []
    for _ in range(receipt_count):
        raw, at = _take_blob(payload, at)
        receipts.append(raw)

    accounts_bytes, at = _take_blob(payload, at)
    contracts_bytes, at = _take_blob(payload, at)
    registry_bytes, at = _take_blob(payload, at)

    if at != len(payload):
        raise ValueError("trailing action-record bytes")
    if receipt_count != tx_count:
        raise ValueError("receipt count does not match transaction count")
    if transaction_root(txs) != tx_root_value:
        raise ValueError("transaction root mismatch")
    if receipts_root(receipts) != receipt_root_value:
        raise ValueError("receipt root mismatch")

    accounts = parse_canonical_state(accounts_bytes)
    contracts = decode_contract_state(contracts_bytes)
    registry = ContractRegistry.from_bytes(registry_bytes)

    if registry.root() != post_registry_root:
        raise ValueError("persisted post-registry root mismatch")

    final_state = UnifiedState(
        accounts=accounts,
        contracts=contracts,
    )
    if combined_state_root(final_state, registry) != post_state_root:
        raise ValueError("persisted unified state root mismatch")

    expected_block_hash = _action_block_hash(
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
        pre_registry_root=pre_registry_root,
        post_registry_root=post_registry_root,
        pre_state_root=pre_state_root,
        tx_root_value=tx_root_value,
        receipt_root_value=receipt_root_value,
        post_state_root=post_state_root,
        tx_count=tx_count,
    )
    if expected_block_hash != stored_block_hash:
        raise ValueError("action block hash mismatch")

    return PersistedActionBlock(
        raw=data,
        record_hash=stored_record_hash,
        chain_id=chain_id,
        height=height,
        parent_block_hash=parent_block_hash,
        pre_registry_root=pre_registry_root,
        post_registry_root=post_registry_root,
        pre_state_root=pre_state_root,
        tx_root=tx_root_value,
        receipt_root=receipt_root_value,
        post_state_root=post_state_root,
        block_hash=stored_block_hash,
        tx_bytes=tuple(txs),
        receipts=tuple(receipts),
        accounts_bytes=accounts_bytes,
        contracts_bytes=contracts_bytes,
        registry_bytes=registry_bytes,
        final_state=final_state,
        registry=registry,
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


class ActionStore:
    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.blocks = self.root / "action-blocks"
        self.head_path = self.root / "ACTION_HEAD"
        self.blocks.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _name(height: int, block_hash: bytes) -> str:
        return f"{height:020d}-{block_hash.hex()}.flockact"

    def _head(self) -> tuple[int, bytes] | None:
        if not self.head_path.exists():
            return None
        parts = self.head_path.read_text(encoding="ascii").strip().split()
        if len(parts) != 2:
            raise ValueError("malformed action HEAD")
        height = int(parts[0])
        block_hash = bytes.fromhex(parts[1])
        if len(block_hash) != HASH_SIZE:
            raise ValueError("malformed action HEAD hash")
        return height, block_hash

    def _path(self, height: int, block_hash: bytes) -> Path:
        return self.blocks / self._name(height, block_hash)

    def read(self, height: int, block_hash: bytes) -> PersistedActionBlock:
        return parse_action_record(
            self._path(height, block_hash).read_bytes()
        )

    def tip(self) -> PersistedActionBlock | None:
        head = self._head()
        if head is None:
            return None
        return self.read(*head)

    def append(self, record_bytes: bytes) -> PersistedActionBlock:
        record = parse_action_record(record_bytes)
        head = self._head()

        if head is None:
            if record.height != 0:
                raise ValueError("action genesis height must be zero")
            if record.parent_block_hash != ZERO_HASH:
                raise ValueError("action genesis parent must be zero")
        else:
            previous = self.read(*head)
            if record.height != previous.height + 1:
                raise ValueError("action height is not contiguous")
            if record.parent_block_hash != previous.block_hash:
                raise ValueError("action parent hash mismatch")
            if record.pre_state_root != previous.post_state_root:
                raise ValueError("action state-root discontinuity")
            if record.pre_registry_root != previous.post_registry_root:
                raise ValueError("action registry-root discontinuity")

        target = self._path(record.height, record.block_hash)
        if target.exists():
            raise ValueError("action block already exists")

        fd, tmp_name = tempfile.mkstemp(prefix=".action-", dir=self.blocks)
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

        head_bytes = (
            f"{record.height} {record.block_hash.hex()}\n"
        ).encode("ascii")
        fd, tmp_name = tempfile.mkstemp(prefix=".ACTION_HEAD-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(head_bytes)
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

    def verify_chain(self) -> list[PersistedActionBlock]:
        head = self._head()
        if head is None:
            return []

        head_height, head_hash = head
        by_height: dict[int, list[Path]] = {}

        for path in self.blocks.glob("*.flockact"):
            try:
                height = int(path.name.split("-", 1)[0])
            except ValueError as exc:
                raise ValueError(
                    f"malformed action-block filename: {path.name}"
                ) from exc
            if height <= head_height:
                by_height.setdefault(height, []).append(path)

        chain: list[PersistedActionBlock] = []
        previous: PersistedActionBlock | None = None

        for height in range(head_height + 1):
            paths = by_height.get(height, [])
            if len(paths) != 1:
                raise ValueError(
                    f"expected exactly one action block at height {height}"
                )

            record = parse_action_record(paths[0].read_bytes())
            if record.height != height:
                raise ValueError("action filename/header height mismatch")

            if previous is None:
                if height != 0 or record.parent_block_hash != ZERO_HASH:
                    raise ValueError("invalid action genesis")
            else:
                if record.parent_block_hash != previous.block_hash:
                    raise ValueError("action chain parent mismatch")
                if record.pre_state_root != previous.post_state_root:
                    raise ValueError("action chain state-root discontinuity")
                if record.pre_registry_root != previous.post_registry_root:
                    raise ValueError("action chain registry-root discontinuity")

            chain.append(record)
            previous = record

        if not chain or chain[-1].block_hash != head_hash:
            raise ValueError("action HEAD does not match verified tip")

        return chain

    def recover(self) -> tuple[
        int,
        bytes,
        UnifiedState,
        ContractRegistry,
    ] | None:
        chain = self.verify_chain()
        if not chain:
            return None
        tip = chain[-1]
        return (
            tip.height,
            tip.block_hash,
            tip.final_state,
            tip.registry,
        )
