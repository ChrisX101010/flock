from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tools.action_store import ActionStore, parse_action_record
from tools.authenticated_mempool import public_key_bytes
from tools.consensus import (
    ConsensusMachine,
    STEP_PRECOMMIT,
    STEP_PREVOTE,
    Validator,
    ValidatorSet,
    Vote,
    build_qc,
    decode_vote,
    encode_qc,
    encode_vote,
    make_proposal,
    sign_vote,
    verify_proposal,
    verify_vote,
)
from tools.consensus_wire import decode_proposal, decode_qc, encode_proposal
from tools.transport import recv_frame, send_frame

P2P_DOMAIN = b"FLOCKP2P19"
ROUND_CHANGE_DOMAIN = b"FLOCKROUND19"
ROUND_CHANGE_RECORD_DOMAIN = b"FLOCKROUNDREC19"
ROUND_CHANGE_QC_DOMAIN = b"FLOCKROUNDQC19"
ROUND_CHANGE_QC_HASH_DOMAIN = b"FLOCKROUNDQCHASH19"
WAL_DOMAIN = b"FLOCKP2PWAL19"
WAL_HASH_DOMAIN = b"FLOCKP2PWALHASH19"
STATUS_REQUEST = b"FLOCKSTATUSREQ19"
STATUS_RESPONSE = b"FLOCKSTATUSRESP19"
ACK = b"FLOCKACK19"

MSG_PROPOSAL = 1
MSG_VOTE = 2
MSG_QC = 3
MSG_ROUND_CHANGE = 4
MSG_ROUND_CHANGE_QC = 5

MAX_FRAME = 4 * 1024 * 1024
HASH_LEN = 32
PUBKEY_LEN = 32
SIGNATURE_LEN = 64
ZERO_HASH = bytes(HASH_LEN)
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1


def _u32(value: int) -> bytes:
    if not 0 <= value <= U32_MAX:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    if not 0 <= value <= U64_MAX:
        raise ValueError("u64 out of range")
    return struct.pack(">Q", value)


def _blob(value: bytes) -> bytes:
    return _u32(len(value)) + value


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


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class RoundChange:
    chain_id: int
    height: int
    target_round: int
    validator_set_root: bytes
    validator_public_key: bytes
    signature: bytes


def _round_change_message(
    *,
    chain_id: int,
    height: int,
    target_round: int,
    validator_set_root: bytes,
) -> bytes:
    if len(validator_set_root) != HASH_LEN:
        raise ValueError("validator-set root must be 32 bytes")
    return b"".join(
        (
            ROUND_CHANGE_DOMAIN,
            _u32(chain_id),
            _u64(height),
            _u32(target_round),
            validator_set_root,
        )
    )


def sign_round_change(
    *,
    chain_id: int,
    height: int,
    target_round: int,
    validators: ValidatorSet,
    private_key: Ed25519PrivateKey,
) -> RoundChange:
    public_key = public_key_bytes(private_key.public_key())
    validators.power(public_key)
    message = _round_change_message(
        chain_id=chain_id,
        height=height,
        target_round=target_round,
        validator_set_root=validators.root,
    )
    return RoundChange(
        chain_id=chain_id,
        height=height,
        target_round=target_round,
        validator_set_root=validators.root,
        validator_public_key=public_key,
        signature=private_key.sign(message),
    )


def verify_round_change(change: RoundChange, validators: ValidatorSet) -> None:
    validators.power(change.validator_public_key)
    if change.validator_set_root != validators.root:
        raise ValueError("round-change validator-set root mismatch")
    if len(change.validator_public_key) != PUBKEY_LEN:
        raise ValueError("round-change public key must be 32 bytes")
    if len(change.signature) != SIGNATURE_LEN:
        raise ValueError("round-change signature must be 64 bytes")
    message = _round_change_message(
        chain_id=change.chain_id,
        height=change.height,
        target_round=change.target_round,
        validator_set_root=change.validator_set_root,
    )
    try:
        Ed25519PublicKey.from_public_bytes(change.validator_public_key).verify(
            change.signature,
            message,
        )
    except InvalidSignature as exc:
        raise ValueError("invalid round-change signature") from exc


def encode_round_change(change: RoundChange) -> bytes:
    if len(change.validator_set_root) != HASH_LEN:
        raise ValueError("round-change validator-set root must be 32 bytes")
    if len(change.validator_public_key) != PUBKEY_LEN:
        raise ValueError("round-change public key must be 32 bytes")
    if len(change.signature) != SIGNATURE_LEN:
        raise ValueError("round-change signature must be 64 bytes")
    return b"".join(
        (
            ROUND_CHANGE_RECORD_DOMAIN,
            _u32(change.chain_id),
            _u64(change.height),
            _u32(change.target_round),
            change.validator_set_root,
            change.validator_public_key,
            change.signature,
        )
    )


def decode_round_change(raw: bytes) -> RoundChange:
    expected = (
        len(ROUND_CHANGE_RECORD_DOMAIN)
        + 4 + 8 + 4 + HASH_LEN + PUBKEY_LEN + SIGNATURE_LEN
    )
    if len(raw) != expected or not raw.startswith(ROUND_CHANGE_RECORD_DOMAIN):
        raise ValueError("invalid round-change record")
    at = len(ROUND_CHANGE_RECORD_DOMAIN)
    chain_id = struct.unpack_from(">I", raw, at)[0]
    at += 4
    height = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    target_round = struct.unpack_from(">I", raw, at)[0]
    at += 4
    validator_set_root = raw[at:at + HASH_LEN]
    at += HASH_LEN
    validator_public_key = raw[at:at + PUBKEY_LEN]
    at += PUBKEY_LEN
    signature = raw[at:at + SIGNATURE_LEN]
    at += SIGNATURE_LEN
    if at != len(raw):
        raise ValueError("trailing round-change bytes")
    change = RoundChange(
        chain_id=chain_id,
        height=height,
        target_round=target_round,
        validator_set_root=validator_set_root,
        validator_public_key=validator_public_key,
        signature=signature,
    )
    if encode_round_change(change) != raw:
        raise ValueError("non-canonical round-change record")
    return change



@dataclass(frozen=True)
class RoundChangeCertificate:
    chain_id: int
    height: int
    target_round: int
    validator_set_root: bytes
    changes: tuple[RoundChange, ...]


def build_round_change_qc(
    changes: list[RoundChange] | tuple[RoundChange, ...],
    validators: ValidatorSet,
) -> RoundChangeCertificate:
    if not changes:
        raise ValueError("cannot build round-change certificate without changes")
    first = changes[0]
    expected = (
        first.chain_id,
        first.height,
        first.target_round,
        first.validator_set_root,
    )
    seen: set[bytes] = set()
    power = 0
    for change in changes:
        verify_round_change(change, validators)
        actual = (
            change.chain_id,
            change.height,
            change.target_round,
            change.validator_set_root,
        )
        if actual != expected:
            raise ValueError("round-change records do not agree on one target round")
        if change.validator_public_key in seen:
            raise ValueError("duplicate validator in round-change certificate")
        seen.add(change.validator_public_key)
        power += validators.power(change.validator_public_key)
    if power < validators.quorum_power:
        raise ValueError("insufficient voting power for round-change certificate")
    ordered = tuple(sorted(changes, key=lambda item: item.validator_public_key))
    return RoundChangeCertificate(
        chain_id=first.chain_id,
        height=first.height,
        target_round=first.target_round,
        validator_set_root=first.validator_set_root,
        changes=ordered,
    )


def verify_round_change_qc(
    certificate: RoundChangeCertificate,
    validators: ValidatorSet,
) -> None:
    rebuilt = build_round_change_qc(certificate.changes, validators)
    if rebuilt != certificate:
        raise ValueError("non-canonical round-change certificate")


def encode_round_change_qc(certificate: RoundChangeCertificate) -> bytes:
    body = bytearray(ROUND_CHANGE_QC_DOMAIN)
    body += _u32(certificate.chain_id)
    body += _u64(certificate.height)
    body += _u32(certificate.target_round)
    if len(certificate.validator_set_root) != HASH_LEN:
        raise ValueError("round-change certificate root must be 32 bytes")
    body += certificate.validator_set_root
    body += _u32(len(certificate.changes))
    for change in certificate.changes:
        body += encode_round_change(change)
    return bytes(body) + hashlib.sha256(
        ROUND_CHANGE_QC_HASH_DOMAIN + body
    ).digest()


def decode_round_change_qc(
    raw: bytes,
    validators: ValidatorSet,
) -> RoundChangeCertificate:
    fixed_change_len = (
        len(ROUND_CHANGE_RECORD_DOMAIN)
        + 4 + 8 + 4 + HASH_LEN + PUBKEY_LEN + SIGNATURE_LEN
    )
    minimum = (
        len(ROUND_CHANGE_QC_DOMAIN)
        + 4 + 8 + 4 + HASH_LEN + 4 + 32
    )
    if len(raw) < minimum or not raw.startswith(ROUND_CHANGE_QC_DOMAIN):
        raise ValueError("invalid round-change certificate")
    body, stored_hash = raw[:-32], raw[-32:]
    expected_hash = hashlib.sha256(
        ROUND_CHANGE_QC_HASH_DOMAIN + body
    ).digest()
    if stored_hash != expected_hash:
        raise ValueError("round-change certificate hash mismatch")
    at = len(ROUND_CHANGE_QC_DOMAIN)
    chain_id = struct.unpack_from(">I", body, at)[0]
    at += 4
    height = struct.unpack_from(">Q", body, at)[0]
    at += 8
    target_round = struct.unpack_from(">I", body, at)[0]
    at += 4
    validator_set_root = body[at:at + HASH_LEN]
    at += HASH_LEN
    count, at = _take_u32(body, at)
    expected_len = at + count * fixed_change_len
    if len(body) != expected_len:
        raise ValueError("wrong round-change certificate payload length")
    changes = []
    for _ in range(count):
        change_raw = body[at:at + fixed_change_len]
        at += fixed_change_len
        changes.append(decode_round_change(change_raw))
    certificate = RoundChangeCertificate(
        chain_id=chain_id,
        height=height,
        target_round=target_round,
        validator_set_root=validator_set_root,
        changes=tuple(changes),
    )
    verify_round_change_qc(certificate, validators)
    if encode_round_change_qc(certificate) != raw:
        raise ValueError("non-canonical round-change certificate")
    return certificate


def encode_message(kind: int, payload: bytes) -> bytes:
    if kind not in (
        MSG_PROPOSAL,
        MSG_VOTE,
        MSG_QC,
        MSG_ROUND_CHANGE,
        MSG_ROUND_CHANGE_QC,
    ):
        raise ValueError("unknown Phase 19 message kind")
    return P2P_DOMAIN + bytes((kind,)) + _blob(payload)


def decode_message(raw: bytes) -> tuple[int, bytes]:
    if len(raw) < len(P2P_DOMAIN) + 1 + 4 or not raw.startswith(P2P_DOMAIN):
        raise ValueError("invalid Phase 19 P2P message")
    at = len(P2P_DOMAIN)
    kind = raw[at]
    at += 1
    payload, at = _take_blob(raw, at)
    if at != len(raw):
        raise ValueError("trailing Phase 19 P2P bytes")
    if kind not in (
        MSG_PROPOSAL,
        MSG_VOTE,
        MSG_QC,
        MSG_ROUND_CHANGE,
        MSG_ROUND_CHANGE_QC,
    ):
        raise ValueError("unknown Phase 19 message kind")
    return kind, payload


def encode_proposal_payload(record_raw: bytes, proposal_raw: bytes) -> bytes:
    return _blob(record_raw) + _blob(proposal_raw)


def decode_proposal_payload(raw: bytes) -> tuple[bytes, bytes]:
    record_raw, at = _take_blob(raw, 0)
    proposal_raw, at = _take_blob(raw, at)
    if at != len(raw):
        raise ValueError("trailing proposal payload bytes")
    return record_raw, proposal_raw


@dataclass(frozen=True)
class P2PStatus:
    public_key: bytes
    current_round: int
    locked_round: int
    locked_block_hash: bytes
    finalized_block_hash: bytes | None
    proposal_rounds: tuple[int, ...]
    prevote_qc_rounds: tuple[int, ...]
    precommit_qc_rounds: tuple[int, ...]
    round_change_rounds: tuple[int, ...]


def encode_status(status: P2PStatus) -> bytes:
    if len(status.public_key) != PUBKEY_LEN:
        raise ValueError("status public key must be 32 bytes")
    body = bytearray(STATUS_RESPONSE)
    body += status.public_key
    body += _u32(status.current_round)
    body += _u32(U32_MAX if status.locked_round < 0 else status.locked_round)
    body += status.locked_block_hash
    body += bytes((1 if status.finalized_block_hash is not None else 0,))
    body += status.finalized_block_hash or ZERO_HASH
    for values in (
        status.proposal_rounds,
        status.prevote_qc_rounds,
        status.precommit_qc_rounds,
        status.round_change_rounds,
    ):
        body += _u32(len(values))
        for value in values:
            body += _u32(value)
    return bytes(body)


def decode_status(raw: bytes) -> P2PStatus:
    minimum = len(STATUS_RESPONSE) + 32 + 4 + 4 + 32 + 1 + 32 + (4 * 4)
    if len(raw) < minimum or not raw.startswith(STATUS_RESPONSE):
        raise ValueError("invalid Phase 19 status")
    at = len(STATUS_RESPONSE)
    public_key = raw[at:at + 32]
    at += 32
    current_round, at = _take_u32(raw, at)
    locked_raw, at = _take_u32(raw, at)
    locked_round = -1 if locked_raw == U32_MAX else locked_raw
    locked_block_hash = raw[at:at + 32]
    at += 32
    has_finalized = bool(raw[at])
    at += 1
    finalized_raw = raw[at:at + 32]
    at += 32
    groups = []
    for _ in range(4):
        count, at = _take_u32(raw, at)
        values = []
        for _ in range(count):
            value, at = _take_u32(raw, at)
            values.append(value)
        groups.append(tuple(values))
    if at != len(raw):
        raise ValueError("trailing Phase 19 status bytes")
    status = P2PStatus(
        public_key=public_key,
        current_round=current_round,
        locked_round=locked_round,
        locked_block_hash=locked_block_hash,
        finalized_block_hash=finalized_raw if has_finalized else None,
        proposal_rounds=groups[0],
        prevote_qc_rounds=groups[1],
        precommit_qc_rounds=groups[2],
        round_change_rounds=groups[3],
    )
    if encode_status(status) != raw:
        raise ValueError("non-canonical Phase 19 status")
    return status


def _wal_json_bytes(value: dict) -> bytes:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    body = WAL_DOMAIN + _blob(payload)
    return body + hashlib.sha256(WAL_HASH_DOMAIN + body).digest()


def _decode_wal_json(raw: bytes) -> dict:
    if len(raw) < len(WAL_DOMAIN) + 4 + 32 or not raw.startswith(WAL_DOMAIN):
        raise ValueError("invalid Phase 19 WAL")
    body, stored_hash = raw[:-32], raw[-32:]
    if hashlib.sha256(WAL_HASH_DOMAIN + body).digest() != stored_hash:
        raise ValueError("Phase 19 WAL hash mismatch")
    payload, at = _take_blob(body, len(WAL_DOMAIN))
    if at != len(body):
        raise ValueError("trailing Phase 19 WAL bytes")
    value = json.loads(payload.decode("ascii"))
    if not isinstance(value, dict):
        raise ValueError("Phase 19 WAL must contain an object")
    if _wal_json_bytes(value) != raw:
        raise ValueError("non-canonical Phase 19 WAL")
    return value


class P2PConsensusNode:
    def __init__(
        self,
        *,
        data_dir: Path,
        chain_id: int,
        height: int,
        validators: ValidatorSet,
        private_key: Ed25519PrivateKey,
        record_raw: bytes,
        peers: tuple[tuple[str, int], ...],
        round_timeout: float,
    ) -> None:
        if round_timeout <= 0:
            raise ValueError("round timeout must be positive")
        self.data_dir = data_dir
        self.chain_id = chain_id
        self.height = height
        self.validators = validators
        self.private_key = private_key
        self.public_key = public_key_bytes(private_key.public_key())
        validators.power(self.public_key)
        self.peers = peers
        self.round_timeout = round_timeout
        self.store = ActionStore(data_dir / "action-store")
        self.wal_path = data_dir / "P2P_CONSENSUS_WAL"
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.seen: set[bytes] = set()
        self.deadline = time.monotonic() + round_timeout
        self.current_round = 0
        self.proposals: dict[int, bytes] = {}
        self.local_votes: dict[tuple[int, int], bytes] = {}
        self.votes: dict[tuple[int, int, bytes], dict[bytes, bytes]] = {}
        self.prevote_qcs: dict[int, bytes] = {}
        self.precommit_qcs: dict[int, bytes] = {}
        self.round_changes: dict[int, dict[bytes, bytes]] = {}
        self.local_round_changes: dict[int, bytes] = {}

        data_dir.mkdir(parents=True, exist_ok=True)
        self.record = self._ensure_record(record_raw)
        self._restore()

    def _ensure_record(self, raw: bytes):
        record = parse_action_record(raw)
        if record.chain_id != self.chain_id or record.height != self.height:
            raise ValueError("Phase 19 action record has wrong chain/height")
        current = self.store.tip()
        if current is None:
            return self.store.append(raw)
        if current.raw != raw or current.block_hash != record.block_hash:
            raise ValueError("Phase 19 conflicting action record")
        return current

    def _wal_value(self) -> dict:
        return {
            "version": 1,
            "chain_id": self.chain_id,
            "height": self.height,
            "validator_set_root": self.validators.root.hex(),
            "public_key": self.public_key.hex(),
            "current_round": self.current_round,
            "proposals": {
                str(k): v.hex() for k, v in sorted(self.proposals.items())
            },
            "local_votes": {
                f"{round_}:{step}": raw.hex()
                for (round_, step), raw in sorted(self.local_votes.items())
            },
            "prevote_qcs": {
                str(k): v.hex() for k, v in sorted(self.prevote_qcs.items())
            },
            "precommit_qcs": {
                str(k): v.hex() for k, v in sorted(self.precommit_qcs.items())
            },
            "round_changes": {
                str(round_): {
                    key.hex(): raw.hex()
                    for key, raw in sorted(changes.items())
                }
                for round_, changes in sorted(self.round_changes.items())
            },
            "local_round_changes": {
                str(k): v.hex()
                for k, v in sorted(self.local_round_changes.items())
            },
        }

    def _persist(self) -> None:
        _atomic_write(self.wal_path, _wal_json_bytes(self._wal_value()))

    def _machine(self) -> ConsensusMachine:
        machine = ConsensusMachine(
            chain_id=self.chain_id,
            height=self.height,
            validators=self.validators,
        )
        for round_ in sorted(self.prevote_qcs):
            machine.observe_prevote_qc(
                decode_qc(self.prevote_qcs[round_], self.validators)
            )
        for round_ in sorted(self.precommit_qcs):
            machine.observe_precommit_qc(
                decode_qc(self.precommit_qcs[round_], self.validators)
            )
        return machine

    def _restore(self) -> None:
        if not self.wal_path.exists():
            return
        value = _decode_wal_json(self.wal_path.read_bytes())
        if value.get("version") != 1:
            raise ValueError("unsupported Phase 19 WAL version")
        if value.get("chain_id") != self.chain_id or value.get("height") != self.height:
            raise ValueError("Phase 19 WAL belongs to another consensus instance")
        if value.get("validator_set_root") != self.validators.root.hex():
            raise ValueError("Phase 19 WAL validator-set mismatch")
        if value.get("public_key") != self.public_key.hex():
            raise ValueError("Phase 19 WAL belongs to another validator")

        self.current_round = int(value.get("current_round", 0))

        for key, raw_hex in value.get("proposals", {}).items():
            round_ = int(key)
            raw = bytes.fromhex(raw_hex)
            proposal = decode_proposal(raw)
            verify_proposal(proposal, self.record, self.validators)
            if proposal.round != round_:
                raise ValueError("persisted proposal round mismatch")
            self.proposals[round_] = raw

        for key, raw_hex in value.get("local_votes", {}).items():
            round_text, step_text = key.split(":", 1)
            round_, step = int(round_text), int(step_text)
            raw = bytes.fromhex(raw_hex)
            vote = decode_vote(raw)
            verify_vote(vote, self.validators)
            if (
                vote.chain_id != self.chain_id
                or vote.height != self.height
                or vote.round != round_
                or vote.step != step
                or vote.validator_public_key != self.public_key
            ):
                raise ValueError("persisted local vote mismatch")
            self.local_votes[(round_, step)] = raw
            self._remember_vote(raw)

        for key, raw_hex in value.get("prevote_qcs", {}).items():
            round_ = int(key)
            raw = bytes.fromhex(raw_hex)
            qc = decode_qc(raw, self.validators)
            if qc.round != round_ or qc.step != STEP_PREVOTE:
                raise ValueError("persisted PREVOTE QC mismatch")
            self.prevote_qcs[round_] = raw
            for vote in qc.votes:
                self._remember_vote(encode_vote(vote))

        for key, raw_hex in value.get("precommit_qcs", {}).items():
            round_ = int(key)
            raw = bytes.fromhex(raw_hex)
            qc = decode_qc(raw, self.validators)
            if qc.round != round_ or qc.step != STEP_PRECOMMIT:
                raise ValueError("persisted PRECOMMIT QC mismatch")
            self.precommit_qcs[round_] = raw
            for vote in qc.votes:
                self._remember_vote(encode_vote(vote))

        for key, entries in value.get("round_changes", {}).items():
            target = int(key)
            bucket: dict[bytes, bytes] = {}
            for pub_hex, raw_hex in entries.items():
                raw = bytes.fromhex(raw_hex)
                change = decode_round_change(raw)
                verify_round_change(change, self.validators)
                if (
                    change.chain_id != self.chain_id
                    or change.height != self.height
                    or change.target_round != target
                    or change.validator_public_key.hex() != pub_hex
                ):
                    raise ValueError("persisted round-change mismatch")
                bucket[change.validator_public_key] = raw
            self.round_changes[target] = bucket

        for key, raw_hex in value.get("local_round_changes", {}).items():
            target = int(key)
            raw = bytes.fromhex(raw_hex)
            change = decode_round_change(raw)
            verify_round_change(change, self.validators)
            if (
                change.target_round != target
                or change.validator_public_key != self.public_key
            ):
                raise ValueError("persisted local round-change mismatch")
            self.local_round_changes[target] = raw

        machine = self._machine()
        if machine.finalized_block_hash is not None:
            machine.verify_finalized_record(self.record)

    def _remember_vote(self, raw: bytes) -> Vote:
        vote = decode_vote(raw)
        verify_vote(vote, self.validators)
        if vote.chain_id != self.chain_id or vote.height != self.height:
            raise ValueError("vote belongs to another consensus instance")
        key = (vote.round, vote.step, vote.block_hash)
        bucket = self.votes.setdefault(key, {})
        existing = bucket.get(vote.validator_public_key)
        if existing is not None and existing != raw:
            raise ValueError("validator equivocation detected")
        bucket[vote.validator_public_key] = raw
        return vote

    def status(self) -> P2PStatus:
        with self.lock:
            machine = self._machine()
            return P2PStatus(
                public_key=self.public_key,
                current_round=self.current_round,
                locked_round=machine.locked_round,
                locked_block_hash=machine.locked_block_hash,
                finalized_block_hash=machine.finalized_block_hash,
                proposal_rounds=tuple(sorted(self.proposals)),
                prevote_qc_rounds=tuple(sorted(self.prevote_qcs)),
                precommit_qc_rounds=tuple(sorted(self.precommit_qcs)),
                round_change_rounds=tuple(sorted(self.round_changes)),
            )

    def _broadcast(self, messages: list[bytes]) -> None:
        for message in messages:
            for host, port in self.peers:
                try:
                    with socket.create_connection((host, port), timeout=0.25) as sock:
                        sock.settimeout(0.5)
                        send_frame(sock, message, max_payload=MAX_FRAME)
                        ack = recv_frame(sock, max_payload=1024)
                        if ack != ACK:
                            raise ValueError("peer returned invalid Phase 19 ACK")
                except (OSError, EOFError, TimeoutError):
                    continue

    def _local_vote(self, round_: int, step: int, block_hash: bytes) -> bytes:
        key = (round_, step)
        existing = self.local_votes.get(key)
        if existing is not None:
            vote = decode_vote(existing)
            if vote.block_hash != block_hash:
                raise ValueError("refusing local validator equivocation")
            return existing
        vote = sign_vote(
            chain_id=self.chain_id,
            height=self.height,
            round_=round_,
            step=step,
            block_hash=block_hash,
            validators=self.validators,
            private_key=self.private_key,
        )
        raw = encode_vote(vote)
        self.local_votes[key] = raw
        self._remember_vote(raw)
        return raw

    def _maybe_build_qc(
        self,
        *,
        round_: int,
        step: int,
        block_hash: bytes,
    ) -> bytes | None:
        bucket = self.votes.get((round_, step, block_hash), {})
        votes = [decode_vote(raw) for raw in bucket.values()]
        power = sum(
            self.validators.power(vote.validator_public_key)
            for vote in votes
        )
        if power < self.validators.quorum_power:
            return None
        qc = build_qc(votes, self.validators)
        return encode_qc(qc)

    def _proposal_for_round(self, round_: int) -> bytes:
        existing = self.proposals.get(round_)
        if existing is not None:
            proposal = decode_proposal(existing)
            if proposal.block_hash != self.record.block_hash:
                raise ValueError("persisted proposal targets another block")
            return existing
        expected = self.validators.proposer(self.height, round_)
        if expected.public_key != self.public_key:
            raise ValueError("local validator is not scheduled proposer")
        proposal = make_proposal(
            self.record,
            round_=round_,
            validators=self.validators,
            private_key=self.private_key,
        )
        raw = encode_proposal(proposal)
        self.proposals[round_] = raw
        return raw

    def _enter_round(self, round_: int) -> list[bytes]:
        if round_ < self.current_round:
            return []
        self.current_round = round_
        self.deadline = time.monotonic() + self.round_timeout
        outgoing: list[bytes] = []
        expected = self.validators.proposer(self.height, round_)
        if expected.public_key == self.public_key:
            proposal_raw = self._proposal_for_round(round_)
            # The proposer is also a validator. Its own PREVOTE must count
            # toward quorum; otherwise a 3/4 live set with one failed node can
            # never make progress because only the two follower votes exist.
            prevote_raw = self._local_vote(
                round_,
                STEP_PREVOTE,
                self.record.block_hash,
            )
            outgoing.append(
                encode_message(
                    MSG_PROPOSAL,
                    encode_proposal_payload(self.record.raw, proposal_raw),
                )
            )
            outgoing.append(
                encode_message(
                    MSG_VOTE,
                    prevote_raw,
                )
            )
        self._persist()
        return outgoing

    def _process_proposal(self, payload: bytes) -> list[bytes]:
        record_raw, proposal_raw = decode_proposal_payload(payload)
        record = parse_action_record(record_raw)
        if record.raw != self.record.raw:
            raise ValueError("peer proposal carries another action record")
        proposal = decode_proposal(proposal_raw)
        verify_proposal(proposal, self.record, self.validators)
        if proposal.round < self.current_round:
            return []
        if proposal.round > self.current_round:
            # A proposal cannot by itself skip the authenticated round-change gate.
            return []
        existing = self.proposals.get(proposal.round)
        if existing is not None and existing != proposal_raw:
            raise ValueError("conflicting proposal for same round")
        self.proposals[proposal.round] = proposal_raw
        vote_raw = self._local_vote(
            proposal.round,
            STEP_PREVOTE,
            proposal.block_hash,
        )
        self.deadline = time.monotonic() + self.round_timeout
        self._persist()
        return [encode_message(MSG_VOTE, vote_raw)]

    def _process_vote(self, payload: bytes) -> list[bytes]:
        vote = self._remember_vote(payload)
        if vote.round != self.current_round:
            return []
        if vote.block_hash != self.record.block_hash:
            raise ValueError("vote targets another action block")
        outgoing: list[bytes] = []
        qc_raw = self._maybe_build_qc(
            round_=vote.round,
            step=vote.step,
            block_hash=vote.block_hash,
        )
        if qc_raw is None:
            return outgoing

        if vote.step == STEP_PREVOTE:
            existing = self.prevote_qcs.get(vote.round)
            if existing is not None and existing != qc_raw:
                # Different canonical signer subsets can both prove the same quorum.
                # Preserve the first valid QC; safety depends on decision identity,
                # not byte equality between independently aggregated certificates.
                return []
            if existing is None:
                qc = decode_qc(qc_raw, self.validators)
                self._machine().observe_prevote_qc(qc)
                self.prevote_qcs[vote.round] = qc_raw
                precommit_raw = self._local_vote(
                    vote.round,
                    STEP_PRECOMMIT,
                    vote.block_hash,
                )
                self._persist()
                outgoing.append(encode_message(MSG_QC, qc_raw))
                outgoing.append(encode_message(MSG_VOTE, precommit_raw))
        elif vote.step == STEP_PRECOMMIT:
            existing = self.precommit_qcs.get(vote.round)
            if existing is None:
                if vote.round not in self.prevote_qcs:
                    return []
                machine = self._machine()
                qc = decode_qc(qc_raw, self.validators)
                finalized = machine.observe_precommit_qc(qc)
                if finalized != self.record.block_hash:
                    raise ValueError("PRECOMMIT QC finalizes another block")
                machine.verify_finalized_record(self.record)
                self.precommit_qcs[vote.round] = qc_raw
                self._persist()
                outgoing.append(encode_message(MSG_QC, qc_raw))
        return outgoing

    def _process_qc(self, payload: bytes) -> list[bytes]:
        qc = decode_qc(payload, self.validators)
        if (
            qc.chain_id != self.chain_id
            or qc.height != self.height
            or qc.block_hash != self.record.block_hash
        ):
            raise ValueError("QC belongs to another consensus decision")
        for vote in qc.votes:
            self._remember_vote(encode_vote(vote))
        outgoing: list[bytes] = []

        if qc.step == STEP_PREVOTE:
            existing = self.prevote_qcs.get(qc.round)
            if existing is None:
                machine = self._machine()
                machine.observe_prevote_qc(qc)
                self.prevote_qcs[qc.round] = payload
                if qc.round >= self.current_round:
                    self.current_round = qc.round
                    precommit_raw = self._local_vote(
                        qc.round,
                        STEP_PRECOMMIT,
                        qc.block_hash,
                    )
                    outgoing.append(encode_message(MSG_VOTE, precommit_raw))
                self._persist()
        elif qc.step == STEP_PRECOMMIT:
            if qc.round not in self.prevote_qcs:
                return []
            existing = self.precommit_qcs.get(qc.round)
            if existing is None:
                machine = self._machine()
                finalized = machine.observe_precommit_qc(qc)
                if finalized != self.record.block_hash:
                    raise ValueError("QC finalizes another block")
                machine.verify_finalized_record(self.record)
                self.precommit_qcs[qc.round] = payload
                self._persist()
        return outgoing

    def _round_change_power(self, target_round: int) -> int:
        return sum(
            self.validators.power(public_key)
            for public_key in self.round_changes.get(target_round, {})
        )

    def _local_round_change(self, target_round: int) -> bytes:
        existing = self.local_round_changes.get(target_round)
        if existing is not None:
            return existing
        change = sign_round_change(
            chain_id=self.chain_id,
            height=self.height,
            target_round=target_round,
            validators=self.validators,
            private_key=self.private_key,
        )
        raw = encode_round_change(change)
        self.local_round_changes[target_round] = raw
        self.round_changes.setdefault(target_round, {})[self.public_key] = raw
        return raw

    def _process_round_change(self, payload: bytes) -> list[bytes]:
        change = decode_round_change(payload)
        verify_round_change(change, self.validators)
        if change.chain_id != self.chain_id or change.height != self.height:
            raise ValueError("round-change belongs to another consensus instance")
        if change.target_round <= self.current_round:
            return []
        bucket = self.round_changes.setdefault(change.target_round, {})
        existing = bucket.get(change.validator_public_key)
        if existing is not None and existing != payload:
            raise ValueError("validator sent conflicting round-change")
        bucket[change.validator_public_key] = payload
        outgoing: list[bytes] = []
        if self._round_change_power(change.target_round) >= self.validators.quorum_power:
            certificate = build_round_change_qc(
                [decode_round_change(raw) for raw in bucket.values()],
                self.validators,
            )
            certificate_raw = encode_round_change_qc(certificate)
            # Broadcast the authenticated round-change proof before any proposal
            # for the new round. Peers therefore advance independently instead
            # of trusting a future-round proposal as implicit round evidence.
            outgoing.append(
                encode_message(MSG_ROUND_CHANGE_QC, certificate_raw)
            )
            outgoing.extend(self._enter_round(change.target_round))
        else:
            self._persist()
        return outgoing

    def _process_round_change_qc(self, payload: bytes) -> list[bytes]:
        certificate = decode_round_change_qc(payload, self.validators)
        if (
            certificate.chain_id != self.chain_id
            or certificate.height != self.height
        ):
            raise ValueError(
                "round-change certificate belongs to another consensus instance"
            )
        if certificate.target_round <= self.current_round:
            return []
        bucket = self.round_changes.setdefault(
            certificate.target_round,
            {},
        )
        for change in certificate.changes:
            raw = encode_round_change(change)
            existing = bucket.get(change.validator_public_key)
            if existing is not None and existing != raw:
                raise ValueError(
                    "round-change certificate conflicts with persisted evidence"
                )
            bucket[change.validator_public_key] = raw
        return self._enter_round(certificate.target_round)

    def process_message(self, raw: bytes) -> None:
        digest = hashlib.sha256(raw).digest()
        with self.lock:
            if digest in self.seen:
                return
            self.seen.add(digest)
            kind, payload = decode_message(raw)
            machine = self._machine()
            if machine.finalized_block_hash is not None:
                return
            if kind == MSG_PROPOSAL:
                outgoing = self._process_proposal(payload)
            elif kind == MSG_VOTE:
                outgoing = self._process_vote(payload)
            elif kind == MSG_QC:
                outgoing = self._process_qc(payload)
            elif kind == MSG_ROUND_CHANGE:
                outgoing = self._process_round_change(payload)
            elif kind == MSG_ROUND_CHANGE_QC:
                outgoing = self._process_round_change_qc(payload)
            else:
                raise ValueError("unknown Phase 19 P2P message")
        self._broadcast(outgoing)

    def start(self) -> None:
        outgoing: list[bytes]
        with self.lock:
            if self._machine().finalized_block_hash is not None:
                return
            outgoing = self._enter_round(self.current_round)
        self._broadcast(outgoing)

    def pacemaker_loop(self) -> None:
        while not self.stop_event.wait(0.02):
            outgoing: list[bytes] = []
            with self.lock:
                if self._machine().finalized_block_hash is not None:
                    continue
                if time.monotonic() < self.deadline:
                    continue
                target = self.current_round + 1
                change_raw = self._local_round_change(target)
                self.deadline = time.monotonic() + self.round_timeout
                self._persist()
                outgoing.append(encode_message(MSG_ROUND_CHANGE, change_raw))
            self._broadcast(outgoing)


class P2PServer:
    def __init__(self, node: P2PConsensusNode, host: str, port: int) -> None:
        self.node = node
        self.host = host
        self.port = port
        self.server_socket: socket.socket | None = None

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            self.server_socket = server
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(64)
            server.settimeout(0.2)
            print(f"FLOCK_P2P19_LISTEN={self.host}:{self.port}", flush=True)
            while not self.node.stop_event.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                )
                thread.start()

    def _handle_connection(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(2.0)
            try:
                raw = recv_frame(conn, max_payload=MAX_FRAME)
                if raw == STATUS_REQUEST:
                    response = encode_status(self.node.status())
                else:
                    self.node.process_message(raw)
                    response = ACK
            except Exception as exc:
                response = (
                    b"FLOCKERR19"
                    + _blob(f"{type(exc).__name__}: {exc}".encode("utf-8")[:8192])
                )
            send_frame(conn, response, max_payload=MAX_FRAME)


def status_call(host: str, port: int, timeout: float = 1.0) -> P2PStatus:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        send_frame(sock, STATUS_REQUEST, max_payload=MAX_FRAME)
        response = recv_frame(sock, max_payload=MAX_FRAME)
    if response.startswith(b"FLOCKERR19"):
        msg, _ = _take_blob(response, len(b"FLOCKERR19"))
        raise RuntimeError(msg.decode("utf-8", "replace"))
    return decode_status(response)


def _parse_validator(value: str) -> Validator:
    key_hex, sep, power_text = value.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError("validator must be PUBKEY_HEX:POWER")
    try:
        return Validator(bytes.fromhex(key_hex), int(power_text))
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parse_peer(value: str) -> tuple[str, int]:
    host, sep, port_text = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError("peer must be HOST:PORT")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("peer port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("peer port out of range")
    return host, port


def main() -> None:
    parser = argparse.ArgumentParser(description="Flock Phase 19 P2P consensus node")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--chain-id", type=int, required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--record-file", type=Path, required=True)
    parser.add_argument("--round-timeout", type=float, default=0.5)
    parser.add_argument("--validator", action="append", type=_parse_validator, required=True)
    parser.add_argument("--peer", action="append", type=_parse_peer, default=[])
    args = parser.parse_args()

    key_hex = os.environ.get("FLOCK_DEVNET_KEY_HEX")
    if key_hex is None:
        raise SystemExit("FLOCK_DEVNET_KEY_HEX is required")
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
    validators = ValidatorSet(args.validator)
    node = P2PConsensusNode(
        data_dir=args.data_dir,
        chain_id=args.chain_id,
        height=args.height,
        validators=validators,
        private_key=private_key,
        record_raw=args.record_file.read_bytes(),
        peers=tuple(args.peer),
        round_timeout=args.round_timeout,
    )
    server = P2PServer(node, args.host, args.port)
    pacemaker = threading.Thread(target=node.pacemaker_loop, daemon=True)
    pacemaker.start()
    try:
        # Listening begins before initial proposal broadcast so peers can answer.
        starter = threading.Thread(
            target=lambda: (time.sleep(0.1), node.start()),
            daemon=True,
        )
        starter.start()
        server.serve_forever()
    finally:
        node.stop_event.set()
        pacemaker.join(timeout=1.0)


if __name__ == "__main__":
    main()
