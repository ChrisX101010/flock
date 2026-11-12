from __future__ import annotations

from dataclasses import dataclass, replace
import argparse
import hashlib
import os
from pathlib import Path
import socket
import struct
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.action_store import ActionStore, parse_action_record
from tools.authenticated_mempool import public_key_bytes
from tools.consensus import (
    ConsensusMachine,
    STEP_PRECOMMIT,
    STEP_PREVOTE,
    Validator,
    ValidatorSet,
    decode_vote,
    encode_vote,
    make_proposal,
    sign_vote,
    verify_proposal,
    verify_vote,
)
from tools.consensus_wire import decode_proposal, decode_qc, encode_proposal
from tools.transport import recv_frame, send_frame

RPC_REQUEST_DOMAIN = b"FLOCKRPCREQ1"
RPC_RESPONSE_DOMAIN = b"FLOCKRPCRESP1"
WAL_DOMAIN = b"FLOCKCONSWAL1"
WAL_HASH_DOMAIN = b"FLOCKCONSWALHASH1"
STATUS_DOMAIN = b"FLOCKSTATUS1"
MAX_RPC_PAYLOAD = 4 * 1024 * 1024
ZERO_HASH = bytes(32)
LOCK_NONE = 0xFFFFFFFF

REQ_STATUS = 1
REQ_MAKE_PROPOSAL = 2
REQ_PREVOTE = 3
REQ_PREVOTE_QC = 4
REQ_PRECOMMIT_QC = 5
REQ_CATCH_UP = 6

RESP_STATUS = 101
RESP_PROPOSAL = 102
RESP_VOTE = 103
RESP_ACK = 104


def _u32(value: int) -> bytes:
    if not 0 <= value <= (1 << 32) - 1:
        raise ValueError("u32 out of range")
    return struct.pack(">I", value)


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


@dataclass(frozen=True)
class WalState:
    proposal: bytes = b""
    signed_prevote: bytes = b""
    prevote_qc: bytes = b""
    signed_precommit: bytes = b""
    precommit_qc: bytes = b""


@dataclass(frozen=True)
class NodeStatus:
    public_key: bytes
    has_record: bool
    tip_hash: bytes
    signed_prevote: bool
    signed_precommit: bool
    locked_round: int
    locked_block_hash: bytes
    finalized_block_hash: bytes | None


def encode_wal(state: WalState) -> bytes:
    body = bytearray(WAL_DOMAIN)
    for value in (
        state.proposal,
        state.signed_prevote,
        state.prevote_qc,
        state.signed_precommit,
        state.precommit_qc,
    ):
        body += _blob(value)
    return bytes(body) + hashlib.sha256(WAL_HASH_DOMAIN + body).digest()


def decode_wal(raw: bytes) -> WalState:
    if len(raw) < len(WAL_DOMAIN) + 32 or not raw.startswith(WAL_DOMAIN):
        raise ValueError("invalid consensus WAL")
    body, stored = raw[:-32], raw[-32:]
    if hashlib.sha256(WAL_HASH_DOMAIN + body).digest() != stored:
        raise ValueError("consensus WAL hash mismatch")
    at = len(WAL_DOMAIN)
    values = []
    for _ in range(5):
        value, at = _take_blob(body, at)
        values.append(value)
    if at != len(body):
        raise ValueError("trailing consensus WAL bytes")
    state = WalState(*values)
    if encode_wal(state) != raw:
        raise ValueError("non-canonical consensus WAL")
    return state


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        _fsync_dir(path.parent)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def encode_status(status: NodeStatus) -> bytes:
    if len(status.public_key) != 32:
        raise ValueError("status public key must be 32 bytes")
    finalized = status.finalized_block_hash or ZERO_HASH
    locked = LOCK_NONE if status.locked_round < 0 else status.locked_round
    return b"".join(
        (
            STATUS_DOMAIN,
            status.public_key,
            bytes((1 if status.has_record else 0,)),
            status.tip_hash,
            bytes((1 if status.signed_prevote else 0,)),
            bytes((1 if status.signed_precommit else 0,)),
            _u32(locked),
            status.locked_block_hash,
            bytes((1 if status.finalized_block_hash is not None else 0,)),
            finalized,
        )
    )


def decode_status(raw: bytes) -> NodeStatus:
    expected = len(STATUS_DOMAIN) + 32 + 1 + 32 + 1 + 1 + 4 + 32 + 1 + 32
    if len(raw) != expected or not raw.startswith(STATUS_DOMAIN):
        raise ValueError("invalid status record")
    at = len(STATUS_DOMAIN)
    public_key = raw[at:at + 32]
    at += 32
    has_record = bool(raw[at]); at += 1
    tip_hash = raw[at:at + 32]; at += 32
    signed_prevote = bool(raw[at]); at += 1
    signed_precommit = bool(raw[at]); at += 1
    locked_u32 = struct.unpack_from(">I", raw, at)[0]; at += 4
    locked_round = -1 if locked_u32 == LOCK_NONE else locked_u32
    locked_hash = raw[at:at + 32]; at += 32
    has_finalized = bool(raw[at]); at += 1
    finalized = raw[at:at + 32]; at += 32
    if at != len(raw):
        raise ValueError("trailing status bytes")
    status = NodeStatus(
        public_key=public_key,
        has_record=has_record,
        tip_hash=tip_hash,
        signed_prevote=signed_prevote,
        signed_precommit=signed_precommit,
        locked_round=locked_round,
        locked_block_hash=locked_hash,
        finalized_block_hash=finalized if has_finalized else None,
    )
    if encode_status(status) != raw:
        raise ValueError("non-canonical status record")
    return status


def encode_request(kind: int, body: bytes = b"") -> bytes:
    return RPC_REQUEST_DOMAIN + bytes((kind,)) + body


def decode_request(raw: bytes) -> tuple[int, bytes]:
    if len(raw) < len(RPC_REQUEST_DOMAIN) + 1 or not raw.startswith(RPC_REQUEST_DOMAIN):
        raise ValueError("invalid RPC request")
    at = len(RPC_REQUEST_DOMAIN)
    return raw[at], raw[at + 1:]


def encode_response(kind: int, body: bytes = b"", error: str | None = None) -> bytes:
    if error is not None:
        return RPC_RESPONSE_DOMAIN + b"\x01" + bytes((kind,)) + _blob(error.encode()[:8192])
    return RPC_RESPONSE_DOMAIN + b"\x00" + bytes((kind,)) + body


def decode_response(raw: bytes) -> tuple[int, bytes]:
    if len(raw) < len(RPC_RESPONSE_DOMAIN) + 2 or not raw.startswith(RPC_RESPONSE_DOMAIN):
        raise ValueError("invalid RPC response")
    at = len(RPC_RESPONSE_DOMAIN)
    is_error = raw[at]
    kind = raw[at + 1]
    body = raw[at + 2:]
    if is_error:
        msg, end = _take_blob(body, 0)
        if end != len(body):
            raise ValueError("trailing RPC error bytes")
        raise RuntimeError(msg.decode("utf-8", "replace"))
    return kind, body


def rpc_call(host: str, port: int, request: bytes, timeout: float = 2.0) -> tuple[int, bytes]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        send_frame(sock, request, max_payload=MAX_RPC_PAYLOAD)
        response = recv_frame(sock, max_payload=MAX_RPC_PAYLOAD)
    return decode_response(response)


class DevnetNode:
    def __init__(self, data_dir: Path, chain_id: int, height: int,
                 validators: ValidatorSet, private_key: Ed25519PrivateKey):
        self.data_dir = data_dir
        self.chain_id = chain_id
        self.height = height
        self.validators = validators
        self.private_key = private_key
        self.public_key = public_key_bytes(private_key.public_key())
        self.validators.power(self.public_key)
        self.store = ActionStore(data_dir / "action-store")
        self.wal_path = data_dir / "CONSENSUS_WAL"
        data_dir.mkdir(parents=True, exist_ok=True)
        self._validate_wal(self._load_wal())

    def _load_wal(self) -> WalState:
        return decode_wal(self.wal_path.read_bytes()) if self.wal_path.exists() else WalState()

    def _save_wal(self, state: WalState) -> None:
        self._validate_wal(state)
        _atomic_write(self.wal_path, encode_wal(state))

    def _record(self):
        tip = self.store.tip()
        if tip is not None and (tip.chain_id != self.chain_id or tip.height != self.height):
            raise ValueError("local action record belongs to another consensus instance")
        return tip

    def _ensure_record(self, raw: bytes):
        record = parse_action_record(raw)
        if record.chain_id != self.chain_id or record.height != self.height:
            raise ValueError("action record has wrong chain/height")
        current = self._record()
        if current is None:
            return self.store.append(raw)
        if current.block_hash != record.block_hash or current.raw != raw:
            raise ValueError("conflicting action record")
        return current

    def _validate_local_vote(self, raw: bytes, step: int) -> None:
        vote = decode_vote(raw)
        verify_vote(vote, self.validators)
        if vote.chain_id != self.chain_id or vote.height != self.height:
            raise ValueError("persisted vote has wrong chain/height")
        if vote.validator_public_key != self.public_key or vote.step != step:
            raise ValueError("persisted vote identity/step mismatch")

    def _machine(self, state: WalState):
        machine = ConsensusMachine(
            chain_id=self.chain_id, height=self.height, validators=self.validators
        )
        if state.prevote_qc:
            machine.observe_prevote_qc(decode_qc(state.prevote_qc, self.validators))
        if state.precommit_qc:
            machine.observe_precommit_qc(decode_qc(state.precommit_qc, self.validators))
        return machine

    def _validate_wal(self, state: WalState) -> None:
        record = self._record()
        if state.proposal:
            proposal = decode_proposal(state.proposal)
            if proposal.chain_id != self.chain_id or proposal.height != self.height:
                raise ValueError("persisted proposal has wrong chain/height")
            if proposal.validator_set_root != self.validators.root:
                raise ValueError("persisted proposal has wrong validator set")
            # Followers may persist the scheduled proposer's proposal during
            # voting or catch-up. Local ownership is not a WAL invariant;
            # verify_proposal() authenticates the scheduled proposer instead.
            if record is not None:
                verify_proposal(proposal, record, self.validators)
        if state.signed_prevote:
            self._validate_local_vote(state.signed_prevote, STEP_PREVOTE)
        if state.signed_precommit:
            self._validate_local_vote(state.signed_precommit, STEP_PRECOMMIT)
        machine = self._machine(state)
        if machine.finalized_block_hash is not None:
            if record is None or machine.finalized_block_hash != record.block_hash:
                raise ValueError("persisted finality does not match action record")
            machine.verify_finalized_record(record)

    def status(self) -> NodeStatus:
        state = self._load_wal()
        machine = self._machine(state)
        record = self._record()
        return NodeStatus(
            self.public_key,
            record is not None,
            record.block_hash if record is not None else ZERO_HASH,
            bool(state.signed_prevote),
            bool(state.signed_precommit),
            machine.locked_round,
            machine.locked_block_hash,
            machine.finalized_block_hash,
        )

    def make_proposal(self, record_raw: bytes, round_: int) -> bytes:
        record = self._ensure_record(record_raw)
        expected = self.validators.proposer(record.height, round_)
        if expected.public_key != self.public_key:
            raise ValueError("local validator is not the scheduled proposer")
        state = self._load_wal()
        if state.proposal:
            proposal = decode_proposal(state.proposal)
            if proposal.round != round_ or proposal.block_hash != record.block_hash:
                raise ValueError("refusing proposer equivocation")
            return state.proposal
        proposal = make_proposal(
            record, round_=round_, validators=self.validators, private_key=self.private_key
        )
        raw = encode_proposal(proposal)
        self._save_wal(replace(state, proposal=raw))
        return raw

    def _sign_once(self, state: WalState, step: int, block_hash: bytes, round_: int):
        field = "signed_prevote" if step == STEP_PREVOTE else "signed_precommit"
        existing_raw = getattr(state, field)
        if existing_raw:
            vote = decode_vote(existing_raw)
            self._validate_local_vote(existing_raw, step)
            if vote.round != round_ or vote.block_hash != block_hash:
                raise ValueError("refusing validator equivocation")
            return state, existing_raw
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
        new_state = replace(state, **{field: raw})
        self._save_wal(new_state)
        return new_state, raw

    def prevote(self, record_raw: bytes, proposal_raw: bytes) -> bytes:
        record = self._ensure_record(record_raw)
        proposal = decode_proposal(proposal_raw)
        verify_proposal(proposal, record, self.validators)
        _, raw = self._sign_once(
            self._load_wal(), STEP_PREVOTE, record.block_hash, proposal.round
        )
        return raw

    def observe_prevote_qc(self, qc_raw: bytes) -> bytes:
        record = self._record()
        if record is None:
            raise ValueError("prevote QC requires action record")
        qc = decode_qc(qc_raw, self.validators)
        if qc.block_hash != record.block_hash:
            raise ValueError("prevote QC targets another block")
        state = self._load_wal()
        self._machine(state).observe_prevote_qc(qc)
        if state.prevote_qc and state.prevote_qc != qc_raw:
            raise ValueError("conflicting prevote QC")
        state = replace(state, prevote_qc=qc_raw)
        self._save_wal(state)
        _, raw = self._sign_once(state, STEP_PRECOMMIT, qc.block_hash, qc.round)
        return raw

    def observe_precommit_qc(self, qc_raw: bytes) -> NodeStatus:
        record = self._record()
        if record is None:
            raise ValueError("finality requires action record")
        state = self._load_wal()
        if not state.prevote_qc:
            raise ValueError("finality requires persisted prevote QC")
        if state.precommit_qc:
            if state.precommit_qc != qc_raw:
                raise ValueError("conflicting precommit QC")
            return self.status()
        machine = self._machine(state)
        qc = decode_qc(qc_raw, self.validators)
        finalized = machine.observe_precommit_qc(qc)
        if finalized != record.block_hash:
            raise ValueError("finality targets another block")
        machine.verify_finalized_record(record)
        self._save_wal(replace(state, precommit_qc=qc_raw))
        return self.status()

    def catch_up(self, record_raw: bytes, proposal_raw: bytes,
                 prevote_qc_raw: bytes, precommit_qc_raw: bytes) -> NodeStatus:
        record = self._ensure_record(record_raw)
        proposal = decode_proposal(proposal_raw)
        verify_proposal(proposal, record, self.validators)
        prevote_qc = decode_qc(prevote_qc_raw, self.validators)
        precommit_qc = decode_qc(precommit_qc_raw, self.validators)
        machine = ConsensusMachine(
            chain_id=self.chain_id, height=self.height, validators=self.validators
        )
        machine.observe_prevote_qc(prevote_qc)
        if machine.observe_precommit_qc(precommit_qc) != record.block_hash:
            raise ValueError("catch-up finality mismatch")
        machine.verify_finalized_record(record)
        state = self._load_wal()
        for old, new, label in (
            (state.proposal, proposal_raw, "proposal"),
            (state.prevote_qc, prevote_qc_raw, "prevote QC"),
            (state.precommit_qc, precommit_qc_raw, "precommit QC"),
        ):
            if old and old != new:
                raise ValueError(f"catch-up conflicts with persisted {label}")
        self._save_wal(replace(
            state,
            proposal=proposal_raw,
            prevote_qc=prevote_qc_raw,
            precommit_qc=precommit_qc_raw,
        ))
        return self.status()

    def handle(self, raw: bytes) -> tuple[int, bytes]:
        kind, body = decode_request(raw)
        if kind == REQ_STATUS:
            if body:
                raise ValueError("STATUS body must be empty")
            return RESP_STATUS, encode_status(self.status())
        if kind == REQ_MAKE_PROPOSAL:
            record, at = _take_blob(body, 0)
            round_, at = _take_u32(body, at)
            if at != len(body):
                raise ValueError("trailing MAKE_PROPOSAL bytes")
            return RESP_PROPOSAL, self.make_proposal(record, round_)
        if kind == REQ_PREVOTE:
            record, at = _take_blob(body, 0)
            proposal, at = _take_blob(body, at)
            if at != len(body):
                raise ValueError("trailing PREVOTE bytes")
            return RESP_VOTE, self.prevote(record, proposal)
        if kind == REQ_PREVOTE_QC:
            qc, at = _take_blob(body, 0)
            if at != len(body):
                raise ValueError("trailing PREVOTE_QC bytes")
            return RESP_VOTE, self.observe_prevote_qc(qc)
        if kind == REQ_PRECOMMIT_QC:
            qc, at = _take_blob(body, 0)
            if at != len(body):
                raise ValueError("trailing PRECOMMIT_QC bytes")
            return RESP_STATUS, encode_status(self.observe_precommit_qc(qc))
        if kind == REQ_CATCH_UP:
            record, at = _take_blob(body, 0)
            proposal, at = _take_blob(body, at)
            prevote_qc, at = _take_blob(body, at)
            precommit_qc, at = _take_blob(body, at)
            if at != len(body):
                raise ValueError("trailing CATCH_UP bytes")
            return RESP_STATUS, encode_status(
                self.catch_up(record, proposal, prevote_qc, precommit_qc)
            )
        raise ValueError("unknown RPC kind")


def serve(node: DevnetNode, host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(32)
        print(f"FLOCK_DEVNET_LISTEN={host}:{port}", flush=True)
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(5.0)
                try:
                    req = recv_frame(conn, max_payload=MAX_RPC_PAYLOAD)
                    kind, body = node.handle(req)
                    resp = encode_response(kind, body)
                except Exception as exc:
                    resp = encode_response(RESP_ACK, error=f"{type(exc).__name__}: {exc}")
                send_frame(conn, resp, max_payload=MAX_RPC_PAYLOAD)


def _parse_validator(value: str) -> Validator:
    key_hex, sep, power_text = value.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError("validator must be PUBKEY_HEX:POWER")
    try:
        return Validator(bytes.fromhex(key_hex), int(power_text))
    except Exception as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("serve",))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--chain-id", type=int, required=True)
    parser.add_argument("--height", type=int, required=True)
    parser.add_argument("--validator", action="append", type=_parse_validator, required=True)
    args = parser.parse_args()

    key_hex = os.environ.get("FLOCK_DEVNET_KEY_HEX")
    if key_hex is None:
        raise SystemExit("FLOCK_DEVNET_KEY_HEX is required")
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
    node = DevnetNode(
        args.data_dir,
        args.chain_id,
        args.height,
        ValidatorSet(args.validator),
        key,
    )
    serve(node, args.host, args.port)


if __name__ == "__main__":
    main()
