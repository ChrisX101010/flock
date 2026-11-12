from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tools.action_store import PersistedActionBlock
from tools.authenticated_mempool import public_key_bytes

VALIDATOR_SET_DOMAIN = b"FLOCKVALSET1"
PROPOSAL_DOMAIN = b"FLOCKPROPOSAL1"
VOTE_DOMAIN = b"FLOCKVOTE1"
VOTE_RECORD_DOMAIN = b"FLOCKVOTEREC1"
QC_DOMAIN = b"FLOCKQC1"
QC_HASH_DOMAIN = b"FLOCKQCHASH1"

STEP_PREVOTE = 1
STEP_PRECOMMIT = 2
VALID_STEPS = (STEP_PREVOTE, STEP_PRECOMMIT)
PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64
HASH_LEN = 32
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


def _hash32(value: bytes, name: str) -> bytes:
    if len(value) != HASH_LEN:
        raise ValueError(f"{name} must be 32 bytes")
    return value


@dataclass(frozen=True, order=True)
class Validator:
    public_key: bytes
    voting_power: int = 1

    def __post_init__(self) -> None:
        if len(self.public_key) != PUBLIC_KEY_LEN:
            raise ValueError("validator public key must be 32 bytes")
        if not 1 <= self.voting_power <= U64_MAX:
            raise ValueError("validator voting power must be positive u64")


class ValidatorSet:
    def __init__(self, validators: list[Validator] | tuple[Validator, ...]):
        if not validators:
            raise ValueError("validator set cannot be empty")
        ordered = tuple(sorted(validators, key=lambda v: v.public_key))
        if len({v.public_key for v in ordered}) != len(ordered):
            raise ValueError("duplicate validator public key")
        total = sum(v.voting_power for v in ordered)
        if total > U64_MAX:
            raise ValueError("total validator power exceeds u64")
        self.validators = ordered
        self.total_power = total
        self.quorum_power = (2 * total) // 3 + 1
        body = bytearray(VALIDATOR_SET_DOMAIN)
        body += _u32(len(ordered))
        for validator in ordered:
            body += validator.public_key
            body += _u64(validator.voting_power)
        self.root = hashlib.sha256(bytes(body)).digest()
        self._power = {v.public_key: v.voting_power for v in ordered}

    def __len__(self) -> int:
        return len(self.validators)

    def power(self, public_key: bytes) -> int:
        try:
            return self._power[public_key]
        except KeyError as exc:
            raise ValueError("validator is not in validator set") from exc

    def proposer(self, height: int, round_: int) -> Validator:
        if not 0 <= height <= U64_MAX:
            raise ValueError("height outside u64")
        if not 0 <= round_ <= U32_MAX:
            raise ValueError("round outside u32")
        return self.validators[(height + round_) % len(self.validators)]


@dataclass(frozen=True)
class Proposal:
    chain_id: int
    height: int
    round: int
    block_hash: bytes
    parent_block_hash: bytes
    pre_state_root: bytes
    post_state_root: bytes
    pre_registry_root: bytes
    post_registry_root: bytes
    validator_set_root: bytes
    proposer_public_key: bytes
    signature: bytes


def _proposal_message(
    *,
    chain_id: int,
    height: int,
    round_: int,
    block_hash: bytes,
    parent_block_hash: bytes,
    pre_state_root: bytes,
    post_state_root: bytes,
    pre_registry_root: bytes,
    post_registry_root: bytes,
    validator_set_root: bytes,
) -> bytes:
    return b"".join(
        (
            PROPOSAL_DOMAIN,
            _u32(chain_id),
            _u64(height),
            _u32(round_),
            _hash32(block_hash, "block hash"),
            _hash32(parent_block_hash, "parent block hash"),
            _hash32(pre_state_root, "pre-state root"),
            _hash32(post_state_root, "post-state root"),
            _hash32(pre_registry_root, "pre-registry root"),
            _hash32(post_registry_root, "post-registry root"),
            _hash32(validator_set_root, "validator-set root"),
        )
    )


def make_proposal(
    record: PersistedActionBlock,
    *,
    round_: int,
    validators: ValidatorSet,
    private_key: Ed25519PrivateKey,
) -> Proposal:
    proposer_public_key = public_key_bytes(private_key.public_key())
    expected = validators.proposer(record.height, round_)
    if proposer_public_key != expected.public_key:
        raise ValueError("private key is not the scheduled proposer")
    message = _proposal_message(
        chain_id=record.chain_id,
        height=record.height,
        round_=round_,
        block_hash=record.block_hash,
        parent_block_hash=record.parent_block_hash,
        pre_state_root=record.pre_state_root,
        post_state_root=record.post_state_root,
        pre_registry_root=record.pre_registry_root,
        post_registry_root=record.post_registry_root,
        validator_set_root=validators.root,
    )
    return Proposal(
        chain_id=record.chain_id,
        height=record.height,
        round=round_,
        block_hash=record.block_hash,
        parent_block_hash=record.parent_block_hash,
        pre_state_root=record.pre_state_root,
        post_state_root=record.post_state_root,
        pre_registry_root=record.pre_registry_root,
        post_registry_root=record.post_registry_root,
        validator_set_root=validators.root,
        proposer_public_key=proposer_public_key,
        signature=private_key.sign(message),
    )


def verify_proposal(
    proposal: Proposal,
    record: PersistedActionBlock,
    validators: ValidatorSet,
) -> None:
    expected = validators.proposer(proposal.height, proposal.round)
    if proposal.proposer_public_key != expected.public_key:
        raise ValueError("proposal is not signed by scheduled proposer")
    if proposal.validator_set_root != validators.root:
        raise ValueError("proposal validator-set root mismatch")
    expected_fields = (
        record.chain_id,
        record.height,
        record.block_hash,
        record.parent_block_hash,
        record.pre_state_root,
        record.post_state_root,
        record.pre_registry_root,
        record.post_registry_root,
    )
    actual_fields = (
        proposal.chain_id,
        proposal.height,
        proposal.block_hash,
        proposal.parent_block_hash,
        proposal.pre_state_root,
        proposal.post_state_root,
        proposal.pre_registry_root,
        proposal.post_registry_root,
    )
    if actual_fields != expected_fields:
        raise ValueError("proposal does not bind to action record")
    message = _proposal_message(
        chain_id=proposal.chain_id,
        height=proposal.height,
        round_=proposal.round,
        block_hash=proposal.block_hash,
        parent_block_hash=proposal.parent_block_hash,
        pre_state_root=proposal.pre_state_root,
        post_state_root=proposal.post_state_root,
        pre_registry_root=proposal.pre_registry_root,
        post_registry_root=proposal.post_registry_root,
        validator_set_root=proposal.validator_set_root,
    )
    try:
        Ed25519PublicKey.from_public_bytes(proposal.proposer_public_key).verify(
            proposal.signature,
            message,
        )
    except InvalidSignature as exc:
        raise ValueError("invalid proposal signature") from exc


@dataclass(frozen=True)
class Vote:
    chain_id: int
    height: int
    round: int
    step: int
    block_hash: bytes
    validator_set_root: bytes
    validator_public_key: bytes
    signature: bytes


def _vote_message(
    *,
    chain_id: int,
    height: int,
    round_: int,
    step: int,
    block_hash: bytes,
    validator_set_root: bytes,
) -> bytes:
    if step not in VALID_STEPS:
        raise ValueError("invalid consensus vote step")
    return b"".join(
        (
            VOTE_DOMAIN,
            _u32(chain_id),
            _u64(height),
            _u32(round_),
            bytes([step]),
            _hash32(block_hash, "block hash"),
            _hash32(validator_set_root, "validator-set root"),
        )
    )


def sign_vote(
    *,
    chain_id: int,
    height: int,
    round_: int,
    step: int,
    block_hash: bytes,
    validators: ValidatorSet,
    private_key: Ed25519PrivateKey,
) -> Vote:
    public_key = public_key_bytes(private_key.public_key())
    validators.power(public_key)
    message = _vote_message(
        chain_id=chain_id,
        height=height,
        round_=round_,
        step=step,
        block_hash=block_hash,
        validator_set_root=validators.root,
    )
    return Vote(
        chain_id=chain_id,
        height=height,
        round=round_,
        step=step,
        block_hash=block_hash,
        validator_set_root=validators.root,
        validator_public_key=public_key,
        signature=private_key.sign(message),
    )


def verify_vote(vote: Vote, validators: ValidatorSet) -> None:
    validators.power(vote.validator_public_key)
    if vote.validator_set_root != validators.root:
        raise ValueError("vote validator-set root mismatch")
    if len(vote.validator_public_key) != PUBLIC_KEY_LEN:
        raise ValueError("vote public key must be 32 bytes")
    if len(vote.signature) != SIGNATURE_LEN:
        raise ValueError("vote signature must be 64 bytes")
    message = _vote_message(
        chain_id=vote.chain_id,
        height=vote.height,
        round_=vote.round,
        step=vote.step,
        block_hash=vote.block_hash,
        validator_set_root=vote.validator_set_root,
    )
    try:
        Ed25519PublicKey.from_public_bytes(vote.validator_public_key).verify(
            vote.signature,
            message,
        )
    except InvalidSignature as exc:
        raise ValueError("invalid vote signature") from exc


def encode_vote(vote: Vote) -> bytes:
    if len(vote.validator_public_key) != PUBLIC_KEY_LEN:
        raise ValueError("vote public key must be 32 bytes")
    if len(vote.signature) != SIGNATURE_LEN:
        raise ValueError("vote signature must be 64 bytes")
    return b"".join(
        (
            VOTE_RECORD_DOMAIN,
            _u32(vote.chain_id),
            _u64(vote.height),
            _u32(vote.round),
            bytes([vote.step]),
            _hash32(vote.block_hash, "block hash"),
            _hash32(vote.validator_set_root, "validator-set root"),
            vote.validator_public_key,
            vote.signature,
        )
    )


def decode_vote(raw: bytes) -> Vote:
    fixed = len(VOTE_RECORD_DOMAIN) + 4 + 8 + 4 + 1 + 32 + 32 + 32 + 64
    if len(raw) != fixed or not raw.startswith(VOTE_RECORD_DOMAIN):
        raise ValueError("invalid vote record")
    at = len(VOTE_RECORD_DOMAIN)
    chain_id = struct.unpack_from(">I", raw, at)[0]
    at += 4
    height = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    round_ = struct.unpack_from(">I", raw, at)[0]
    at += 4
    step = raw[at]
    at += 1
    block_hash = raw[at:at + 32]
    at += 32
    validator_set_root = raw[at:at + 32]
    at += 32
    validator_public_key = raw[at:at + 32]
    at += 32
    signature = raw[at:at + 64]
    vote = Vote(
        chain_id=chain_id,
        height=height,
        round=round_,
        step=step,
        block_hash=block_hash,
        validator_set_root=validator_set_root,
        validator_public_key=validator_public_key,
        signature=signature,
    )
    if encode_vote(vote) != raw:
        raise ValueError("non-canonical vote record")
    return vote


@dataclass(frozen=True)
class QuorumCertificate:
    chain_id: int
    height: int
    round: int
    step: int
    block_hash: bytes
    validator_set_root: bytes
    votes: tuple[Vote, ...]


def build_qc(votes: list[Vote] | tuple[Vote, ...], validators: ValidatorSet) -> QuorumCertificate:
    if not votes:
        raise ValueError("cannot build quorum certificate without votes")
    first = votes[0]
    expected = (
        first.chain_id,
        first.height,
        first.round,
        first.step,
        first.block_hash,
        first.validator_set_root,
    )
    seen: set[bytes] = set()
    power = 0
    for vote in votes:
        verify_vote(vote, validators)
        actual = (
            vote.chain_id,
            vote.height,
            vote.round,
            vote.step,
            vote.block_hash,
            vote.validator_set_root,
        )
        if actual != expected:
            raise ValueError("quorum votes do not agree on one decision")
        if vote.validator_public_key in seen:
            raise ValueError("duplicate validator in quorum certificate")
        seen.add(vote.validator_public_key)
        power += validators.power(vote.validator_public_key)
    if power < validators.quorum_power:
        raise ValueError("insufficient voting power for quorum")
    ordered = tuple(sorted(votes, key=lambda vote: vote.validator_public_key))
    return QuorumCertificate(
        chain_id=first.chain_id,
        height=first.height,
        round=first.round,
        step=first.step,
        block_hash=first.block_hash,
        validator_set_root=first.validator_set_root,
        votes=ordered,
    )


def verify_qc(qc: QuorumCertificate, validators: ValidatorSet) -> None:
    rebuilt = build_qc(qc.votes, validators)
    if rebuilt != qc:
        raise ValueError("non-canonical quorum certificate")


def encode_qc(qc: QuorumCertificate) -> bytes:
    body = bytearray(QC_DOMAIN)
    body += _u32(qc.chain_id)
    body += _u64(qc.height)
    body += _u32(qc.round)
    if qc.step not in VALID_STEPS:
        raise ValueError("invalid quorum-certificate step")
    body += bytes([qc.step])
    body += _hash32(qc.block_hash, "block hash")
    body += _hash32(qc.validator_set_root, "validator-set root")
    body += _u32(len(qc.votes))
    for vote in qc.votes:
        body += encode_vote(vote)
    digest = hashlib.sha256(QC_HASH_DOMAIN + bytes(body)).digest()
    return bytes(body) + digest


def qc_hash(qc: QuorumCertificate) -> bytes:
    return hashlib.sha256(encode_qc(qc)).digest()


class EquivocationError(ValueError):
    pass


class VoteBook:
    def __init__(self, validators: ValidatorSet):
        self.validators = validators
        self._seen: dict[tuple[bytes, int, int, int, int], bytes] = {}
        self._votes: list[Vote] = []

    def add(self, vote: Vote) -> bool:
        verify_vote(vote, self.validators)
        key = (
            vote.validator_public_key,
            vote.chain_id,
            vote.height,
            vote.round,
            vote.step,
        )
        previous = self._seen.get(key)
        if previous is not None:
            if previous != vote.block_hash:
                raise EquivocationError("validator equivocated in same height/round/step")
            return False
        self._seen[key] = vote.block_hash
        self._votes.append(vote)
        return True

    def votes_for(
        self,
        *,
        chain_id: int,
        height: int,
        round_: int,
        step: int,
        block_hash: bytes,
    ) -> tuple[Vote, ...]:
        return tuple(
            vote
            for vote in self._votes
            if vote.chain_id == chain_id
            and vote.height == height
            and vote.round == round_
            and vote.step == step
            and vote.block_hash == block_hash
        )


class ConsensusMachine:
    def __init__(self, *, chain_id: int, height: int, validators: ValidatorSet):
        if not 0 <= chain_id <= U32_MAX:
            raise ValueError("chain id outside u32")
        if not 0 <= height <= U64_MAX:
            raise ValueError("height outside u64")
        self.chain_id = chain_id
        self.height = height
        self.validators = validators
        self.round = 0
        self.locked_round = -1
        self.locked_block_hash = ZERO_HASH
        self.finalized_block_hash: bytes | None = None
        self._prevote_qcs: dict[int, QuorumCertificate] = {}

    def _check_qc_context(self, qc: QuorumCertificate, step: int) -> None:
        verify_qc(qc, self.validators)
        if qc.chain_id != self.chain_id or qc.height != self.height:
            raise ValueError("quorum certificate is for different consensus instance")
        if qc.step != step:
            raise ValueError("quorum certificate has wrong step")

    def observe_prevote_qc(self, qc: QuorumCertificate) -> None:
        self._check_qc_context(qc, STEP_PREVOTE)
        existing = self._prevote_qcs.get(qc.round)
        if existing is not None and existing.block_hash != qc.block_hash:
            raise ValueError("conflicting prevote quorum certificate for same round")
        if qc.round < self.locked_round and qc.block_hash != self.locked_block_hash:
            raise ValueError("stale quorum certificate cannot break a newer lock")
        self._prevote_qcs[qc.round] = qc
        if qc.round >= self.locked_round:
            self.locked_round = qc.round
            self.locked_block_hash = qc.block_hash
        self.round = max(self.round, qc.round)

    def observe_precommit_qc(self, qc: QuorumCertificate) -> bytes:
        self._check_qc_context(qc, STEP_PRECOMMIT)
        prevote_qc = self._prevote_qcs.get(qc.round)
        if prevote_qc is None or prevote_qc.block_hash != qc.block_hash:
            raise ValueError("precommit quorum lacks matching prevote quorum")
        if self.locked_block_hash != qc.block_hash or self.locked_round > qc.round:
            raise ValueError("precommit quorum conflicts with local lock")
        if self.finalized_block_hash is not None and self.finalized_block_hash != qc.block_hash:
            raise ValueError("consensus instance already finalized another block")
        self.finalized_block_hash = qc.block_hash
        self.round = max(self.round, qc.round)
        return qc.block_hash

    def verify_finalized_record(self, record: PersistedActionBlock) -> None:
        if self.finalized_block_hash is None:
            raise ValueError("no finalized block")
        if record.chain_id != self.chain_id or record.height != self.height:
            raise ValueError("finalized record context mismatch")
        if record.block_hash != self.finalized_block_hash:
            raise ValueError("finalized record hash mismatch")
