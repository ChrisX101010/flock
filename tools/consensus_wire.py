from __future__ import annotations

import hashlib
import struct

from tools.consensus import (
    QC_DOMAIN,
    QC_HASH_DOMAIN,
    VOTE_RECORD_DOMAIN,
    Proposal,
    QuorumCertificate,
    ValidatorSet,
    decode_vote,
    encode_qc,
    verify_qc,
)

PROPOSAL_WIRE_DOMAIN = b"FLOCKPROPWIRE1"
HASH_LEN = 32
PUBKEY_LEN = 32
SIGNATURE_LEN = 64
VOTE_FIXED_LEN = len(VOTE_RECORD_DOMAIN) + 4 + 8 + 4 + 1 + 32 + 32 + 32 + 64


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


def _take(data: bytes, at: int, size: int, label: str) -> tuple[bytes, int]:
    end = at + size
    if end > len(data):
        raise ValueError(f"truncated {label}")
    return data[at:end], end


def encode_proposal(proposal: Proposal) -> bytes:
    hashes = (
        proposal.block_hash,
        proposal.parent_block_hash,
        proposal.pre_state_root,
        proposal.post_state_root,
        proposal.pre_registry_root,
        proposal.post_registry_root,
        proposal.validator_set_root,
    )
    if any(len(value) != HASH_LEN for value in hashes):
        raise ValueError("proposal hashes must be 32 bytes")
    if len(proposal.proposer_public_key) != PUBKEY_LEN:
        raise ValueError("proposal public key must be 32 bytes")
    if len(proposal.signature) != SIGNATURE_LEN:
        raise ValueError("proposal signature must be 64 bytes")

    return b"".join(
        (
            PROPOSAL_WIRE_DOMAIN,
            _u32(proposal.chain_id),
            _u64(proposal.height),
            _u32(proposal.round),
            *hashes,
            proposal.proposer_public_key,
            proposal.signature,
        )
    )


def decode_proposal(raw: bytes) -> Proposal:
    expected = len(PROPOSAL_WIRE_DOMAIN) + 4 + 8 + 4 + (7 * 32) + 32 + 64
    if len(raw) != expected or not raw.startswith(PROPOSAL_WIRE_DOMAIN):
        raise ValueError("invalid proposal wire record")

    at = len(PROPOSAL_WIRE_DOMAIN)
    chain_id, at = _take_u32(raw, at)
    height, at = _take_u64(raw, at)
    round_, at = _take_u32(raw, at)

    fields = []
    for label in (
        "block hash",
        "parent block hash",
        "pre-state root",
        "post-state root",
        "pre-registry root",
        "post-registry root",
        "validator-set root",
    ):
        value, at = _take(raw, at, 32, label)
        fields.append(value)

    proposer_public_key, at = _take(raw, at, 32, "proposer public key")
    signature, at = _take(raw, at, 64, "proposal signature")
    if at != len(raw):
        raise ValueError("trailing proposal bytes")

    proposal = Proposal(
        chain_id=chain_id,
        height=height,
        round=round_,
        block_hash=fields[0],
        parent_block_hash=fields[1],
        pre_state_root=fields[2],
        post_state_root=fields[3],
        pre_registry_root=fields[4],
        post_registry_root=fields[5],
        validator_set_root=fields[6],
        proposer_public_key=proposer_public_key,
        signature=signature,
    )
    if encode_proposal(proposal) != raw:
        raise ValueError("non-canonical proposal wire record")
    return proposal


def decode_qc(raw: bytes, validators: ValidatorSet) -> QuorumCertificate:
    minimum = len(QC_DOMAIN) + 4 + 8 + 4 + 1 + 32 + 32 + 4 + 32
    if len(raw) < minimum or not raw.startswith(QC_DOMAIN):
        raise ValueError("invalid quorum-certificate record")

    body = raw[:-32]
    stored_hash = raw[-32:]
    expected_hash = hashlib.sha256(QC_HASH_DOMAIN + body).digest()
    if stored_hash != expected_hash:
        raise ValueError("quorum-certificate hash mismatch")

    at = len(QC_DOMAIN)
    chain_id, at = _take_u32(body, at)
    height, at = _take_u64(body, at)
    round_, at = _take_u32(body, at)
    step_raw, at = _take(body, at, 1, "quorum step")
    step = step_raw[0]
    block_hash, at = _take(body, at, 32, "quorum block hash")
    validator_set_root, at = _take(body, at, 32, "validator-set root")
    vote_count, at = _take_u32(body, at)

    votes = []
    for _ in range(vote_count):
        vote_raw, at = _take(body, at, VOTE_FIXED_LEN, "vote record")
        votes.append(decode_vote(vote_raw))

    if at != len(body):
        raise ValueError("trailing quorum-certificate bytes")

    qc = QuorumCertificate(
        chain_id=chain_id,
        height=height,
        round=round_,
        step=step,
        block_hash=block_hash,
        validator_set_root=validator_set_root,
        votes=tuple(votes),
    )
    verify_qc(qc, validators)
    if encode_qc(qc) != raw:
        raise ValueError("non-canonical quorum-certificate record")
    return qc
