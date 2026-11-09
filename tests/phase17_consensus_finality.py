from __future__ import annotations

from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.action_store import encode_action_record, parse_action_record
from tools.block_producer import BlockLimits
from tools.consensus import (
    ConsensusMachine,
    EquivocationError,
    STEP_PRECOMMIT,
    STEP_PREVOTE,
    Validator,
    ValidatorSet,
    VoteBook,
    build_qc,
    decode_vote,
    encode_qc,
    encode_vote,
    make_proposal,
    qc_hash,
    sign_vote,
    verify_proposal,
    verify_qc,
)
from tools.contract_runtime import ContractRegistry
from tools.deployment_actions import execute_action_block
from tools.execution_pipeline import UnifiedState
from tools.authenticated_mempool import public_key_bytes

ALICE = bytes.fromhex("11" * 32)
ZERO = bytes(32)


def limits() -> BlockLimits:
    return BlockLimits(
        max_txs=16,
        max_tx_bytes=16 * 8192,
        max_compute=10000,
        max_state=1000,
        max_memory=10000,
    )


def expect_value_error(fn, label: str) -> None:
    try:
        fn()
    except ValueError:
        return
    raise AssertionError(label)


def main() -> None:
    private_keys = [
        Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32)
        for i in range(1, 5)
    ]
    by_public_key = {
        public_key_bytes(private.public_key()): private
        for private in private_keys
    }
    validator_values = [
        Validator(public_key=public_key, voting_power=1)
        for public_key in by_public_key
    ]
    validators = ValidatorSet(validator_values)
    reversed_validators = ValidatorSet(list(reversed(validator_values)))
    assert validators.root == reversed_validators.root
    assert validators.total_power == 4
    assert validators.quorum_power == 3
    expect_value_error(
        lambda: ValidatorSet(validator_values + [validator_values[0]]),
        "duplicate validator accepted",
    )
    print("PHASE17_VALIDATOR_SET_CANONICAL=GREEN")

    state0 = UnifiedState(accounts={ALICE: (0, 1000)}, contracts={})
    registry0 = ContractRegistry()
    block0 = execute_action_block(
        state0,
        registry0,
        [],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits(),
    )
    record0 = parse_action_record(encode_action_record(block0))

    proposer = validators.proposer(record0.height, 0)
    proposal = make_proposal(
        record0,
        round_=0,
        validators=validators,
        private_key=by_public_key[proposer.public_key],
    )
    verify_proposal(proposal, record0, validators)
    expect_value_error(
        lambda: verify_proposal(
            replace(proposal, block_hash=bytes.fromhex("aa" * 32)),
            record0,
            validators,
        ),
        "proposal detached from action record",
    )
    print("PHASE17_PROPOSER_AND_PROPOSAL_BINDING=GREEN")

    voting_keys = [by_public_key[v.public_key] for v in validators.validators]
    prevotes = [
        sign_vote(
            chain_id=1,
            height=0,
            round_=0,
            step=STEP_PREVOTE,
            block_hash=record0.block_hash,
            validators=validators,
            private_key=private,
        )
        for private in voting_keys[:3]
    ]
    vote_raw = encode_vote(prevotes[0])
    assert decode_vote(vote_raw) == prevotes[0]
    assert encode_vote(decode_vote(vote_raw)) == vote_raw

    prevote_qc = build_qc(prevotes, validators)
    verify_qc(prevote_qc, validators)
    assert encode_qc(prevote_qc) == encode_qc(build_qc(list(reversed(prevotes)), validators))
    assert len(qc_hash(prevote_qc)) == 32
    print("PHASE17_SIGNED_VOTES_AND_QC=GREEN")

    expect_value_error(
        lambda: build_qc(prevotes[:2], validators),
        "two-of-four votes incorrectly reached quorum",
    )
    expect_value_error(
        lambda: build_qc([prevotes[0], prevotes[0], prevotes[1]], validators),
        "duplicate vote inflated quorum power",
    )
    print("PHASE17_QUORUM_THRESHOLD=GREEN")

    book = VoteBook(validators)
    assert book.add(prevotes[0])
    assert not book.add(prevotes[0])
    conflict_hash = bytes.fromhex("bb" * 32)
    conflicting_vote = sign_vote(
        chain_id=1,
        height=0,
        round_=0,
        step=STEP_PREVOTE,
        block_hash=conflict_hash,
        validators=validators,
        private_key=voting_keys[0],
    )
    try:
        book.add(conflicting_vote)
    except EquivocationError:
        pass
    else:
        raise AssertionError("equivocation was not detected")
    print("PHASE17_EQUIVOCATION_DETECTION=GREEN")

    machine = ConsensusMachine(chain_id=1, height=0, validators=validators)
    machine.observe_prevote_qc(prevote_qc)
    assert machine.locked_round == 0
    assert machine.locked_block_hash == record0.block_hash

    conflict_precommits = [
        sign_vote(
            chain_id=1,
            height=0,
            round_=0,
            step=STEP_PRECOMMIT,
            block_hash=conflict_hash,
            validators=validators,
            private_key=private,
        )
        for private in voting_keys[:3]
    ]
    conflict_precommit_qc = build_qc(conflict_precommits, validators)
    expect_value_error(
        lambda: machine.observe_precommit_qc(conflict_precommit_qc),
        "conflicting precommit quorum bypassed prevote lock",
    )
    assert machine.finalized_block_hash is None
    print("PHASE17_LOCKING_RULE=GREEN")

    precommits = [
        sign_vote(
            chain_id=1,
            height=0,
            round_=0,
            step=STEP_PRECOMMIT,
            block_hash=record0.block_hash,
            validators=validators,
            private_key=private,
        )
        for private in voting_keys[:3]
    ]
    precommit_qc = build_qc(precommits, validators)
    finalized = machine.observe_precommit_qc(precommit_qc)
    assert finalized == record0.block_hash
    machine.verify_finalized_record(record0)
    print("PHASE17_PRECOMMIT_FINALITY=GREEN")

    relock = ConsensusMachine(chain_id=1, height=0, validators=validators)
    relock.observe_prevote_qc(prevote_qc)
    higher_prevotes = [
        sign_vote(
            chain_id=1,
            height=0,
            round_=1,
            step=STEP_PREVOTE,
            block_hash=conflict_hash,
            validators=validators,
            private_key=private,
        )
        for private in voting_keys[:3]
    ]
    higher_prevote_qc = build_qc(higher_prevotes, validators)
    relock.observe_prevote_qc(higher_prevote_qc)
    assert relock.locked_round == 1
    assert relock.locked_block_hash == conflict_hash
    print("PHASE17_HIGHER_ROUND_RELOCK=GREEN")

    print("FLOCK_PHASE17_DETERMINISTIC_BFT_FINALITY=GREEN")


if __name__ == "__main__":
    main()
