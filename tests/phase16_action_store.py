from __future__ import annotations

import struct
import tempfile

from tools.action_store import (
    ActionStore,
    encode_action_record,
    parse_action_record,
)
from tools.block_producer import BlockLimits
from tools.contract_runtime import ContractRegistry, derive_contract_id
from tools.deployment_actions import (
    execute_action_block,
    make_deploy_tx,
)
from tools.execution_pipeline import UnifiedState
from tools.flock_vm_state import (
    OP_HALT,
    OP_PUSH_U64,
    OP_SLOAD_U64,
    OP_SSTORE_U64,
    encode_program,
)
from tools.reference_model import Tx

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)
ZERO = bytes(32)


def push(value: int) -> bytes:
    return bytes([OP_PUSH_U64]) + struct.pack(">Q", value)


def sload(slot: int) -> bytes:
    return push(slot) + bytes([OP_SLOAD_U64])


def sstore(slot: int, value: int) -> bytes:
    return push(slot) + push(value) + bytes([OP_SSTORE_U64])


def limits() -> BlockLimits:
    return BlockLimits(
        max_txs=16,
        max_tx_bytes=16 * 8192,
        max_compute=10000,
        max_state=1000,
        max_memory=10000,
    )


def main() -> None:
    registry0 = ContractRegistry()
    state0 = UnifiedState(
        accounts={ALICE: (0, 1000), BOB: (0, 0)},
        contracts={},
    )

    program1 = encode_program(
        sstore(7, 42) + sload(7) + bytes([OP_HALT])
    )
    contract1 = derive_contract_id(ALICE, 0, program1)
    deploy1 = make_deploy_tx(
        chain_id=1,
        nonce=0,
        sender=ALICE,
        amount=10,
        compute_limit=100,
        state_limit=4,
        memory_limit=64,
        program=program1,
    )
    call1 = Tx(
        chain_id=1,
        nonce=1,
        sender=ALICE,
        recipient=contract1,
        amount=5,
        compute_limit=100,
        state_limit=2,
        memory_limit=64,
        payload=b"",
    )

    block0 = execute_action_block(
        state0,
        registry0,
        [call1, deploy1],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits(),
    )
    assert block0.pre_registry_root != block0.post_registry_root
    raw0 = encode_action_record(block0)
    parsed0 = parse_action_record(raw0)
    assert parsed0.block_hash == block0.block_hash
    assert parsed0.post_registry_root == block0.post_registry_root
    assert parsed0.final_state == block0.final_state
    assert encode_action_record(block0) == raw0
    print("PHASE16_ACTION_RECORD_REPEAT=BYTE_IDENTICAL")

    with tempfile.TemporaryDirectory() as td:
        store = ActionStore(td)
        store.append(raw0)

        restarted = ActionStore(td)
        recovered0 = restarted.recover()
        assert recovered0 is not None
        h0, hash0, recovered_state0, recovered_registry0 = recovered0
        assert h0 == 0
        assert hash0 == block0.block_hash
        assert recovered_state0 == block0.final_state
        assert recovered_registry0.get(contract1) is not None
        print("PHASE16_DEPLOYMENT_RESTART_RECOVERY=GREEN")

        transfer = Tx(
            chain_id=1,
            nonce=2,
            sender=ALICE,
            recipient=BOB,
            amount=100,
            compute_limit=10,
            state_limit=0,
            memory_limit=0,
            payload=b"",
        )
        block1 = execute_action_block(
            recovered_state0,
            recovered_registry0,
            [transfer],
            chain_id=1,
            height=1,
            parent_block_hash=hash0,
            limits=limits(),
        )
        assert block1.pre_registry_root == block1.post_registry_root
        store.append(encode_action_record(block1))

        restarted1 = ActionStore(td)
        recovered1 = restarted1.recover()
        assert recovered1 is not None
        h1, hash1, recovered_state1, recovered_registry1 = recovered1
        assert h1 == 1
        assert recovered_state1.accounts[ALICE] == (3, 885)
        assert recovered_state1.accounts[BOB] == (0, 100)
        assert recovered_registry1.get(contract1) is not None
        print("PHASE16_UNCHANGED_REGISTRY_CONTINUITY=GREEN")

        program2 = encode_program(bytes([OP_HALT]))
        contract2 = derive_contract_id(ALICE, 3, program2)
        deploy2 = make_deploy_tx(
            chain_id=1,
            nonce=3,
            sender=ALICE,
            amount=7,
            compute_limit=50,
            state_limit=0,
            memory_limit=0,
            program=program2,
        )
        block2 = execute_action_block(
            recovered_state1,
            recovered_registry1,
            [deploy2],
            chain_id=1,
            height=2,
            parent_block_hash=hash1,
            limits=limits(),
        )
        assert block2.pre_registry_root != block2.post_registry_root
        store.append(encode_action_record(block2))

        restarted2 = ActionStore(td)
        chain = restarted2.verify_chain()
        assert len(chain) == 3
        assert chain[1].pre_registry_root == chain[0].post_registry_root
        assert chain[2].pre_registry_root == chain[1].post_registry_root
        assert chain[2].pre_state_root == chain[1].post_state_root

        recovered2 = restarted2.recover()
        assert recovered2 is not None
        h2, hash2, recovered_state2, recovered_registry2 = recovered2
        assert h2 == 2
        assert hash2 == block2.block_hash
        assert recovered_registry2.get(contract1) is not None
        assert recovered_registry2.get(contract2) is not None
        assert recovered_state2.accounts[ALICE] == (4, 878)
        assert recovered_state2.accounts[contract2] == (0, 7)
        print("PHASE16_MULTIPLE_REGISTRY_TRANSITIONS=GREEN")

        # A block built from a stale registry has a different pre-registry
        # commitment and must be rejected without changing HEAD.
        stale_registry = ContractRegistry()
        bad = execute_action_block(
            recovered_state2,
            stale_registry,
            [],
            chain_id=1,
            height=3,
            parent_block_hash=hash2,
            limits=limits(),
        )
        before = restarted2.tip()
        assert before is not None
        before_identity = (before.height, before.block_hash, before.raw)
        try:
            restarted2.append(encode_action_record(bad))
        except ValueError:
            pass
        else:
            raise AssertionError("stale-registry block accepted")

        after = restarted2.tip()
        assert after is not None
        assert (after.height, after.block_hash, after.raw) == before_identity
        print("PHASE16_REGISTRY_DISCONTINUITY_NO_MUTATION=GREEN")

        try:
            restarted2.append(encode_action_record(block2))
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate action block accepted")
        print("PHASE16_DUPLICATE_APPEND_REJECTED=GREEN")

        tampered = bytearray(encode_action_record(block2))
        tampered[-40] ^= 1
        try:
            parse_action_record(bytes(tampered))
        except ValueError:
            pass
        else:
            raise AssertionError("tampered action record accepted")
        print("PHASE16_TAMPER_DETECTION=GREEN")

        # Recovered state and registry can immediately produce the next block.
        next_tx = Tx(
            chain_id=1,
            nonce=4,
            sender=ALICE,
            recipient=BOB,
            amount=1,
            compute_limit=10,
            state_limit=0,
            memory_limit=0,
            payload=b"",
        )
        block3 = execute_action_block(
            recovered_state2,
            recovered_registry2,
            [next_tx],
            chain_id=1,
            height=3,
            parent_block_hash=hash2,
            limits=limits(),
        )
        assert block3.final_state.accounts[ALICE] == (5, 877)
        assert block3.final_state.accounts[BOB] == (0, 101)
        print("PHASE16_CONTINUE_AFTER_REGISTRY_RESTART=GREEN")

    print("FLOCK_PHASE16_REGISTRY_CHANGING_ACTION_STORE=GREEN")


if __name__ == "__main__":
    main()
