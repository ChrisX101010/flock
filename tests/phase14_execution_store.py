from __future__ import annotations

import tempfile

from tools.block_producer import BlockLimits
from tools.contract_runtime import ContractRegistry
from tools.execution_pipeline import (
    UnifiedState,
    execute_block,
)
from tools.execution_store import (
    ExecutionStore,
    encode_execution_record,
    parse_execution_record,
)
from tools.reference_model import Tx

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)
ZERO = bytes(32)


def tx(*, nonce: int, amount: int) -> Tx:
    return Tx(
        chain_id=1,
        nonce=nonce,
        sender=ALICE,
        recipient=BOB,
        amount=amount,
        compute_limit=10,
        state_limit=0,
        memory_limit=0,
        payload=b"",
    )


def limits() -> BlockLimits:
    return BlockLimits(
        max_txs=8,
        max_tx_bytes=8 * 8192,
        max_compute=1000,
        max_state=100,
        max_memory=1000,
    )


def main() -> None:
    registry = ContractRegistry()
    genesis_state = UnifiedState(
        accounts={ALICE: (0, 1000), BOB: (0, 0)},
        contracts={},
    )

    block0 = execute_block(
        genesis_state,
        registry,
        [tx(nonce=0, amount=100)],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits(),
    )
    raw0 = encode_execution_record(block0, registry)
    parsed0 = parse_execution_record(raw0)

    assert parsed0.block_hash == block0.block_hash
    assert parsed0.post_state_root == block0.post_state_root
    assert parsed0.final_state == block0.final_state
    assert parsed0.registry.to_bytes() == registry.to_bytes()
    assert encode_execution_record(block0, registry) == raw0
    print("PHASE14_RECORD_REPEAT=BYTE_IDENTICAL")

    with tempfile.TemporaryDirectory() as td:
        store = ExecutionStore(td)
        committed0 = store.append(raw0)
        assert committed0.block_hash == block0.block_hash

        restarted = ExecutionStore(td)
        recovered0 = restarted.recover()
        assert recovered0 is not None
        height0, hash0, state0, registry0 = recovered0
        assert height0 == 0
        assert hash0 == block0.block_hash
        assert state0 == block0.final_state
        assert registry0.to_bytes() == registry.to_bytes()
        print("PHASE14_GENESIS_RESTART_RECOVERY=GREEN")

        block1 = execute_block(
            state0,
            registry0,
            [tx(nonce=1, amount=25)],
            chain_id=1,
            height=1,
            parent_block_hash=hash0,
            limits=limits(),
        )
        raw1 = encode_execution_record(block1, registry0)
        store.append(raw1)

        restarted2 = ExecutionStore(td)
        chain = restarted2.verify_chain()
        assert len(chain) == 2
        assert chain[0].block_hash == block0.block_hash
        assert chain[1].block_hash == block1.block_hash
        assert chain[1].pre_state_root == chain[0].post_state_root

        recovered1 = restarted2.recover()
        assert recovered1 is not None
        height1, hash1, state1, registry1 = recovered1
        assert height1 == 1
        assert hash1 == block1.block_hash
        assert state1 == block1.final_state
        assert state1.accounts[ALICE] == (2, 875)
        assert state1.accounts[BOB] == (0, 125)
        assert registry1.to_bytes() == registry.to_bytes()
        print("PHASE14_SEQUENTIAL_RESTART_RECOVERY=GREEN")

        # Re-execution from recovered state must continue deterministically.
        block2 = execute_block(
            state1,
            registry1,
            [tx(nonce=2, amount=5)],
            chain_id=1,
            height=2,
            parent_block_hash=hash1,
            limits=limits(),
        )
        assert block2.final_state.accounts[ALICE] == (3, 870)
        assert block2.final_state.accounts[BOB] == (0, 130)
        print("PHASE14_CONTINUE_AFTER_RESTART=GREEN")

        # Duplicate append is rejected.
        try:
            restarted2.append(raw1)
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate execution block accepted")
        print("PHASE14_DUPLICATE_APPEND_REJECTED=GREEN")

        # Wrong parent is rejected without advancing HEAD.
        wrong_parent = execute_block(
            state1,
            registry1,
            [tx(nonce=2, amount=1)],
            chain_id=1,
            height=2,
            parent_block_hash=ZERO,
            limits=limits(),
        )
        before_tip = restarted2.tip()
        assert before_tip is not None
        before_tip_identity = (
            before_tip.height,
            before_tip.block_hash,
            before_tip.raw,
        )
        try:
            restarted2.append(
                encode_execution_record(wrong_parent, registry1)
            )
        except ValueError:
            pass
        else:
            raise AssertionError("wrong-parent execution block accepted")

        after_tip = restarted2.tip()
        assert after_tip is not None
        assert (
            after_tip.height,
            after_tip.block_hash,
            after_tip.raw,
        ) == before_tip_identity
        print("PHASE14_WRONG_PARENT_NO_MUTATION=GREEN")

        # Tamper detection is fail-closed.
        tampered = bytearray(raw1)
        tampered[-40] ^= 1
        try:
            parse_execution_record(bytes(tampered))
        except ValueError:
            pass
        else:
            raise AssertionError("tampered execution record accepted")
        print("PHASE14_TAMPER_DETECTION=GREEN")

        # Persisted roots bind the full reconstructed state.
        parsed1 = parse_execution_record(raw1)
        assert parsed1.final_state == block1.final_state
        assert parsed1.post_state_root == block1.post_state_root
        assert parsed1.registry_root == block1.registry_root
        print("PHASE14_FULL_STATE_BINDING=GREEN")

    print("FLOCK_PHASE14_EXECUTION_STORE_RECOVERY=GREEN")


if __name__ == "__main__":
    main()
