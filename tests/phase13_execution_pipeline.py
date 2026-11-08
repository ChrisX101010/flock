from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import struct

from tools.authenticated_mempool import (
    AuthenticatedMempool,
    address_from_public_key,
    public_key_bytes,
    sign_tx,
)
from tools.block_producer import BlockLimits
from tools.contract_runtime import ContractRegistry
from tools.execution_pipeline import (
    ACTION_CONTRACT_CALL,
    ACTION_TRANSFER,
    UnifiedState,
    combined_state_root,
    execute_block,
    execute_transaction,
)
from tools.flock_vm_state import (
    OP_HALT,
    OP_PUSH_U64,
    OP_REVERT,
    OP_SLOAD_U64,
    OP_SSTORE_U64,
    encode_program,
)
from tools.mempool import MempoolLimits
from tools.reference_model import Tx

ZERO = bytes(32)
BOB = bytes.fromhex("22" * 32)


def key(byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([byte]) * 32)


ALICE_KEY = key(1)
ALICE = address_from_public_key(public_key_bytes(ALICE_KEY.public_key()))


def push(value: int) -> bytes:
    return bytes([OP_PUSH_U64]) + struct.pack(">Q", value)


def sload(slot: int) -> bytes:
    return push(slot) + bytes([OP_SLOAD_U64])


def sstore(slot: int, value: int) -> bytes:
    return push(slot) + push(value) + bytes([OP_SSTORE_U64])


def tx(
    recipient: bytes,
    *,
    nonce: int,
    amount: int,
    state_limit: int = 4,
) -> Tx:
    return Tx(
        chain_id=1,
        nonce=nonce,
        sender=ALICE,
        recipient=recipient,
        amount=amount,
        compute_limit=100,
        state_limit=state_limit,
        memory_limit=64,
        payload=b"",
    )


def main() -> None:
    registry = ContractRegistry()
    program = encode_program(
        sstore(7, 42)
        + sload(7)
        + bytes([OP_HALT])
    )
    deployed = registry.deploy(ALICE, 0, program)
    contract_id = deployed.contract_id

    initial = UnifiedState(
        accounts={ALICE: (0, 1000), BOB: (0, 0)},
        contracts={},
    )
    root = combined_state_root(initial, registry)
    assert len(root) == 32
    assert root == combined_state_root(initial, registry)
    print("PHASE13_COMBINED_STATE_ROOT=GREEN")

    transfer = tx(BOB, nonce=0, amount=100)
    transfer_result = execute_transaction(
        initial,
        registry,
        transfer,
        chain_id=1,
    )
    assert transfer_result.receipt.action == ACTION_TRANSFER
    assert transfer_result.receipt.success
    assert transfer_result.final_state.accounts[ALICE] == (1, 900)
    assert transfer_result.final_state.accounts[BOB] == (0, 100)
    assert transfer_result.final_state.contracts == {}
    print("PHASE13_ACCOUNT_TRANSFER_DISPATCH=GREEN")

    call = tx(contract_id, nonce=1, amount=25, state_limit=2)
    call_result = execute_transaction(
        transfer_result.final_state,
        registry,
        call,
        chain_id=1,
    )
    assert call_result.receipt.action == ACTION_CONTRACT_CALL
    assert call_result.receipt.success
    assert call_result.final_state.accounts[ALICE] == (2, 875)
    assert call_result.final_state.accounts[contract_id] == (0, 25)
    assert call_result.final_state.contracts == {contract_id: {7: 42}}
    print("PHASE13_ATOMIC_VALUE_AND_CONTRACT_CALL=GREEN")

    revert_program = encode_program(
        sstore(1, 99) + bytes([OP_REVERT])
    )
    revert_contract = registry.deploy(ALICE, 1, revert_program).contract_id

    before_revert = call_result.final_state
    failed_call = tx(revert_contract, nonce=2, amount=50, state_limit=1)
    failed = execute_transaction(
        before_revert,
        registry,
        failed_call,
        chain_id=1,
    )
    assert not failed.receipt.success
    assert failed.final_state == before_revert
    assert failed.receipt.pre_state_root == failed.receipt.post_state_root
    assert ALICE not in failed.final_state.contracts.get(revert_contract, {})
    print("PHASE13_CONTRACT_FAILURE_ROLLS_BACK_VALUE=GREEN")

    pool = AuthenticatedMempool(
        MempoolLimits(
            max_entries=8,
            max_total_bytes=8 * 8192,
            max_compute_per_tx=1000,
            max_state_per_tx=100,
            max_memory_per_tx=1000,
        )
    )

    # Intentionally admit out of nonce order. Block execution must canonicalize.
    assert pool.admit_signed(sign_tx(call, ALICE_KEY), chain_id=1).accepted
    assert pool.admit_signed(sign_tx(transfer, ALICE_KEY), chain_id=1).accepted
    assert pool.admit_signed(sign_tx(failed_call, ALICE_KEY), chain_id=1).accepted
    print("PHASE13_AUTHENTICATED_MEMPOOL_INGRESS=GREEN")

    limits = BlockLimits(
        max_txs=8,
        max_tx_bytes=8 * 8192,
        max_compute=1000,
        max_state=100,
        max_memory=1000,
    )
    block = execute_block(
        initial,
        registry,
        list(pool.transactions()),
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits,
    )

    assert [item.nonce for item in block.selected] == [0, 1]
    assert len(block.receipts) == 2
    assert any(item.reason == "execution" for item in block.rejected)
    assert block.final_state.accounts[ALICE] == (2, 875)
    assert block.final_state.accounts[BOB] == (0, 100)
    assert block.final_state.accounts[contract_id] == (0, 25)
    assert block.final_state.contracts == {contract_id: {7: 42}}
    assert len(block.block_hash) == 32
    print("PHASE13_MEMPOOL_TO_BLOCK_EXECUTION=GREEN")

    repeated = execute_block(
        initial,
        registry,
        list(reversed(pool.transactions())),
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits,
    )
    assert repeated == block
    print("PHASE13_INPUT_ORDER_INVARIANT=GREEN")

    resource_limited = execute_block(
        initial,
        registry,
        [transfer, call],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=BlockLimits(
            max_txs=1,
            max_tx_bytes=8192,
            max_compute=1000,
            max_state=100,
            max_memory=1000,
        ),
    )
    assert [item.nonce for item in resource_limited.selected] == [0]
    assert any(item.reason == "tx_count" for item in resource_limited.rejected)
    assert resource_limited.final_state.accounts[ALICE] == (1, 900)
    assert resource_limited.final_state.contracts == {}
    print("PHASE13_BLOCK_RESOURCE_GATE=GREEN")

    wrong_chain = Tx(
        chain_id=2,
        nonce=0,
        sender=ALICE,
        recipient=BOB,
        amount=1,
        compute_limit=1,
        state_limit=0,
        memory_limit=0,
        payload=b"",
    )
    rejected = execute_transaction(
        initial,
        registry,
        wrong_chain,
        chain_id=1,
    )
    assert not rejected.receipt.success
    assert rejected.final_state == initial
    assert rejected.receipt.pre_state_root == rejected.receipt.post_state_root
    print("PHASE13_FAILURE_NO_MUTATION=GREEN")

    print("FLOCK_PHASE13_UNIFIED_EXECUTION_PIPELINE=GREEN")


if __name__ == "__main__":
    main()
