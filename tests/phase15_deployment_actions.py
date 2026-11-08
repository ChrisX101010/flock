from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
import struct

from tools.authenticated_mempool import (
    AuthenticatedMempool,
    address_from_public_key,
    public_key_bytes,
    sign_tx,
)
from tools.block_producer import BlockLimits
from tools.contract_runtime import (
    ContractRegistry,
    derive_contract_id,
)
from tools.deployment_actions import (
    ACTION_CONTRACT_DEPLOY,
    ACTION_DOMAIN,
    _action_receipt_bytes,
    decode_deploy_action,
    encode_deploy_action,
    execute_action_block,
    execute_action_transaction,
    make_deploy_tx,
)
from tools.execution_pipeline import (
    ACTION_CONTRACT_CALL,
    UnifiedState,
    _receipt_bytes,
)
from tools.flock_vm_state import (
    OP_HALT,
    OP_PUSH_U64,
    OP_SLOAD_U64,
    OP_SSTORE_U64,
    encode_program,
)
from tools.mempool import MempoolLimits
from tools.reference_model import Tx

ZERO = bytes(32)
BOB = bytes.fromhex("22" * 32)


def key(byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        bytes([byte]) * 32
    )


ALICE_KEY = key(1)
ALICE = address_from_public_key(
    public_key_bytes(ALICE_KEY.public_key())
)


def push(value: int) -> bytes:
    return bytes([OP_PUSH_U64]) + struct.pack(">Q", value)


def sload(slot: int) -> bytes:
    return push(slot) + bytes([OP_SLOAD_U64])


def sstore(slot: int, value: int) -> bytes:
    return (
        push(slot)
        + push(value)
        + bytes([OP_SSTORE_U64])
    )


def limits() -> BlockLimits:
    return BlockLimits(
        max_txs=16,
        max_tx_bytes=16 * 8192,
        max_compute=10000,
        max_state=1000,
        max_memory=10000,
    )


def main() -> None:
    program = encode_program(
        sstore(7, 42)
        + sload(7)
        + bytes([OP_HALT])
    )
    action = encode_deploy_action(program)
    assert action.startswith(ACTION_DOMAIN)
    assert decode_deploy_action(action).program == program
    assert encode_deploy_action(
        decode_deploy_action(action).program
    ) == action
    print("PHASE15_DEPLOY_ACTION_CODEC=GREEN")

    expected_contract = derive_contract_id(
        ALICE,
        0,
        program,
    )
    deploy_tx = make_deploy_tx(
        chain_id=1,
        nonce=0,
        sender=ALICE,
        amount=10,
        compute_limit=100,
        state_limit=4,
        memory_limit=64,
        program=program,
    )
    assert deploy_tx.recipient == expected_contract
    assert deploy_tx.amount == 10
    print("PHASE15_RECIPIENT_BINDING=GREEN")

    pool = AuthenticatedMempool(
        MempoolLimits(
            max_entries=16,
            max_total_bytes=16 * 8192,
            max_compute_per_tx=1000,
            max_state_per_tx=100,
            max_memory_per_tx=1000,
        )
    )
    admission = pool.admit_signed(
        sign_tx(deploy_tx, ALICE_KEY),
        chain_id=1,
    )
    assert admission.accepted
    print("PHASE15_SIGNED_DEPLOYMENT_MEMPOOL=GREEN")

    initial = UnifiedState(
        accounts={
            ALICE: (0, 1000),
            BOB: (0, 0),
        },
        contracts={},
    )
    registry = ContractRegistry()

    deployed = execute_action_transaction(
        initial,
        registry,
        deploy_tx,
        chain_id=1,
    )
    assert deployed.receipt.success
    assert deployed.receipt.action == ACTION_CONTRACT_DEPLOY
    assert deployed.final_state.accounts[ALICE] == (1, 990)
    assert deployed.final_state.accounts[expected_contract] == (0, 10)

    deployed_registry = ContractRegistry.from_bytes(
        deployed.final_registry_bytes
    )
    record = deployed_registry.get(expected_contract)
    assert record is not None
    assert record.program == program
    assert record.deploy_nonce == 0
    assert deployed_registry.root() != registry.root()
    print("PHASE15_ATOMIC_DEPLOY_AND_ENDOW=GREEN")

    wrong_recipient = Tx(
        chain_id=1,
        nonce=0,
        sender=ALICE,
        recipient=BOB,
        amount=10,
        compute_limit=100,
        state_limit=4,
        memory_limit=64,
        payload=action,
    )
    rejected = execute_action_transaction(
        initial,
        registry,
        wrong_recipient,
        chain_id=1,
    )
    assert not rejected.receipt.success
    assert rejected.final_state == initial
    assert rejected.final_registry_bytes == registry.to_bytes()
    assert (
        rejected.receipt.pre_state_root
        == rejected.receipt.post_state_root
    )
    print("PHASE15_BAD_DEPLOYMENT_NO_MUTATION=GREEN")

    malformed = Tx(
        chain_id=1,
        nonce=0,
        sender=ALICE,
        recipient=expected_contract,
        amount=10,
        compute_limit=100,
        state_limit=4,
        memory_limit=64,
        payload=ACTION_DOMAIN + b"\xff\x00",
    )
    malformed_result = execute_action_transaction(
        initial,
        registry,
        malformed,
        chain_id=1,
    )
    assert not malformed_result.receipt.success
    assert malformed_result.final_state == initial
    assert malformed_result.final_registry_bytes == registry.to_bytes()
    print("PHASE15_ACTION_FAIL_CLOSED=GREEN")

    call_tx = Tx(
        chain_id=1,
        nonce=1,
        sender=ALICE,
        recipient=expected_contract,
        amount=5,
        compute_limit=100,
        state_limit=2,
        memory_limit=64,
        payload=b"",
    )

    pool2 = AuthenticatedMempool(
        MempoolLimits(
            max_entries=16,
            max_total_bytes=16 * 8192,
            max_compute_per_tx=1000,
            max_state_per_tx=100,
            max_memory_per_tx=1000,
        )
    )
    assert pool2.admit_signed(
        sign_tx(call_tx, ALICE_KEY),
        chain_id=1,
    ).accepted
    assert pool2.admit_signed(
        sign_tx(deploy_tx, ALICE_KEY),
        chain_id=1,
    ).accepted

    block = execute_action_block(
        initial,
        registry,
        list(pool2.transactions()),
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits(),
    )

    assert [item.nonce for item in block.selected] == [0, 1]
    assert block.pre_registry_root != block.post_registry_root
    assert block.final_state.accounts[ALICE] == (2, 985)
    assert block.final_state.accounts[expected_contract] == (0, 15)
    assert block.final_state.contracts == {
        expected_contract: {7: 42}
    }
    final_registry = ContractRegistry.from_bytes(
        block.final_registry_bytes
    )
    assert final_registry.get(expected_contract) is not None
    print("PHASE15_DEPLOY_THEN_CALL_SAME_BLOCK=GREEN")

    repeated = execute_action_block(
        initial,
        registry,
        list(reversed(pool2.transactions())),
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits(),
    )
    assert repeated.block_hash == block.block_hash
    assert repeated.selected_bytes == block.selected_bytes
    assert repeated.receipts == block.receipts
    assert repeated.final_state == block.final_state
    assert (
        repeated.final_registry_bytes
        == block.final_registry_bytes
    )
    print("PHASE15_INPUT_ORDER_INVARIANT=GREEN")

    call_receipt = execute_action_transaction(
        deployed.final_state,
        deployed_registry,
        call_tx,
        chain_id=1,
    )
    assert call_receipt.receipt.success
    assert call_receipt.receipt.action == ACTION_CONTRACT_CALL
    print("PHASE15_LEGACY_CALL_COMPATIBILITY=GREEN")

    assert (
        _action_receipt_bytes(call_receipt.receipt)
        == _receipt_bytes(call_receipt.receipt)
    )
    assert _action_receipt_bytes(deployed.receipt).startswith(
        b"FLOCKEXECRES1"
    )
    print("PHASE15_RECEIPT_NAMESPACE_CONFORMANCE=GREEN")

    resource_block = execute_action_block(
        initial,
        registry,
        [deploy_tx, call_tx],
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
    assert [item.nonce for item in resource_block.selected] == [0]
    assert any(
        item.reason == "tx_count"
        for item in resource_block.rejected
    )
    resource_registry = ContractRegistry.from_bytes(
        resource_block.final_registry_bytes
    )
    assert resource_registry.get(expected_contract) is not None
    assert resource_block.final_state.accounts[ALICE] == (1, 990)
    print("PHASE15_BLOCK_RESOURCE_GATE=GREEN")

    print("FLOCK_PHASE15_AUTHENTICATED_DEPLOYMENT_ACTIONS=GREEN")


if __name__ == "__main__":
    main()
