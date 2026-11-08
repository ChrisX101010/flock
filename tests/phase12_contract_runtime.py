from __future__ import annotations

import struct

from tools.contract_runtime import (
    CALL_RECEIPT_DOMAIN,
    DEPLOY_RECEIPT_DOMAIN,
    ContractRegistry,
    code_hash,
    decode_registry,
    derive_contract_id,
    encode_deployment_receipt,
    encode_registry,
    registry_root,
    call_contract,
)
from tools.contract_state import contract_state_root
from tools.flock_vm_state import (
    OP_HALT,
    OP_PUSH_U64,
    OP_REVERT,
    OP_SLOAD_U64,
    OP_SSTORE_U64,
    encode_program,
)
from tools.reference_model import Tx

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)


def push(value: int) -> bytes:
    return bytes([OP_PUSH_U64]) + struct.pack(">Q", value)


def sload(slot: int) -> bytes:
    return push(slot) + bytes([OP_SLOAD_U64])


def sstore(slot: int, value: int) -> bytes:
    return push(slot) + push(value) + bytes([OP_SSTORE_U64])


def tx_for(contract_id: bytes, *, nonce: int = 0, state_limit: int = 4) -> Tx:
    return Tx(
        chain_id=1,
        nonce=nonce,
        sender=ALICE,
        recipient=contract_id,
        amount=1,
        compute_limit=100,
        state_limit=state_limit,
        memory_limit=64,
        payload=b"",
    )


def main() -> None:
    program = encode_program(
        sstore(7, 42)
        + sload(7)
        + bytes([OP_HALT])
    )
    cid = derive_contract_id(ALICE, 0, program)
    assert len(cid) == 32
    assert cid == derive_contract_id(ALICE, 0, program)
    assert cid != derive_contract_id(ALICE, 1, program)
    print("PHASE12_DETERMINISTIC_CONTRACT_ADDRESS=GREEN")

    registry = ContractRegistry()
    before_root = registry.root()
    deployed = registry.deploy(ALICE, 0, program)
    assert deployed.contract_id == cid
    assert deployed.code_hash == code_hash(program)
    assert deployed.registry_root == registry.root()
    assert registry.root() != before_root
    assert encode_deployment_receipt(deployed).startswith(DEPLOY_RECEIPT_DOMAIN)

    snapshot = registry.to_bytes()
    try:
        registry.deploy(ALICE, 0, program)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate deployment was accepted")
    assert registry.to_bytes() == snapshot
    print("PHASE12_IMMUTABLE_DEPLOYMENT=GREEN")

    raw_registry = registry.to_bytes()
    decoded = decode_registry(raw_registry)
    assert encode_registry(decoded) == raw_registry
    assert registry_root(decoded) == registry.root()

    restored = ContractRegistry.from_bytes(raw_registry)
    assert restored.to_bytes() == raw_registry
    assert restored.root() == registry.root()
    print("PHASE12_CANONICAL_CODE_REGISTRY=GREEN")

    state = {}
    called = call_contract(registry, state, cid, tx_for(cid))
    assert called.receipt.startswith(CALL_RECEIPT_DOMAIN)
    assert called.execution.committed
    assert called.execution.vm_result.stack == (42,)
    assert called.execution.final_state == {cid: {7: 42}}
    assert called.execution.pre_root == contract_state_root({})
    assert called.execution.post_root == contract_state_root({cid: {7: 42}})
    print("PHASE12_DEPLOYED_CODE_CALL=GREEN")

    repeated = call_contract(registry, state, cid, tx_for(cid))
    assert repeated == called
    print("PHASE12_CALL_RECEIPT_DETERMINISM=GREEN")

    try:
        call_contract(registry, state, cid, tx_for(BOB))
    except ValueError:
        pass
    else:
        raise AssertionError("recipient mismatch accepted")

    unknown = bytes.fromhex("33" * 32)
    try:
        call_contract(registry, state, unknown, tx_for(unknown))
    except ValueError:
        pass
    else:
        raise AssertionError("unknown contract accepted")
    assert state == {}
    print("PHASE12_CALL_BINDING_AND_UNKNOWN_REJECTED=GREEN")

    revert_program = encode_program(
        sstore(1, 99) + bytes([OP_REVERT])
    )
    reverted_deploy = registry.deploy(ALICE, 1, revert_program)
    pre = {reverted_deploy.contract_id: {1: 5}}
    reverted = call_contract(
        registry,
        pre,
        reverted_deploy.contract_id,
        tx_for(reverted_deploy.contract_id, nonce=1),
    )
    assert not reverted.execution.committed
    assert reverted.execution.final_state == pre
    assert reverted.execution.pre_root == reverted.execution.post_root
    print("PHASE12_CALL_ROLLBACK=GREEN")

    budget_program = encode_program(
        sstore(1, 9)
        + sload(1)
        + bytes([OP_HALT])
    )
    budget_deploy = registry.deploy(ALICE, 2, budget_program)
    exhausted = call_contract(
        registry,
        {},
        budget_deploy.contract_id,
        tx_for(budget_deploy.contract_id, nonce=2, state_limit=1),
    )
    assert not exhausted.execution.committed
    assert exhausted.execution.vm_result.status == "out_of_state"
    assert exhausted.execution.final_state == {}
    print("PHASE12_RESOURCE_FAILURE_ATOMIC=GREEN")

    assert registry.get(cid).program == program
    assert registry.get(cid).code_hash == code_hash(program)
    print("PHASE12_CODE_HASH_BINDING=GREEN")

    print("FLOCK_PHASE12_CONTRACT_DEPLOYMENT_CALLS=GREEN")


if __name__ == "__main__":
    main()
