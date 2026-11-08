from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from tools.contract_state import (
    ContractExecution,
    ContractState,
    contract_state_root,
    encode_contract_receipt,
    execute_contract_program,
)
from tools.flock_vm_state import decode_program
from tools.reference_model import Tx, U64_MAX, encode_tx

CONTRACT_ADDRESS_DOMAIN = b"FLOCKCONTRACT1"
CODE_HASH_DOMAIN = b"FLOCKCODE1"
REGISTRY_DOMAIN = b"FLOCKCREG1"
REGISTRY_ROOT_DOMAIN = b"FLOCKCREGROOT1"
DEPLOY_RECEIPT_DOMAIN = b"FLOCKDEPLOYRES1"
CALL_RECEIPT_DOMAIN = b"FLOCKCALLRES1"

MAX_CONTRACT_CODE_BYTES = 16 * 1024


@dataclass(frozen=True)
class ContractRecord:
    contract_id: bytes
    deployer: bytes
    deploy_nonce: int
    code_hash: bytes
    program: bytes


@dataclass(frozen=True)
class DeploymentResult:
    contract_id: bytes
    code_hash: bytes
    registry_root: bytes


@dataclass(frozen=True)
class CallResult:
    contract_id: bytes
    tx_hash: bytes
    execution: ContractExecution
    receipt: bytes


def _check_id(value: bytes, name: str) -> None:
    if len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")


def _check_u64(value: int, name: str) -> None:
    if not 0 <= value <= U64_MAX:
        raise ValueError(f"{name} outside u64")


def code_hash(program: bytes) -> bytes:
    decode_program(program)
    if len(program) > MAX_CONTRACT_CODE_BYTES:
        raise ValueError("contract code too large")
    return hashlib.sha256(CODE_HASH_DOMAIN + program).digest()


def derive_contract_id(
    deployer: bytes,
    deploy_nonce: int,
    program: bytes,
) -> bytes:
    _check_id(deployer, "deployer")
    _check_u64(deploy_nonce, "deploy nonce")
    digest = code_hash(program)
    return hashlib.sha256(
        CONTRACT_ADDRESS_DOMAIN
        + deployer
        + struct.pack(">Q", deploy_nonce)
        + digest
    ).digest()


def encode_registry(records: dict[bytes, ContractRecord]) -> bytes:
    out = bytearray(REGISTRY_DOMAIN)
    out += struct.pack(">I", len(records))

    previous: bytes | None = None
    for contract_id in sorted(records):
        record = records[contract_id]
        _check_id(contract_id, "contract id")
        _check_id(record.contract_id, "record contract id")
        _check_id(record.deployer, "deployer")
        _check_u64(record.deploy_nonce, "deploy nonce")

        if contract_id != record.contract_id:
            raise ValueError("registry key/record id mismatch")
        if previous is not None and contract_id <= previous:
            raise ValueError("registry not canonical")
        previous = contract_id

        digest = code_hash(record.program)
        if digest != record.code_hash:
            raise ValueError("record code hash mismatch")
        if derive_contract_id(
            record.deployer,
            record.deploy_nonce,
            record.program,
        ) != contract_id:
            raise ValueError("record contract id mismatch")

        out += contract_id
        out += record.deployer
        out += struct.pack(">Q", record.deploy_nonce)
        out += record.code_hash
        out += struct.pack(">I", len(record.program))
        out += record.program

    return bytes(out)


def decode_registry(raw: bytes) -> dict[bytes, ContractRecord]:
    if not raw.startswith(REGISTRY_DOMAIN):
        raise ValueError("wrong registry domain")

    at = len(REGISTRY_DOMAIN)
    if len(raw) < at + 4:
        raise ValueError("truncated registry count")
    count = struct.unpack_from(">I", raw, at)[0]
    at += 4

    records: dict[bytes, ContractRecord] = {}
    previous: bytes | None = None

    for _ in range(count):
        fixed = 32 + 32 + 8 + 32 + 4
        if len(raw) < at + fixed:
            raise ValueError("truncated registry record")

        contract_id = raw[at : at + 32]
        at += 32
        deployer = raw[at : at + 32]
        at += 32
        deploy_nonce = struct.unpack_from(">Q", raw, at)[0]
        at += 8
        digest = raw[at : at + 32]
        at += 32
        program_len = struct.unpack_from(">I", raw, at)[0]
        at += 4

        if program_len > MAX_CONTRACT_CODE_BYTES:
            raise ValueError("contract code too large")
        if len(raw) < at + program_len:
            raise ValueError("truncated contract code")

        program = raw[at : at + program_len]
        at += program_len

        if previous is not None and contract_id <= previous:
            raise ValueError("contracts are not in canonical order")
        previous = contract_id

        record = ContractRecord(
            contract_id=contract_id,
            deployer=deployer,
            deploy_nonce=deploy_nonce,
            code_hash=digest,
            program=program,
        )
        if contract_id in records:
            raise ValueError("duplicate contract id")
        records[contract_id] = record

    if at != len(raw):
        raise ValueError("trailing registry bytes")
    if encode_registry(records) != raw:
        raise ValueError("non-canonical registry")
    return records


def registry_root(records: dict[bytes, ContractRecord]) -> bytes:
    return hashlib.sha256(
        REGISTRY_ROOT_DOMAIN + encode_registry(records)
    ).digest()


class ContractRegistry:
    def __init__(self):
        self._records: dict[bytes, ContractRecord] = {}

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> dict[bytes, ContractRecord]:
        return dict(self._records)

    def root(self) -> bytes:
        return registry_root(self._records)

    def get(self, contract_id: bytes) -> ContractRecord | None:
        _check_id(contract_id, "contract id")
        return self._records.get(contract_id)

    def deploy(
        self,
        deployer: bytes,
        deploy_nonce: int,
        program: bytes,
    ) -> DeploymentResult:
        contract_id = derive_contract_id(
            deployer,
            deploy_nonce,
            program,
        )
        if contract_id in self._records:
            raise ValueError("contract already deployed")

        digest = code_hash(program)
        record = ContractRecord(
            contract_id=contract_id,
            deployer=deployer,
            deploy_nonce=deploy_nonce,
            code_hash=digest,
            program=bytes(program),
        )
        self._records[contract_id] = record
        return DeploymentResult(
            contract_id=contract_id,
            code_hash=digest,
            registry_root=self.root(),
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> ContractRegistry:
        obj = cls()
        obj._records = decode_registry(raw)
        return obj

    def to_bytes(self) -> bytes:
        return encode_registry(self._records)


def encode_deployment_receipt(result: DeploymentResult) -> bytes:
    _check_id(result.contract_id, "contract id")
    _check_id(result.code_hash, "code hash")
    _check_id(result.registry_root, "registry root")
    return (
        DEPLOY_RECEIPT_DOMAIN
        + result.contract_id
        + result.code_hash
        + result.registry_root
    )


def call_contract(
    registry: ContractRegistry,
    state: ContractState,
    contract_id: bytes,
    tx: Tx,
) -> CallResult:
    _check_id(contract_id, "contract id")
    if tx.recipient != contract_id:
        raise ValueError("transaction recipient does not match contract")

    record = registry.get(contract_id)
    if record is None:
        raise ValueError("unknown contract")

    execution = execute_contract_program(
        state,
        contract_id,
        record.program,
        compute_limit=tx.compute_limit,
        state_limit=tx.state_limit,
        memory_limit=tx.memory_limit,
    )
    tx_hash = hashlib.sha256(encode_tx(tx)).digest()
    receipt = encode_call_receipt(
        contract_id,
        tx_hash,
        execution,
        record.code_hash,
    )
    return CallResult(
        contract_id=contract_id,
        tx_hash=tx_hash,
        execution=execution,
        receipt=receipt,
    )


def encode_call_receipt(
    contract_id: bytes,
    tx_hash: bytes,
    execution: ContractExecution,
    contract_code_hash: bytes,
) -> bytes:
    _check_id(contract_id, "contract id")
    _check_id(tx_hash, "transaction hash")
    _check_id(contract_code_hash, "code hash")

    execution_hash = hashlib.sha256(
        encode_contract_receipt(execution)
    ).digest()
    return b"".join(
        (
            CALL_RECEIPT_DOMAIN,
            contract_id,
            tx_hash,
            contract_code_hash,
            execution_hash,
            execution.post_root,
        )
    )
