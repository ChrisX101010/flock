from __future__ import annotations

from pathlib import Path
import os
import socket
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.action_store import encode_action_record, parse_action_record
from tools.authenticated_mempool import public_key_bytes
from tools.block_producer import BlockLimits
from tools.consensus import (
    STEP_PRECOMMIT,
    STEP_PREVOTE,
    Validator,
    ValidatorSet,
    build_qc,
    decode_vote,
    encode_qc,
)
from tools.contract_runtime import ContractRegistry
from tools.deployment_actions import execute_action_block
from tools.devnet import (
    REQ_CATCH_UP,
    REQ_MAKE_PROPOSAL,
    REQ_PRECOMMIT_QC,
    REQ_PREVOTE,
    REQ_PREVOTE_QC,
    REQ_STATUS,
    RESP_PROPOSAL,
    RESP_STATUS,
    RESP_VOTE,
    decode_status,
    encode_request,
    rpc_call,
)
from tools.execution_pipeline import UnifiedState

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


def blob(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class NodeProcess:
    def __init__(self, index: int, port: int, data_dir: Path,
                 seed: bytes, validators: ValidatorSet) -> None:
        self.index = index
        self.port = port
        self.data_dir = data_dir
        self.seed = seed
        self.validators = validators
        self.proc: subprocess.Popen[str] | None = None

    def start(self) -> None:
        if self.proc is not None:
            raise RuntimeError("node already started")
        env = os.environ.copy()
        env["FLOCK_DEVNET_KEY_HEX"] = self.seed.hex()
        args = [
            sys.executable, "-m", "tools.devnet", "serve",
            "--host", "127.0.0.1",
            "--port", str(self.port),
            "--data-dir", str(self.data_dir),
            "--chain-id", "1",
            "--height", "0",
        ]
        for validator in self.validators.validators:
            args += ["--validator", f"{validator.public_key.hex()}:{validator.voting_power}"]
        self.proc = subprocess.Popen(
            args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.wait_ready()

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 10
        last_error = None
        while time.monotonic() < deadline:
            if self.proc is None:
                raise RuntimeError("node not started")
            if self.proc.poll() is not None:
                output = self.proc.stdout.read() if self.proc.stdout else ""
                raise RuntimeError(
                    f"node {self.index} exited early ({self.proc.returncode})\n{output}"
                )
            try:
                self.status()
                return
            except Exception as exc:
                last_error = exc
                time.sleep(0.05)
        raise RuntimeError(f"node {self.index} not ready: {last_error}")

    def stop(self) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc = None

    def request(self, request: bytes):
        return rpc_call("127.0.0.1", self.port, request, timeout=3)

    def status(self):
        kind, body = self.request(encode_request(REQ_STATUS))
        assert kind == RESP_STATUS
        return decode_status(body)

    def restart(self) -> None:
        self.stop()
        self.start()


def expect_value_error(fn, label: str) -> None:
    try:
        fn()
    except ValueError:
        return
    raise AssertionError(label)


def main() -> None:
    seeds = [bytes([i]) * 32 for i in range(1, 5)]
    private_keys = [Ed25519PrivateKey.from_private_bytes(seed) for seed in seeds]
    public_keys = [public_key_bytes(key.public_key()) for key in private_keys]
    validators = ValidatorSet(
        [Validator(public_key=key, voting_power=1) for key in public_keys]
    )

    state0 = UnifiedState(accounts={ALICE: (0, 1000)}, contracts={})
    block0 = execute_action_block(
        state0,
        ContractRegistry(),
        [],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
        limits=limits(),
    )
    record_raw = encode_action_record(block0)
    record = parse_action_record(record_raw)

    with tempfile.TemporaryDirectory(prefix="flock-phase18-") as td:
        root = Path(td)
        ports = [free_port() for _ in range(4)]
        nodes = [
            NodeProcess(i, ports[i], root / f"node{i}", seeds[i], validators)
            for i in range(4)
        ]
        by_pub = {public_keys[i]: nodes[i] for i in range(4)}

        try:
            for node in nodes:
                node.start()

            statuses = [node.status() for node in nodes]
            assert all(not status.has_record for status in statuses)
            assert len({status.public_key for status in statuses}) == 4
            print("PHASE18_INDEPENDENT_PROCESSES=GREEN")

            proposer = validators.proposer(record.height, 0)
            proposer_node = by_pub[proposer.public_key]
            kind, proposal_raw = proposer_node.request(
                encode_request(
                    REQ_MAKE_PROPOSAL,
                    blob(record_raw) + (0).to_bytes(4, "big"),
                )
            )
            assert kind == RESP_PROPOSAL
            print("PHASE18_REMOTE_PROPOSER=GREEN")

            nodes[3].stop()

            prevotes = []
            for node in nodes[:2]:
                kind, vote_raw = node.request(
                    encode_request(REQ_PREVOTE, blob(record_raw) + blob(proposal_raw))
                )
                assert kind == RESP_VOTE
                vote = decode_vote(vote_raw)
                assert vote.step == STEP_PREVOTE
                prevotes.append(vote)

            expect_value_error(
                lambda: build_qc(prevotes, validators),
                "two-of-four partition incorrectly formed quorum",
            )
            print("PHASE18_MINOR_PARTITION_NO_QUORUM=GREEN")

            kind, vote_raw = nodes[2].request(
                encode_request(REQ_PREVOTE, blob(record_raw) + blob(proposal_raw))
            )
            assert kind == RESP_VOTE
            prevotes.append(decode_vote(vote_raw))
            prevote_qc_raw = encode_qc(build_qc(prevotes, validators))

            precommits = []
            for node in nodes[:3]:
                kind, vote_raw = node.request(
                    encode_request(REQ_PREVOTE_QC, blob(prevote_qc_raw))
                )
                assert kind == RESP_VOTE
                vote = decode_vote(vote_raw)
                assert vote.step == STEP_PRECOMMIT
                precommits.append(vote)

            before = nodes[1].status()
            assert before.locked_round == 0
            assert before.locked_block_hash == record.block_hash
            assert before.signed_precommit
            nodes[1].restart()
            after = nodes[1].status()
            assert after.locked_round == 0
            assert after.locked_block_hash == record.block_hash
            assert after.signed_precommit
            assert after.finalized_block_hash is None
            print("PHASE18_LOCK_AND_VOTE_RESTART_RECOVERY=GREEN")

            precommit_qc_raw = encode_qc(build_qc(precommits, validators))
            for node in nodes[:3]:
                kind, body = node.request(
                    encode_request(REQ_PRECOMMIT_QC, blob(precommit_qc_raw))
                )
                assert kind == RESP_STATUS
                assert decode_status(body).finalized_block_hash == record.block_hash
            print("PHASE18_THREE_OF_FOUR_FINALITY=GREEN")

            nodes[3].start()
            assert not nodes[3].status().has_record
            kind, body = nodes[3].request(
                encode_request(
                    REQ_CATCH_UP,
                    blob(record_raw)
                    + blob(proposal_raw)
                    + blob(prevote_qc_raw)
                    + blob(precommit_qc_raw),
                )
            )
            assert kind == RESP_STATUS
            assert decode_status(body).finalized_block_hash == record.block_hash
            print("PHASE18_PARTITION_HEAL_CATCHUP=GREEN")

            for node in nodes:
                node.restart()
            final_statuses = [node.status() for node in nodes]
            assert all(status.has_record for status in final_statuses)
            assert {status.tip_hash for status in final_statuses} == {record.block_hash}
            assert {
                status.finalized_block_hash for status in final_statuses
            } == {record.block_hash}
            print("PHASE18_ALL_NODE_FINALITY_RESTART=GREEN")
            print("FLOCK_PHASE18_MULTIPROCESS_DEVNET=GREEN")
        finally:
            for node in nodes:
                node.stop()


if __name__ == "__main__":
    main()
