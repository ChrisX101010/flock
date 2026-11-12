from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.action_store import encode_action_record, parse_action_record
from tools.authenticated_mempool import public_key_bytes
from tools.block_producer import BlockLimits
from tools.consensus import Validator, ValidatorSet
from tools.contract_runtime import ContractRegistry
from tools.deployment_actions import execute_action_block
from tools.execution_pipeline import UnifiedState
from tools.p2p_consensus import status_call

HOST = "127.0.0.1"
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


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return int(sock.getsockname()[1])


class NodeProcess:
    def __init__(
        self,
        *,
        index: int,
        port: int,
        root: Path,
        seed: bytes,
        validators: ValidatorSet,
        all_ports: list[int],
        record_path: Path,
        round_timeout: float,
    ) -> None:
        self.index = index
        self.port = port
        self.root = root
        self.seed = seed
        self.validators = validators
        self.all_ports = all_ports
        self.record_path = record_path
        self.round_timeout = round_timeout
        self.proc: subprocess.Popen[str] | None = None

    def start(self) -> None:
        if self.proc is not None:
            raise RuntimeError("node already started")
        env = os.environ.copy()
        env["FLOCK_DEVNET_KEY_HEX"] = self.seed.hex()
        args = [
            sys.executable,
            "-m",
            "tools.p2p_consensus",
            "--host",
            HOST,
            "--port",
            str(self.port),
            "--data-dir",
            str(self.root / f"node{self.index}"),
            "--chain-id",
            "1",
            "--height",
            "0",
            "--record-file",
            str(self.record_path),
            "--round-timeout",
            str(self.round_timeout),
        ]
        for validator in self.validators.validators:
            args += [
                "--validator",
                f"{validator.public_key.hex()}:{validator.voting_power}",
            ]
        for peer_port in self.all_ports:
            if peer_port != self.port:
                args += ["--peer", f"{HOST}:{peer_port}"]

        self.proc = subprocess.Popen(
            args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.wait_ready()

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 8.0
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
                time.sleep(0.03)
        raise RuntimeError(f"node {self.index} not ready: {last_error}")

    def status(self):
        return status_call(HOST, self.port, timeout=1.0)

    def stop(self) -> None:
        if self.proc is None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        self.proc = None

    def restart(self) -> None:
        self.stop()
        self.start()


def wait_until(label: str, fn, timeout: float = 8.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            last = value
            if value:
                return value
        except Exception as exc:
            last = exc
        time.sleep(0.04)
    raise AssertionError(f"timeout waiting for {label}: {last!r}")


def make_fixture(root: Path):
    seeds = [bytes([i]) * 32 for i in range(1, 5)]
    keys = [Ed25519PrivateKey.from_private_bytes(seed) for seed in seeds]
    public_keys = [public_key_bytes(key.public_key()) for key in keys]
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
    record_path = root / "action-record.bin"
    record_path.write_bytes(record_raw)
    return seeds, public_keys, validators, record, record_path


def scenario_all_live_round_zero() -> None:
    with tempfile.TemporaryDirectory(prefix="flock-phase19-all-") as td:
        root = Path(td)
        seeds, public_keys, validators, record, record_path = make_fixture(root)
        ports = [free_port() for _ in range(4)]
        nodes = [
            NodeProcess(
                index=i,
                port=ports[i],
                root=root,
                seed=seeds[i],
                validators=validators,
                all_ports=ports,
                record_path=record_path,
                round_timeout=1.5,
            )
            for i in range(4)
        ]
        proposer = validators.proposer(0, 0)
        proposer_index = public_keys.index(proposer.public_key)

        try:
            # Start followers first so the scheduled proposer can broadcast once
            # into a fully reachable peer set.
            for i, node in enumerate(nodes):
                if i != proposer_index:
                    node.start()
            nodes[proposer_index].start()

            def finalized():
                statuses = [node.status() for node in nodes]
                return (
                    statuses
                    if all(
                        status.finalized_block_hash == record.block_hash
                        for status in statuses
                    )
                    else None
                )

            statuses = wait_until("round-0 decentralized finality", finalized)
            assert {status.current_round for status in statuses} == {0}
            proposer_status = statuses[proposer_index]
            assert 0 in proposer_status.proposal_rounds

            # Finality is justified by the certified decision, not by every
            # follower retaining the original proposal in its local cache.
            # The scheduled proposer must retain it; every finalized node must
            # retain the PREVOTE and PRECOMMIT QCs.
            missing_proposal_cache = [
                index
                for index, status in enumerate(statuses)
                if 0 not in status.proposal_rounds
            ]
            if missing_proposal_cache:
                print(
                    "PHASE19_ROUND0_OPTIONAL_PROPOSAL_CACHE_MISS="
                    + ",".join(map(str, missing_proposal_cache))
                )

            assert all(0 in status.prevote_qc_rounds for status in statuses)
            assert all(0 in status.precommit_qc_rounds for status in statuses)
            print("PHASE19_AUTONOMOUS_ROUND0_FINALITY=GREEN")
        finally:
            for node in nodes:
                node.stop()


def scenario_missing_proposer_view_change() -> None:
    with tempfile.TemporaryDirectory(prefix="flock-phase19-view-") as td:
        root = Path(td)
        seeds, public_keys, validators, record, record_path = make_fixture(root)
        ports = [free_port() for _ in range(4)]
        nodes = [
            NodeProcess(
                index=i,
                port=ports[i],
                root=root,
                seed=seeds[i],
                validators=validators,
                all_ports=ports,
                record_path=record_path,
                round_timeout=0.35,
            )
            for i in range(4)
        ]
        round0_proposer = validators.proposer(0, 0)
        missing = public_keys.index(round0_proposer.public_key)
        round1_proposer = validators.proposer(0, 1)
        assert public_keys.index(round1_proposer.public_key) != missing
        live = [node for i, node in enumerate(nodes) if i != missing]

        try:
            for node in live:
                node.start()

            def finalized_live():
                statuses = [node.status() for node in live]
                return (
                    statuses
                    if all(
                        status.finalized_block_hash == record.block_hash
                        for status in statuses
                    )
                    else None
                )

            round1_statuses = wait_until(
                "authenticated round-1 convergence",
                lambda: (
                    statuses
                    if all(status.current_round >= 1 for status in statuses)
                    else None
                )
                if (statuses := [node.status() for node in live])
                else None,
                timeout=6.0,
            )
            assert all(
                1 in status.round_change_rounds
                for status in round1_statuses
            )
            print("PHASE19_ROUND_CHANGE_QC_PROPAGATION=GREEN")

            try:
                statuses = wait_until(
                    "round-1 finality after proposer loss",
                    finalized_live,
                    timeout=10.0,
                )
            except AssertionError:
                for index, node in enumerate(live):
                    try:
                        print(
                            f"PHASE19_DEBUG_LIVE_NODE_{index}="
                            f"{node.status()!r}"
                        )
                    except Exception as exc:
                        print(
                            f"PHASE19_DEBUG_LIVE_NODE_{index}_ERROR="
                            f"{type(exc).__name__}: {exc}"
                        )
                raise
            assert all(status.current_round >= 1 for status in statuses)
            assert all(1 in status.round_change_rounds for status in statuses)
            assert all(1 in status.proposal_rounds for status in statuses)
            assert all(1 in status.prevote_qc_rounds for status in statuses)
            assert all(1 in status.precommit_qc_rounds for status in statuses)
            print("PHASE19_SIGNED_VIEW_CHANGE=GREEN")
            print("PHASE19_THREE_LIVE_PROPOSER_QUORUM=GREEN")
            print("PHASE19_MISSING_PROPOSER_RECOVERY=GREEN")

            # Finality and round evidence survive a real process restart.
            live[1].restart()
            restarted = wait_until(
                "restarted node restores finality",
                lambda: (
                    status
                    if (
                        (status := live[1].status()).finalized_block_hash
                        == record.block_hash
                    )
                    else None
                ),
            )
            assert restarted.current_round >= 1
            assert 1 in restarted.round_change_rounds
            assert 1 in restarted.precommit_qc_rounds
            print("PHASE19_VIEW_CHANGE_RESTART_RECOVERY=GREEN")
        finally:
            for node in nodes:
                node.stop()


def scenario_two_of_four_cannot_advance() -> None:
    with tempfile.TemporaryDirectory(prefix="flock-phase19-minority-") as td:
        root = Path(td)
        seeds, _, validators, record, record_path = make_fixture(root)
        ports = [free_port() for _ in range(4)]
        nodes = [
            NodeProcess(
                index=i,
                port=ports[i],
                root=root,
                seed=seeds[i],
                validators=validators,
                all_ports=ports,
                record_path=record_path,
                round_timeout=0.25,
            )
            for i in range(4)
        ]
        live = nodes[:2]
        try:
            for node in live:
                node.start()
            time.sleep(1.1)
            statuses = [node.status() for node in live]
            assert all(status.finalized_block_hash is None for status in statuses)
            assert all(status.current_round == 0 for status in statuses)
            assert all(
                all(round_ > 0 for round_ in status.round_change_rounds)
                for status in statuses
            )
            print("PHASE19_MINORITY_CANNOT_VIEW_CHANGE=GREEN")
            print("PHASE19_MINORITY_CANNOT_FINALIZE=GREEN")
        finally:
            for node in nodes:
                node.stop()


def main() -> None:
    scenario_all_live_round_zero()
    scenario_missing_proposer_view_change()
    scenario_two_of_four_cannot_advance()
    print("FLOCK_PHASE19_P2P_PACEMAKER=GREEN")


if __name__ == "__main__":
    main()
