from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from tools.block_commitment import build_block_commitment
from tools.chain_store import ChainStore, encode_persisted_block, parse_persisted_block
from tools.reference_model import Tx

ALICE = bytes.fromhex("11" * 32)
BOB = bytes.fromhex("22" * 32)
ZERO = bytes(32)


def tx(sender, recipient, nonce, amount, payload=b"phase0"):
    return Tx(
        chain_id=1,
        nonce=nonce,
        sender=sender,
        recipient=recipient,
        amount=amount,
        compute_limit=100000,
        state_limit=64,
        memory_limit=1048576,
        payload=payload,
    )


def expect_reject(fn, label):
    try:
        fn()
    except (ValueError, FileNotFoundError):
        return
    raise AssertionError(f"{label} was accepted")


def main() -> None:
    genesis_state = {ALICE: (0, 1000), BOB: (0, 0)}

    block0 = build_block_commitment(
        genesis_state,
        [tx(ALICE, BOB, 0, 125)],
        chain_id=1,
        height=0,
        parent_block_hash=ZERO,
    )

    record0 = encode_persisted_block(block0)
    assert record0 == encode_persisted_block(block0)
    parsed0 = parse_persisted_block(record0)
    assert parsed0.block_hash == block0.block_hash
    assert parsed0.fields.post_state_root == block0.post_state_root
    print("PERSISTED_RECORD_REPEAT=BYTE_IDENTICAL")

    block1 = build_block_commitment(
        block0.final_state,
        [],
        chain_id=1,
        height=1,
        parent_block_hash=block0.block_hash,
    )
    record1 = encode_persisted_block(block1)

    with tempfile.TemporaryDirectory(prefix="flock-phase4-") as td:
        root = Path(td) / "chain"
        store = ChainStore(root)

        got0 = store.append(record0)
        assert got0.block_hash == block0.block_hash

        restarted = ChainStore(root)
        assert restarted.tip() is not None
        assert restarted.tip().block_hash == block0.block_hash
        print("RESTART_RECOVERY=GREEN")

        got1 = restarted.append(record1)
        assert got1.block_hash == block1.block_hash
        chain = ChainStore(root).verify_chain()
        assert [r.fields.height for r in chain] == [0, 1]
        assert chain[-1].fields.post_state_root == block1.post_state_root
        print("CHAIN_CONTINUITY=GREEN")

        expect_reject(lambda: ChainStore(root).append(record1), "duplicate block")
        print("DUPLICATE_APPEND_REJECTED=GREEN")

        wrong_parent = build_block_commitment(
            block1.final_state,
            [],
            chain_id=1,
            height=2,
            parent_block_hash=ZERO,
        )
        expect_reject(
            lambda: ChainStore(root).append(encode_persisted_block(wrong_parent)),
            "wrong parent",
        )
        print("WRONG_PARENT_REJECTED=GREEN")

        wrong_pre = build_block_commitment(
            genesis_state,
            [],
            chain_id=1,
            height=2,
            parent_block_hash=block1.block_hash,
        )
        expect_reject(
            lambda: ChainStore(root).append(encode_persisted_block(wrong_pre)),
            "wrong pre-state",
        )
        print("STATE_DISCONTINUITY_REJECTED=GREEN")

        proc = subprocess.run(
            [sys.executable, "-m", "tools.flock_tool", "verify-store", str(root)],
            text=True,
            capture_output=True,
            check=True,
        )
        assert "FLOCK_STORE_VERIFY=GREEN" in proc.stdout
        assert f"TIP_HASH={block1.block_hash.hex()}" in proc.stdout
        print("REFERENCE_TOOL_VERIFY=GREEN")

        corrupt = Path(td) / "corrupt"
        shutil.copytree(root, corrupt)
        head0 = next((corrupt / "blocks").glob("00000000000000000000-*.flock"))
        data = bytearray(head0.read_bytes())
        data[len(data) // 2] ^= 0x01
        head0.write_bytes(data)
        expect_reject(lambda: ChainStore(corrupt).verify_chain(), "tampered block")
        print("TAMPER_DETECTION=GREEN")

    print(f"GENESIS_BLOCK_HASH={block0.block_hash.hex()}")
    print(f"HEIGHT1_BLOCK_HASH={block1.block_hash.hex()}")
    print("FLOCK_PHASE4_PERSISTENCE_TOOLING=GREEN")


if __name__ == "__main__":
    main()
