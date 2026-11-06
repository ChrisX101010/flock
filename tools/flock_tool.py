from __future__ import annotations

import argparse
from pathlib import Path

from tools.chain_store import ChainStore, parse_persisted_block


def cmd_verify_record(path: Path) -> int:
    record = parse_persisted_block(path.read_bytes())
    print(f"HEIGHT={record.fields.height}")
    print(f"BLOCK_HASH={record.block_hash.hex()}")
    print(f"RECORD_HASH={record.record_hash.hex()}")
    print("FLOCK_RECORD_VERIFY=GREEN")
    return 0


def cmd_verify_store(path: Path) -> int:
    chain = ChainStore(path).verify_chain()
    if chain:
        tip = chain[-1]
        print(f"HEIGHT={tip.fields.height}")
        print(f"TIP_HASH={tip.block_hash.hex()}")
        print(f"POST_STATE_ROOT={tip.fields.post_state_root.hex()}")
    else:
        print("HEIGHT=EMPTY")
    print("FLOCK_STORE_VERIFY=GREEN")
    return 0


def cmd_inspect_store(path: Path) -> int:
    tip = ChainStore(path).tip()
    if tip is None:
        print("HEIGHT=EMPTY")
        print("FLOCK_STORE_INSPECT=GREEN")
        return 0
    print(f"HEIGHT={tip.fields.height}")
    print(f"TIP_HASH={tip.block_hash.hex()}")
    print(f"CHAIN_ID={tip.fields.chain_id}")
    print(f"TX_COUNT={tip.fields.tx_count}")
    print(f"POST_STATE_ROOT={tip.fields.post_state_root.hex()}")
    print("FLOCK_STORE_INSPECT=GREEN")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="flock-tool")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("verify-record")
    a.add_argument("file", type=Path)

    a = sub.add_parser("verify-store")
    a.add_argument("directory", type=Path)

    a = sub.add_parser("inspect-store")
    a.add_argument("directory", type=Path)

    args = p.parse_args()

    if args.command == "verify-record":
        return cmd_verify_record(args.file)
    if args.command == "verify-store":
        return cmd_verify_store(args.directory)
    if args.command == "inspect-store":
        return cmd_inspect_store(args.directory)
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
